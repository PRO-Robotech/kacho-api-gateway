// Package restmux инициализирует REST-фасад grpc-gateway для api-gateway.
//
// Регистрирует активные сервисы Kachō + OperationService через OpsProxy.
// KAC-161: loadbalancer (kacho-nlb) активирован — NetworkLoadBalancer / Listener /
// TargetGroup регистрируются на public mux (/nlb/v1/*). InternalResourceLifecycleService —
// streaming gRPC-direct only (нет HTTP-аннотаций; consumer'ы ходят в loadbalancer.kacho.svc:9091
// напрямую gRPC; через grpc-gateway не проксируется).
//
// # Split-mux pattern (KAC-50)
//
// Внутри пакета поднимается ДВА grpc-gateway `runtime.ServeMux`-а с разными
// `protojson.MarshalOptions`:
//
//   - public mux   — `EmitUnpopulated=true`. Tenant-facing контракт: клиент
//     должен видеть поле даже если оно пустое (`description: ""`, `labels: {}`,
//     `cidrBlocks: []`, `defaultSecurityGroupId: ""`, и т.п.). Это часть
//     стабильного API.
//   - internal mux — `EmitUnpopulated=false`. Admin-ресурсы и internal-проекции
//     публичных ресурсов отдают много zero-полей. На внутренней admin/UI
//     поверхности этот шум вреден и сбивает админов.
//
// Все RPC handlers регистрируются на ОБА mux'а — разница только в JSON
// маршалинге. Path-based dispatch выбирает нужный mux на основании
// `request.URL.Path`:
//
//   - Любой путь, содержащий сегмент `/internal` (например
//     `/vpc/v1/networks/{id}/internal`, `/vpc/v1/networkInterfaces/{id}/internal`),
//     → internal mux.
//   - Admin-only ресурсы (kacho-only, не tenant-facing) → internal mux:
//     `/vpc/v1/addressPools`,
//     `/vpc/v1/networks/{id}/addressPoolBinding`.
//   - Всё остальное → public mux.
//
// Корневой `http.Handler` (диспетчер) экспонируется как `http.Handler`
// и передаётся в `httpMux.Handle("/", restHandler)` в `cmd/api-gateway/main.go`.
//
// # Активные сервисы
//
//   - iam.v1: Account, Project, User, ServiceAccount, Group, Role, AccessBinding
//     (KAC-104; заменили resourcemanager Cloud/Folder и organizationmanager Organization)
//   - vpc.v1: Network, Subnet, Address, RouteTable, SecurityGroup, Gateway, NetworkInterface
//   - vpc.v1 admin (kacho-only, NOT YC-verbatim): AddressPool, InternalNetwork —
//     обслуживаются internal-портом vpc backend (9091); см. kacho-vpc/CLAUDE.md §16.
//     (KAC-266: InternalCloudService poolSelector удалён из proto.)
//   - compute.v1: Disk, Image, Snapshot, Instance, DiskType, Zone, Region
//     (Geography Region/Zone перенесены сюда из vpc — эпик KAC-15)
//   - compute.v1 admin (kacho-only, NOT YC-verbatim): InternalDiskType, InternalZone, InternalRegion —
//     обслуживаются internal-портом compute backend (9091); см. kacho-compute/CLAUDE.md.
//   - loadbalancer.v1 (KAC-161, kacho-nlb): NetworkLoadBalancerService, ListenerService,
//     TargetGroupService — публичные RPC под /nlb/v1/*. InternalResourceLifecycleService —
//     streaming gRPC-direct only, REST не регистрируется (нет http-аннотаций).
//   - iam.v1: Account, Project, User (read+delete only), ServiceAccount, Group, Role, AccessBinding —
//     все RPC public под /iam/v1/* (KAC-105, E0).
//   - iam.v1 admin (kacho-only): InternalUserService.Get — для admin tooling; зарегистрирован
//     в internal mux pro-forma (proto-аннотации `google.api.http` отсутствуют → real-трафик
//     идёт только через gRPC-direct до kacho-iam:9091). E2 добавит REST для UpsertFromIdentity.
//     InternalIAMService.LookupSubject/ListPermissions — НЕ регистрируется в REST (gRPC-direct).
//   - operation (без v1!): OperationService (in-process OpsProxy)
package restmux

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/grpc/metadata"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	computepb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/compute/v1"
	iampb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
	// KAC-161: kacho-nlb (loadbalancer.v1) — public RPC под /nlb/v1/*.
	lbpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/loadbalancer/v1"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
	// KAC-124: rmpb/orgpb убраны — kacho-resource-manager заменён на kacho-iam
	// (Organization/Cloud/Folder → Account/Project). Proto-пакеты
	// resourcemanager.v1 / organizationmanager.v1 удалены целиком в kacho-proto.
	vpcpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// isInternalPath решает, какой sub-mux обрабатывает запрос.
//
// Правила (в порядке проверки):
//  1. Любой path-сегмент `/internal` ИЛИ verb-suffix `:internal` → internal mux.
//     Покрывает `/vpc/v1/networks/{id}/internal`,
//     `/vpc/v1/networkInterfaces/{id}/internal`, `/vpc/v1/networks/{id}:internal`
//     (InternalNetworkService.GetNetwork) и любые будущие `*/internal` / `*:internal`.
//  2. `/vpc/v1/addressPools` → internal.
//  3. `/vpc/v1/networks/{id}/addressPoolBinding` → internal.
//  4. Всё остальное → public.
//
// KAC-266: AddressPool `:check` / `:explainResolution`, address `addressPoolOverride`
// (Bind/Unbind) и cloud `poolSelector` (InternalCloudService Get/Set/Unset) удалены
// из proto целиком — соответствующие правила маршрутизации убраны.
func isInternalPath(path string) bool {
	// (1) any `/internal` segment.
	// strings.Contains покрывает оба варианта:
	//   /vpc/v1/networks/{id}/internal      (suffix)
	//   /vpc/v1/.../internal/...            (mid-path, гипотетически)
	// Защищаемся от ложного срабатывания на сегменте, начинающемся с
	// "internal" но не равном ему (никаких таких путей нет в Kachō, но на
	// будущее): требуем именно `/internal` как self-contained сегмент.
	if strings.Contains(path, "/internal/") || strings.HasSuffix(path, "/internal") ||
		strings.HasSuffix(path, ":internal") {
		// `:internal` verb-suffix covers InternalNetworkService.GetNetwork
		// (`/vpc/v1/networks/{id}:internal`) — an internal projection carrying
		// infra-sensitive Network fields. Without this it routed to the public
		// mux and would slip past the external-isolation gate (security.md
		// §«Инфра-чувствительные данные»).
		return true
	}

	// (2) /vpc/v1/addressPools[/...]
	if path == "/vpc/v1/addressPools" ||
		strings.HasPrefix(path, "/vpc/v1/addressPools/") ||
		strings.HasPrefix(path, "/vpc/v1/addressPools:") {
		return true
	}

	// (3) /vpc/v1/networks/{id}/addressPoolBinding
	if strings.HasPrefix(path, "/vpc/v1/networks/") &&
		strings.HasSuffix(path, "/addressPoolBinding") {
		return true
	}

	return false
}

// NewMux создаёт grpc-gateway split-mux (public + internal) и регистрирует
// активные публичные сервисы плюс OperationService (через OpsProxy).
//
// Возвращает `http.Handler`-диспетчер, который на каждый request выбирает
// public или internal sub-mux на основании `isInternalPath(r.URL.Path)`.
//
// addrs — карта domain → адрес gRPC backend:
//
//	"iam"                  → kacho-iam.kacho.svc.cluster.local:9090
//	"iamInternal"          → kacho-iam.kacho.svc.cluster.local:9091
//	"vpc"                  → vpc.kacho.svc.cluster.local:9090
//	"vpcInternal"          → vpc.kacho.svc.cluster.local:9091 (admin internal-порт)
//	"compute"              → compute.kacho.svc.cluster.local:9090
//	"computeInternal"      → compute.kacho.svc.cluster.local:9091 (admin internal-порт)
//	"loadbalancer"         → kacho-nlb.kacho.svc.cluster.local:9090 (KAC-161)
//	"loadbalancerInternal" → kacho-nlb.kacho.svc.cluster.local:9091 (KAC-161; зарезервирован
//	                        под admin/internal REST, если в будущем добавятся http-аннотации;
//	                        сейчас InternalResourceLifecycleService — streaming gRPC-direct only)
//
// conns — карта domain → *grpc.ClientConn (нужна для OpsProxy);
// при nil — OperationService регистрируется через no-op Unimplemented (тесты).
//
// dialOpts — карта backend-key → transport-credentials grpc.DialOption (SEC-K).
// Ключи совпадают с `addrs` / `config.BackendAddrs()` (vpc/vpcInternal/compute/
// computeInternal/iam/iamInternal/loadbalancer/loadbalancerInternal). Для каждого
// backend'а REST-mux дозванивается с ЕГО per-edge creds: mTLS client-cert +
// корректный ServerName, когда mTLS на edge включён; insecure — когда нет.
//
// Это устранение 503-бага: ДО SEC-K NewMux строил ОДИН insecure
// `[]grpc.DialOption` и передавал его в КАЖДЫЙ RegisterXServiceHandlerFromEndpoint.
// После флипа backend'ов в `tls.RequireAndVerifyClientCert` каждый REST-вызов
// (UI → gw REST → backend :9090/:9091) обрывался на TLS-handshake → connection
// reset → 503. Composition-root (`cmd/api-gateway/main.go`) собирает dialOpts
// через `buildBackendDialCreds(cfg)` (те же per-edge creds, что gRPC-director /
// authz-dial в SEC-E) — новой cert-обвязки не вводится.
//
// dialOpts может быть nil или не содержать ключ — тогда для этого backend'а
// используется insecure dial (dev backward-compat, A-1c). enable=false на edge
// также даёт insecure (creds-резолвер в main.go возвращает insecure-опцию).
func NewMux(
	ctx context.Context,
	addrs map[string]string,
	conns map[string]*grpc.ClientConn,
	dialOpts map[string]grpc.DialOption,
) (http.Handler, error) {
	// JSON-marshallers (отличаются ТОЛЬКО `EmitUnpopulated`):
	//   - public: EmitUnpopulated=true — отдаём явные нулевые значения
	//     (`""`/`{}`/`[]`/`null`) для proto-полей. На публичной поверхности
	//     (Network/Subnet/Address/NIC/SG/RT/Gateway/PE) `description`/`labels`/
	//     `cidr_blocks`/`v4_address_ids` и т.п. — полезный контракт, клиент
	//     должен видеть поле даже если оно пустое.
	//   - internal: EmitUnpopulated=false — на internal/admin endpoints
	//     (`/internal`-projections, AddressPool) часть инфра-полей до
	//     материализации пустые; пустые поля скрываем чтобы UI/админам видеть
	//     только реально заполненные значения.
	publicMarshaler := &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames:   false,
			EmitUnpopulated: true,
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	}
	internalMarshaler := &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames:   false,
			EmitUnpopulated: false,
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	}

	// KAC-107 followup: explicit IncomingHeaderMatcher для x-kacho-principal-*
	// + WithMetadata callback что явно собирает outgoing metadata из
	// HTTP middleware-set headers `X-Kacho-Principal-*`. Без WithMetadata
	// grpc-gateway не пробрасывал кастомные headers, IncomingHeaderMatcher
	// один не помогал.
	principalHeaderMatcher := func(key string) (string, bool) {
		if k, ok := runtime.DefaultHeaderMatcher(key); ok {
			return k, true
		}
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-kacho-principal-") {
			return lower, true
		}
		return "", false
	}

	principalMetadata := func(_ context.Context, r *http.Request) metadata.MD {
		md := metadata.MD{}
		// HTTP middleware (`auth.HTTP`) ставит headers с `Grpc-Metadata-` префиксом
		// — это canonical name в r.Header. Читаем оба варианта (с/без префикса)
		// чтобы быть robust.
		get := func(canonical, fallback string) string {
			if v := r.Header.Get(canonical); v != "" {
				return v
			}
			return r.Header.Get(fallback)
		}
		pt := get("Grpc-Metadata-X-Kacho-Principal-Type", "X-Kacho-Principal-Type")
		pi := get("Grpc-Metadata-X-Kacho-Principal-Id", "X-Kacho-Principal-Id")
		pd := get("Grpc-Metadata-X-Kacho-Principal-Display-Name", "X-Kacho-Principal-Display-Name")
		// Debug log to verify callback fires and sees headers.
		fmt.Printf("[restmux.WithMetadata] path=%s pt=%q pi=%q pd=%q\n", r.URL.Path, pt, pi, pd)
		if pt != "" {
			md.Append("x-kacho-principal-type", pt)
		}
		if pi != "" {
			md.Append("x-kacho-principal-id", pi)
		}
		if pd != "" {
			md.Append("x-kacho-principal-display-name", pd)
		}
		return md
	}

	publicMux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, publicMarshaler),
		runtime.WithIncomingHeaderMatcher(principalHeaderMatcher),
		runtime.WithMetadata(principalMetadata),
	)
	internalMux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, internalMarshaler),
		runtime.WithIncomingHeaderMatcher(principalHeaderMatcher),
		runtime.WithMetadata(principalMetadata),
	)

	// optsFor returns the dial-options for one backend-key (SEC-K): that backend's
	// per-edge transport credentials (mTLS client-cert + ServerName when the edge
	// is enabled, else insecure) plus the shared round-robin service-config. When
	// dialOpts has no entry for the key the dial falls back to insecure — dev
	// backward-compat (A-1c). This replaces the pre-SEC-K single insecure opts
	// that every Register* shared (the 503 bug).
	optsFor := func(backendKey string) []grpc.DialOption {
		transport, ok := dialOpts[backendKey]
		if !ok {
			transport = grpc.WithTransportCredentials(insecure.NewCredentials())
		}
		return []grpc.DialOption{
			transport,
			// Client-side round-robin; pair with `dns:///<headless-svc>:<port>` dial target.
			grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
		}
	}

	// KAC-124: rmAddr убран — backend kacho-resource-manager упразднён.
	// KAC-161: lbAddr / lbInternalAddr добавлены под kacho-nlb (loadbalancer.v1).
	var vpcAddr, vpcInternalAddr, computeAddr, computeInternalAddr, iamAddr, iamInternalAddr, lbAddr, lbInternalAddr string
	if addrs != nil {
		vpcAddr = addrs["vpc"]
		vpcInternalAddr = addrs["vpcInternal"]
		computeAddr = addrs["compute"]
		computeInternalAddr = addrs["computeInternal"]
		iamAddr = addrs["iam"]
		iamInternalAddr = addrs["iamInternal"]
		lbAddr = addrs["loadbalancer"]
		lbInternalAddr = addrs["loadbalancerInternal"]
	}

	// Регистрируем КАЖДЫЙ handler на ОБА mux'а (public + internal). Path-based
	// dispatch (isInternalPath) ниже выбирает, какой из них фактически обработает
	// конкретный запрос — разница только в JSON-маршалинге. Так нам не нужно
	// заранее знать, какой RPC попадёт на какой путь: grpc-gateway сам разрулит,
	// а мы лишь подсовываем правильный JSONPb.
	muxes := []*runtime.ServeMux{publicMux, internalMux}

	for _, mux := range muxes {
		// KAC-124: resourcemanager (Cloud/Folder) и organizationmanager (Organization)
		// удалены целиком — backend заменён на kacho-iam Accounts/Projects.

		// --- vpc: Network + Subnet + Address + RouteTable + SecurityGroup + Gateway ---
		if err := vpcpb.RegisterNetworkServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register NetworkService: %w", err)
		}
		if err := vpcpb.RegisterSubnetServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register SubnetService: %w", err)
		}
		if err := vpcpb.RegisterAddressServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register AddressService: %w", err)
		}
		if err := vpcpb.RegisterRouteTableServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register RouteTableService: %w", err)
		}
		if err := vpcpb.RegisterSecurityGroupServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register SecurityGroupService: %w", err)
		}
		if err := vpcpb.RegisterGatewayServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register GatewayService: %w", err)
		}
		if err := vpcpb.RegisterNetworkInterfaceServiceHandlerFromEndpoint(ctx, mux, vpcAddr, optsFor("vpc")); err != nil {
			return nil, fmt.Errorf("register NetworkInterfaceService: %w", err)
		}

		// --- vpc admin (AddressPool) — kacho-only, internal-port (9091) ---
		// Эти сервисы экспонируются через apiGW REST для UI/админ-tooling. Не верстаются
		// на verbatim-YC; путь /vpc/v1/addressPools. Region/Zone перенесены в kacho-compute
		// (эпик KAC-15) — см. блок compute ниже + workspace CLAUDE.md §«Кросс-доменные ссылки».
		// KAC-266: InternalCloudService (poolSelector Get/Set/Unset) удалён целиком из proto.
		if vpcInternalAddr != "" {
			if err := vpcpb.RegisterInternalAddressPoolServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, optsFor("vpcInternal")); err != nil {
				return nil, fmt.Errorf("register InternalAddressPoolService: %w", err)
			}
			// GetNetwork → GET /vpc/v1/networks/{network_id}/internal — internal
			// projection of a Network (инфра-чувствительные поля); backs the
			// admin-UI "jsonint" tab.
			if err := vpcpb.RegisterInternalNetworkServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, optsFor("vpcInternal")); err != nil {
				return nil, fmt.Errorf("register InternalNetworkService: %w", err)
			}
		}

		// --- compute: Disk + Image + Snapshot + Instance + DiskType + Zone + Region (read-only) ---
		if err := computepb.RegisterDiskServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute DiskService: %w", err)
		}
		if err := computepb.RegisterImageServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute ImageService: %w", err)
		}
		if err := computepb.RegisterSnapshotServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute SnapshotService: %w", err)
		}
		if err := computepb.RegisterInstanceServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute InstanceService: %w", err)
		}
		if err := computepb.RegisterDiskTypeServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute DiskTypeService: %w", err)
		}
		if err := computepb.RegisterZoneServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute ZoneService: %w", err)
		}
		if err := computepb.RegisterRegionServiceHandlerFromEndpoint(ctx, mux, computeAddr, optsFor("compute")); err != nil {
			return nil, fmt.Errorf("register compute RegionService: %w", err)
		}

		// --- compute admin (InternalDiskType/InternalZone/InternalRegion) — kacho-only, internal-port (9091) ---
		// CRUD справочников DiskType/Zone (POST/PATCH/DELETE на /compute/v1/diskTypes,
		// /compute/v1/zones). Не верстается на verbatim-YC, доступен только через
		// cluster-internal REST listener для UI/admin-tooling (CLAUDE.md §запрет 6,
		// kacho-compute/CLAUDE.md §16). InternalWatchService — gRPC server-streaming
		// (outbox), через grpc-gateway REST не проксируется; consumer'ы ходят в
		// compute.kacho.svc:9091 напрямую gRPC.
		if computeInternalAddr != "" {
			if err := computepb.RegisterInternalDiskTypeServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, optsFor("computeInternal")); err != nil {
				return nil, fmt.Errorf("register compute InternalDiskTypeService: %w", err)
			}
			if err := computepb.RegisterInternalZoneServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, optsFor("computeInternal")); err != nil {
				return nil, fmt.Errorf("register compute InternalZoneService: %w", err)
			}
			if err := computepb.RegisterInternalRegionServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, optsFor("computeInternal")); err != nil {
				return nil, fmt.Errorf("register compute InternalRegionService: %w", err)
			}
		}

		// --- iam.v1: Account + Project + User (read+delete only) + ServiceAccount + Group + Role + AccessBinding ---
		// Public surface KAC-105 (E0): все 7 сервисов под /iam/v1/*.
		// User не имеет Create/Update — User'ы создаются через InternalUserService.UpsertFromIdentity
		// (E2: OIDC-callback в api-gateway), на E0 — admin через grpcurl. Update пользователю не
		// требуется на E0 (display_name/email берётся из Zitadel при следующем UpsertFromIdentity).
		if iamAddr != "" {
			if err := iampb.RegisterAccountServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam AccountService: %w", err)
			}
			if err := iampb.RegisterProjectServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam ProjectService: %w", err)
			}
			if err := iampb.RegisterUserServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam UserService: %w", err)
			}
			if err := iampb.RegisterServiceAccountServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam ServiceAccountService: %w", err)
			}
			if err := iampb.RegisterGroupServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam GroupService: %w", err)
			}
			if err := iampb.RegisterRoleServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam RoleService: %w", err)
			}
			if err := iampb.RegisterAccessBindingServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam AccessBindingService: %w", err)
			}
			// KAC-127 Phase 5 — SAKeyService (ServiceAccount OAuth keys). Public
			// under /iam/v1/serviceAccounts/{id}/keys. Без этой регистрации
			// grpc-gateway не имеет REST-route → POST .../keys → 404, и
			// SAKeyService.Issue/Revoke недоступны (ломало authz-sa-apitoken suite).
			if err := iampb.RegisterSAKeyServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam SAKeyService: %w", err)
			}
			// KAC-198 Phase 4: JitPendingService removed. KAC-127 Phase 2:
			// ComplianceReportService removed. Both proto stubs deleted from
			// kacho-proto. Only AuthorizeService remains here (tenant FGA
			// check flows on POST /iam/v1/authorize:check).
			if err := iampb.RegisterAuthorizeServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam AuthorizeService: %w", err)
			}
		}

		// --- iam.v1 admin (InternalUserService + InternalIAMService) —
		// kacho-only, internal-port (9091); CLAUDE.md §Запрет 6 ---
		// KAC-185 (F4): REST HTTP annotations added to internal IAM proto RPCs
		// (UpsertFromIdentity, LookupSubject, ListPermissions, Check) so that
		// grpc-gateway creates routes for /iam/v1/internal/* paths.
		// These handlers are dispatched to the internal mux (isInternalPath
		// returns true for any path containing /internal/); the authz middleware
		// lets them through via the public allowlist (no Bearer JWT required —
		// the IAM service enforces its own per-handler auth via authzguard
		// interceptor whitelist). External TLS listener never serves these
		// paths — gRPC director's HasInternalSuffix blocks Internal* services
		// on the public listener.
		if iamInternalAddr != "" {
			if err := iampb.RegisterInternalUserServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalUserService: %w", err)
			}
			if err := iampb.RegisterInternalIAMServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalIAMService: %w", err)
			}
			// KAC-196: InternalClusterService — cluster-admin RBAC management
			// (Get / GrantAdmin / RevokeAdmin / ListAdmins) under
			// /iam/v1/internal/cluster/...  Internal-only (workspace
			// CLAUDE.md §«Запрет 6»); isInternalPath sends these paths to the
			// internal sub-mux. D-11 gate (catalog `required_relation: admin`)
			// enforces the FGA computed-alias `system_admin OR emergency_admin`
			// on `cluster:cluster_kacho_root`.
			if err := iampb.RegisterInternalClusterServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalClusterService: %w", err)
			}
		}

		// --- loadbalancer.v1 (KAC-161, kacho-nlb): NetworkLoadBalancer + Listener + TargetGroup ---
		// Public RPC под /nlb/v1/*. Регистрируется условно по lbAddr — backend ещё
		// может быть не задеплоен в окружении (поведение симметрично vpcInternalAddr /
		// computeInternalAddr / iamAddr выше).
		if lbAddr != "" {
			if err := lbpb.RegisterNetworkLoadBalancerServiceHandlerFromEndpoint(ctx, mux, lbAddr, optsFor("loadbalancer")); err != nil {
				return nil, fmt.Errorf("register loadbalancer NetworkLoadBalancerService: %w", err)
			}
			if err := lbpb.RegisterListenerServiceHandlerFromEndpoint(ctx, mux, lbAddr, optsFor("loadbalancer")); err != nil {
				return nil, fmt.Errorf("register loadbalancer ListenerService: %w", err)
			}
			if err := lbpb.RegisterTargetGroupServiceHandlerFromEndpoint(ctx, mux, lbAddr, optsFor("loadbalancer")); err != nil {
				return nil, fmt.Errorf("register loadbalancer TargetGroupService: %w", err)
			}
		}

		// --- loadbalancer.v1 admin (InternalResourceLifecycleService) — kacho-only, internal-port (9091) ---
		// InternalResourceLifecycleService.Subscribe — gRPC server-streaming для
		// подписки на CREATED/UPDATED/DELETED события (см. kacho-nlb design §3.9 outbox).
		// В proto НЕТ `option (google.api.http)`, поэтому grpc-gateway не создаёт REST-routes —
		// consumer'ы (наблюдатели data-plane) дозваниваются по gRPC напрямую до
		// loadbalancer.kacho.svc:9091 через grpc-client. Регистрация здесь — pro-forma
		// reference (симметрично iam InternalUserService); если в будущем добавятся
		// http-аннотации, REST автоматически появится на internal mux.
		// HasInternalSuffix в gRPC-director (proxy/director.go) блокирует попадание
		// InternalResourceLifecycleService.* на external/TLS endpoint (запрет #6).
		if lbInternalAddr != "" {
			if err := lbpb.RegisterInternalResourceLifecycleServiceHandlerFromEndpoint(ctx, mux, lbInternalAddr, optsFor("loadbalancerInternal")); err != nil {
				return nil, fmt.Errorf("register loadbalancer InternalResourceLifecycleService: %w", err)
			}
		}

		// --- OperationService (OpsProxy, in-process) ---
		// Не имеет отдельного backend — живёт in-process как OpsProxy.
		// Регистрируем через RegisterOperationServiceHandlerServer (локальный вызов, без dial).
		var opsSrv operationpb.OperationServiceServer
		if conns != nil {
			opsSrv = opsproxy.New(conns)
		} else {
			opsSrv = operationpb.UnimplementedOperationServiceServer{}
		}
		if err := operationpb.RegisterOperationServiceHandlerServer(ctx, mux, opsSrv); err != nil {
			return nil, fmt.Errorf("register OperationService: %w", err)
		}
	}

	// Path-based dispatcher. Решает, какому sub-mux'у скормить запрос. Сами
	// RPC-роуты внутри grpc-gateway-mux'ов идентичны — отличается только JSON
	// маршалинг ответа (EmitUnpopulated). Запрос НЕ переадресуется куда-то ещё:
	// internal sub-mux обработает request тем же handler'ом, что и public, но
	// сожмёт response пустых полей.
	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isInternalPath(r.URL.Path) {
			// SECURITY (workspace CLAUDE.md §запрет #6, security.md): Internal* REST
			// paths are cluster-internal-only. When the request arrived on the
			// advertised external TLS listener (listenerorigin.IsExternal), reject
			// with 404 — existence-hiding, mirroring the gRPC director's
			// HasInternalSuffix block. Internal-listener callers (UI / admin-tooling /
			// port-forward / service self-calls) are unmarked → served as before.
			if listenerorigin.IsExternal(r.Context()) {
				http.NotFound(w, r)
				return
			}
			internalMux.ServeHTTP(w, r)
			return
		}
		publicMux.ServeHTTP(w, r)
	})

	return dispatcher, nil
}
