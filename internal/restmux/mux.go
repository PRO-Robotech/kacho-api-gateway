// Package restmux инициализирует REST-фасад grpc-gateway для api-gateway.
//
// Регистрирует активные сервисы Kachō + OperationService через OpsProxy.
// loadbalancer — НЕ регистрируется (заморожен).
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
//   - internal mux — `EmitUnpopulated=false`. Admin / data-plane-ресурсы и
//     internal-проекции публичных ресурсов до материализации на гипервизоре
//     отдают много zero-полей (`vpnId=0`, `hypervisorId=""`, `sid=""`,
//     `hostIface=""`, `netns=""`, …). На внутренней admin/UI поверхности
//     этот шум вреден и сбивает админов.
//
// Все RPC handlers регистрируются на ОБА mux'а — разница только в JSON
// маршалинге. Path-based dispatch выбирает нужный mux на основании
// `request.URL.Path`:
//
//   - Любой путь, содержащий сегмент `/internal` (например
//     `/vpc/v1/networks/{id}/internal`, `/vpc/v1/networkInterfaces/{id}/internal`),
//     → internal mux.
//   - Admin-only ресурсы (kacho-only, не tenant-facing) → internal mux:
//     `/vpc/v1/addressPools` (включая `:check` / `:explainResolution`),
//     `/vpc/v1/networks/{id}/addressPoolBinding`,
//     `/vpc/v1/addresses/{id}/addressPoolOverride`,
//     `/vpc/v1/clouds/{id}/poolSelector`,
//     `/compute/v1/hypervisors`.
//   - Всё остальное → public mux.
//
// Корневой `http.Handler` (диспетчер) экспонируется как `http.Handler`
// и передаётся в `httpMux.Handle("/", restHandler)` в `cmd/api-gateway/main.go`.
//
// # Активные сервисы
//
//   - iam.v1: Account, Project, User, ServiceAccount, Group, Role, AccessBinding
//     (KAC-104; заменили resourcemanager Cloud/Folder и organizationmanager Organization)
//   - vpc.v1: Network, Subnet, Address, RouteTable, SecurityGroup, Gateway, PrivateEndpoint, NetworkInterface
//   - vpc.v1 admin (kacho-only, NOT YC-verbatim): AddressPool, Cloud, InternalNetwork —
//     обслуживаются internal-портом vpc backend (9091); см. kacho-vpc/CLAUDE.md §16.
//   - compute.v1: Disk, Image, Snapshot, Instance, DiskType, Zone, Region
//     (Geography Region/Zone перенесены сюда из vpc — эпик KAC-15)
//   - compute.v1 admin (kacho-only, NOT YC-verbatim): InternalDiskType, InternalZone, InternalRegion —
//     обслуживаются internal-портом compute backend (9091); см. kacho-compute/CLAUDE.md.
//     (InternalHypervisor выпилен в KAC-36 / kacho-proto commit 79e3790.)
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
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
	// KAC-124: rmpb/orgpb убраны — kacho-resource-manager заменён на kacho-iam
	// (Organization/Cloud/Folder → Account/Project). Proto-пакеты
	// resourcemanager.v1 / organizationmanager.v1 удалены целиком в kacho-proto.
	vpcpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1"
	pepb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1/privatelink"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// isInternalPath решает, какой sub-mux обрабатывает запрос.
//
// Правила (в порядке проверки):
//  1. Любой path-сегмент `/internal` → internal mux. Покрывает
//     `/vpc/v1/networks/{id}/internal`, `/vpc/v1/networkInterfaces/{id}/internal`,
//     и любые будущие `*/internal`.
//  2. `/vpc/v1/addressPools` (и `:check` / `:explainResolution`) → internal.
//  3. `/vpc/v1/networks/{id}/addressPoolBinding` → internal.
//  4. `/vpc/v1/addresses/{id}/addressPoolOverride` → internal.
//  5. `/vpc/v1/clouds/{id}/poolSelector` → internal.
//  6. `/compute/v1/hypervisors` → internal.
//  7. Всё остальное → public.
func isInternalPath(path string) bool {
	// (1) any `/internal` segment.
	// strings.Contains покрывает оба варианта:
	//   /vpc/v1/networks/{id}/internal      (suffix)
	//   /vpc/v1/.../internal/...            (mid-path, гипотетически)
	// Защищаемся от ложного срабатывания на сегменте, начинающемся с
	// "internal" но не равном ему (никаких таких путей нет в Kachō, но на
	// будущее): требуем именно `/internal` как self-contained сегмент.
	if strings.Contains(path, "/internal/") || strings.HasSuffix(path, "/internal") {
		return true
	}

	// (2) /vpc/v1/addressPools[/...|:...]
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

	// (4) /vpc/v1/addresses/{id}/addressPoolOverride
	if strings.HasPrefix(path, "/vpc/v1/addresses/") &&
		strings.HasSuffix(path, "/addressPoolOverride") {
		return true
	}

	// (5) /vpc/v1/clouds/{id}/poolSelector
	if strings.HasPrefix(path, "/vpc/v1/clouds/") &&
		strings.HasSuffix(path, "/poolSelector") {
		return true
	}

	// (6) /compute/v1/hypervisors[/...]
	if path == "/compute/v1/hypervisors" ||
		strings.HasPrefix(path, "/compute/v1/hypervisors/") {
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
//	"iam"                 → kacho-iam.kacho.svc.cluster.local:9090
//	"iamInternal"         → kacho-iam.kacho.svc.cluster.local:9091
//	"vpc"                 → vpc.kacho.svc.cluster.local:9090
//	"vpcInternal"         → vpc.kacho.svc.cluster.local:9091 (admin internal-порт)
//	"compute"             → compute.kacho.svc.cluster.local:9090
//	"computeInternal"     → compute.kacho.svc.cluster.local:9091 (admin internal-порт)
//
// conns — карта domain → *grpc.ClientConn (нужна для OpsProxy);
// при nil — OperationService регистрируется через no-op Unimplemented (тесты).
func NewMux(ctx context.Context, addrs map[string]string, conns map[string]*grpc.ClientConn) (http.Handler, error) {
	// JSON-marshallers (отличаются ТОЛЬКО `EmitUnpopulated`):
	//   - public: EmitUnpopulated=true — отдаём явные нулевые значения
	//     (`""`/`{}`/`[]`/`null`) для proto-полей. На публичной поверхности
	//     (Network/Subnet/Address/NIC/SG/RT/Gateway/PE) `description`/`labels`/
	//     `cidr_blocks`/`v4_address_ids` и т.п. — полезный контракт, клиент
	//     должен видеть поле даже если оно пустое.
	//   - internal: EmitUnpopulated=false — на internal/admin endpoints
	//     (`/internal`-projections, AddressPool, Hypervisor) много инфра-полей
	//     `vpn_id`/`hv_id`/`sid`/`host_iface`/`netns`/... до материализации
	//     пустые; пустые поля скрываем чтобы UI/админам видеть только реально
	//     заполненные значения.
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

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Client-side round-robin; pair with `dns:///<headless-svc>:<port>` dial target.
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
	}

	// KAC-124: rmAddr убран — backend kacho-resource-manager упразднён.
	var vpcAddr, vpcInternalAddr, computeAddr, computeInternalAddr, iamAddr, iamInternalAddr string
	if addrs != nil {
		vpcAddr = addrs["vpc"]
		vpcInternalAddr = addrs["vpcInternal"]
		computeAddr = addrs["compute"]
		computeInternalAddr = addrs["computeInternal"]
		iamAddr = addrs["iam"]
		iamInternalAddr = addrs["iamInternal"]
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

		// --- vpc: Network + Subnet + Address + RouteTable + SecurityGroup + Gateway + PrivateEndpoint ---
		if err := vpcpb.RegisterNetworkServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register NetworkService: %w", err)
		}
		if err := vpcpb.RegisterSubnetServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register SubnetService: %w", err)
		}
		if err := vpcpb.RegisterAddressServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register AddressService: %w", err)
		}
		if err := vpcpb.RegisterRouteTableServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register RouteTableService: %w", err)
		}
		if err := vpcpb.RegisterSecurityGroupServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register SecurityGroupService: %w", err)
		}
		if err := vpcpb.RegisterGatewayServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register GatewayService: %w", err)
		}
		if err := pepb.RegisterPrivateEndpointServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register PrivateEndpointService: %w", err)
		}
		if err := vpcpb.RegisterNetworkInterfaceServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
			return nil, fmt.Errorf("register NetworkInterfaceService: %w", err)
		}

		// --- vpc admin (AddressPool/Cloud) — kacho-only, internal-port (9091) ---
		// Эти сервисы экспонируются через apiGW REST для UI/админ-tooling. Не верстаются
		// на verbatim-YC; путь /vpc/v1/addressPools. Region/Zone перенесены в kacho-compute
		// (эпик KAC-15) — см. блок compute ниже + workspace CLAUDE.md §«Кросс-доменные ссылки».
		if vpcInternalAddr != "" {
			if err := vpcpb.RegisterInternalAddressPoolServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register InternalAddressPoolService: %w", err)
			}
			if err := vpcpb.RegisterInternalCloudServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register InternalCloudService: %w", err)
			}
			// NB: InternalNetworkInterfaceService — НЕ регистрируется в REST mux
			// (KAC-49 решение: NIC оставлен только публичной проекцией). Data-plane-
			// инфо (vpn_id/hv_id/sid/host_iface/netns/...) остаётся доступной только
			// через gRPC `vpc.kacho.svc:9091` для kacho-vpc-implement — не для UI/CLI.
			//
			// GetNetwork → GET /vpc/v1/networks/{network_id}/internal — internal projection
			// of a Network ({network, vpn_id}); backs the admin-UI "jsonint" tab.
			if err := vpcpb.RegisterInternalNetworkServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register InternalNetworkService: %w", err)
			}
		}

		// --- compute: Disk + Image + Snapshot + Instance + DiskType + Zone + Region (read-only) ---
		if err := computepb.RegisterDiskServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute DiskService: %w", err)
		}
		if err := computepb.RegisterImageServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute ImageService: %w", err)
		}
		if err := computepb.RegisterSnapshotServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute SnapshotService: %w", err)
		}
		if err := computepb.RegisterInstanceServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute InstanceService: %w", err)
		}
		if err := computepb.RegisterDiskTypeServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute DiskTypeService: %w", err)
		}
		if err := computepb.RegisterZoneServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute ZoneService: %w", err)
		}
		if err := computepb.RegisterRegionServiceHandlerFromEndpoint(ctx, mux, computeAddr, opts); err != nil {
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
			if err := computepb.RegisterInternalDiskTypeServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register compute InternalDiskTypeService: %w", err)
			}
			if err := computepb.RegisterInternalZoneServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register compute InternalZoneService: %w", err)
			}
			if err := computepb.RegisterInternalRegionServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register compute InternalRegionService: %w", err)
			}
			// InternalHypervisorService удалён в kacho-proto (commit 79e3790,
			// KAC-78/KAC-36): ресурс `Hypervisor` целиком выпилен. Path
			// `/compute/v1/hypervisors` остаётся помеченным как internal в
			// `isInternalPath` (defense-in-depth — на случай реинтродукции),
			// но handler здесь больше НЕ регистрируется. См. KAC-50.
		}

		// --- iam.v1: Account + Project + User (read+delete only) + ServiceAccount + Group + Role + AccessBinding ---
		// Public surface KAC-105 (E0): все 7 сервисов под /iam/v1/*.
		// User не имеет Create/Update — User'ы создаются через InternalUserService.UpsertFromIdentity
		// (E2: OIDC-callback в api-gateway), на E0 — admin через grpcurl. Update пользователю не
		// требуется на E0 (display_name/email берётся из Zitadel при следующем UpsertFromIdentity).
		if iamAddr != "" {
			if err := iampb.RegisterAccountServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam AccountService: %w", err)
			}
			if err := iampb.RegisterProjectServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam ProjectService: %w", err)
			}
			if err := iampb.RegisterUserServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam UserService: %w", err)
			}
			if err := iampb.RegisterServiceAccountServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam ServiceAccountService: %w", err)
			}
			if err := iampb.RegisterGroupServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam GroupService: %w", err)
			}
			if err := iampb.RegisterRoleServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam RoleService: %w", err)
			}
			if err := iampb.RegisterAccessBindingServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam AccessBindingService: %w", err)
			}
			// KAC-127 Phase 5 — SAKeyService (ServiceAccount OAuth keys). Public
			// under /iam/v1/serviceAccounts/{id}/keys. Без этой регистрации
			// grpc-gateway не имеет REST-route → POST .../keys → 404, и
			// SAKeyService.Issue/Revoke недоступны (ломало authz-sa-apitoken suite).
			if err := iampb.RegisterSAKeyServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam SAKeyService: %w", err)
			}
			// KAC-132: JitPendingService + ComplianceReportService + AuthorizeService.
			// All under /iam/v1/; без этих регистраций grpc-gateway не создаёт REST-routes
			// → все POST /jitPending/:approve, GET /jitPending, POST /complianceReports:generate
			// и POST /authorize:check → 404 (breaking iam-jit-pending + iam-compliance-report
			// newman suites). AuthorizeService нужен для tenant FGA check flows.
			if err := iampb.RegisterJitPendingServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam JitPendingService: %w", err)
			}
			if err := iampb.RegisterComplianceReportServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam ComplianceReportService: %w", err)
			}
			if err := iampb.RegisterAuthorizeServiceHandlerFromEndpoint(ctx, mux, iamAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam AuthorizeService: %w", err)
			}
		}

		// --- iam.v1 admin (InternalUserService) — kacho-only, internal-port (9091) ---
		// E0: Регистрируем InternalUserService для admin tooling. ВАЖНО: его RPC
		// (Get, UpsertFromIdentity) в proto НЕ имеют `option (google.api.http)`,
		// поэтому grpc-gateway не создаёт REST-routes для них — реальный трафик
		// идёт исключительно через gRPC-direct (`grpcurl :9091`). Регистрация в
		// REST mux — pro-forma reference для будущего E2 (когда добавим http-аннотации
		// для admin REST UI). InternalIAMService.LookupSubject/ListPermissions — НЕ
		// регистрируется здесь; auth-interceptor api-gateway зовёт kacho-iam:9091
		// напрямую через grpc-client (E2, см. middleware/auth_noop.go TODO).
		if iamInternalAddr != "" {
			if err := iampb.RegisterInternalUserServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, opts); err != nil {
				return nil, fmt.Errorf("register iam InternalUserService: %w", err)
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
			internalMux.ServeHTTP(w, r)
			return
		}
		publicMux.ServeHTTP(w, r)
	})

	return dispatcher, nil
}
