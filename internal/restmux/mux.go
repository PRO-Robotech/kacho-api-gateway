// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package restmux инициализирует REST-фасад grpc-gateway для api-gateway.
//
// Регистрирует активные сервисы Kachō + OperationService через OpsProxy.
// loadbalancer (kacho-nlb) — NetworkLoadBalancer / Listener / TargetGroup
// регистрируются на public mux (/nlb/v1/*). InternalResourceLifecycleService —
// streaming gRPC-direct only (нет HTTP-аннотаций; consumer'ы ходят в loadbalancer.kacho.svc:9091
// напрямую gRPC; через grpc-gateway не проксируется).
//
// # Split-mux pattern
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
//   - Все остальное → public mux.
//
// Корневой `http.Handler` (диспетчер) экспонируется как `http.Handler`
// и передается в `httpMux.Handle("/", restHandler)` в `cmd/api-gateway/main.go`.
//
// # Активные сервисы
//
//   - iam.v1: Account, Project, User, ServiceAccount, Group, Role, AccessBinding
//   - vpc.v1: Network, Subnet, Address, RouteTable, SecurityGroup, Gateway, NetworkInterface
//   - vpc.v1 admin (kacho-only): AddressPool, InternalNetwork — обслуживаются
//     internal-портом vpc backend (9091).
//   - compute.v1: Disk, Image, Snapshot, Instance, DiskType
//     (Geography Region/Zone — отдельный leaf-сервис geo.v1.)
//   - compute.v1 admin (kacho-only): InternalDiskType — обслуживается
//     internal-портом compute backend (9091).
//   - geo.v1: RegionService, ZoneService — public read под /geo/v1/regions,
//     /geo/v1/zones (geoAddr). Geography — leaf-сервис kacho-geo; обслуживается
//     ИСКЛЮЧИТЕЛЬНО geo.v1.
//   - geo.v1 admin (kacho-only): InternalRegionService, InternalZoneService — admin Region/Zone
//     CRUD на internal-порту geo backend (geoInternalAddr, 9091); cluster-internal only (ban #6).
//   - loadbalancer.v1 (kacho-nlb): NetworkLoadBalancerService, ListenerService,
//     TargetGroupService — публичные RPC под /nlb/v1/*. InternalResourceLifecycleService —
//     streaming gRPC-direct only, REST не регистрируется (нет http-аннотаций).
//   - registry.v1 (kacho-registry): RegistryService — публичный control-plane реестра
//     под /registry/v1/* (registries CRUD + repositories/tags/DeleteTag).
//     InternalRegistryService (GC/stats admin, :9091) — без http-аннотаций → default
//     unbound-route, cluster-internal only (ban #6). Data-plane OCI v2 — отдельный ingress.
//   - iam.v1: Account, Project, User (read+delete only), ServiceAccount, Group, Role, AccessBinding —
//     все RPC public под /iam/v1/*.
//   - iam.v1 admin (kacho-only): InternalUserService.Get — для admin tooling; зарегистрирован
//     в internal mux pro-forma (proto-аннотации `google.api.http` отсутствуют → real-трафик
//     идет только через gRPC-direct до kacho-iam:9091) + REST для UpsertFromIdentity.
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

	computepb "github.com/PRO-Robotech/kacho-compute/proto/gen/go/kacho/cloud/compute/v1"
	// geo.v1 — Region/Zone leaf-сервис kacho-geo.
	geopb "github.com/PRO-Robotech/kacho-geo/proto/gen/go/kacho/cloud/geo/v1"
	iampb "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"
	// kacho-nlb (loadbalancer.v1) — public RPC под /nlb/v1/*.
	operationpb "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/operation"
	lbpb "github.com/PRO-Robotech/kacho-nlb/proto/gen/go/kacho/cloud/loadbalancer/v1"
	// kacho-registry (registry.v1) — public RPC под /registry/v1/*.
	registrypb "github.com/PRO-Robotech/kacho-registry/proto/gen/go/kacho/cloud/registry/v1"
	vpcpb "github.com/PRO-Robotech/kacho-vpc/proto/gen/go/kacho/cloud/vpc/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// buildPrincipalMetadata собирает outgoing gRPC-metadata из HTTP middleware-set
// headers для re-dial в backend (public ИЛИ internal mux):
//   - x-kacho-principal-{type,id,display-name} — forwarded end-user principal,
//     который backend trust-aware extract заносит в ctx.
//   - x-kacho-token-acr — validated JWT acr. Public DPoP-middleware уже выставляет
//     `X-Kacho-Token-Acr` (downstream audit); здесь он пробрасывается на :9091
//     re-dial, чтобы iam internal acr-floor мог энфорсить `required_acr_min` на
//     gateway-fronted privileged RPC (иначе acr обрывался бы на internal re-dial).
//     Forward-only on the mTLS-verified gateway→iam edge; iam доверяет acr только
//     на этом проверенном ребре.
//
// HTTP middleware (`auth.HTTP` / DPoP) ставит headers с `Grpc-Metadata-` префиксом
// (canonical в r.Header); читаем оба варианта (с/без префикса) чтобы быть robust.
// Отсутствующий header → ключ не добавляется (никаких пустых значений).
func buildPrincipalMetadata(r *http.Request) metadata.MD {
	md := metadata.MD{}
	get := func(canonical, fallback string) string {
		if v := r.Header.Get(canonical); v != "" {
			return v
		}
		return r.Header.Get(fallback)
	}
	pt := get("Grpc-Metadata-X-Kacho-Principal-Type", "X-Kacho-Principal-Type")
	pi := get("Grpc-Metadata-X-Kacho-Principal-Id", "X-Kacho-Principal-Id")
	pd := get("Grpc-Metadata-X-Kacho-Principal-Display-Name", "X-Kacho-Principal-Display-Name")
	acr := get("Grpc-Metadata-X-Kacho-Token-Acr", "X-Kacho-Token-Acr")
	if pt != "" {
		md.Append("x-kacho-principal-type", pt)
	}
	if pi != "" {
		md.Append("x-kacho-principal-id", pi)
	}
	if pd != "" {
		md.Append("x-kacho-principal-display-name", pd)
	}
	if acr != "" {
		md.Append("x-kacho-token-acr", acr)
	}
	return md
}

// isInternalPath решает, какой sub-mux обрабатывает запрос.
//
// Правила (в порядке проверки):
//  1. Любой path-сегмент `/internal` ИЛИ verb-suffix `:internal` → internal mux.
//     Покрывает `/vpc/v1/networks/{id}/internal`,
//     `/vpc/v1/networkInterfaces/{id}/internal`, `/vpc/v1/networks/{id}:internal`
//     (InternalNetworkService.GetNetwork) и любые будущие `*/internal` / `*:internal`.
//  2. `/vpc/v1/addressPools` → internal.
//  3. `/vpc/v1/networks/{id}/addressPoolBinding` → internal.
//  4. Все остальное → public.
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
		// mux and would slip past the external-isolation gate for
		// infra-sensitive data.
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

	// (4) Internal*Service default unbound-route
	// (`/kacho.cloud.<domain>.v1.Internal<Xxx>Service/<Method>`). Сервисы без
	// `google.api.http`-аннотаций (InternalRegistryService: GC/stats admin) при
	// `generate_unbound_methods` получают default gRPC-style REST-путь — он не
	// содержит сегмента `/internal`, поэтому явно ловим его тем же предикатом,
	// что gRPC-роутер (HasInternalSuffix). Без этого admin-путь ушел бы на public
	// mux и просочился на external listener (ban #6). Форма пути совпадает с
	// gRPC-FQN (ведущий "/"), которую HasInternalSuffix и разбирает; для обычных
	// REST-путей (`/registry/v1/registries`, `/vpc/v1/networks`) предикат ложен.
	if allowlist.HasInternalSuffix(path) {
		return true
	}

	return false
}

// NewMux создает grpc-gateway split-mux (public + internal) и регистрирует
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
//	"loadbalancer"         → kacho-nlb.kacho.svc.cluster.local:9090
//	"loadbalancerInternal" → kacho-nlb.kacho.svc.cluster.local:9091 (зарезервирован
//	                        под admin/internal REST, если в будущем добавятся http-аннотации;
//	                        сейчас InternalResourceLifecycleService — streaming gRPC-direct only)
//	"geo"                  → kacho-geo.kacho.svc.cluster.local:9090 (Region/Zone read)
//	"geoInternal"          → kacho-geo-internal.kacho.svc.cluster.local:9091 (admin Region/Zone CRUD)
//	"registry"             → kacho-registry.kacho.svc.cluster.local:9090 (RegistryService control-plane)
//	"registryInternal"     → kacho-registry.kacho.svc.cluster.local:9091 (InternalRegistryService GC/stats admin)
//
// conns — карта domain → *grpc.ClientConn (нужна для OpsProxy);
// при nil — OperationService регистрируется через no-op Unimplemented (тесты).
//
// dialOpts — карта backend-key → transport-credentials grpc.DialOption.
// Ключи совпадают с `addrs` / `config.BackendAddrs()` (vpc/vpcInternal/compute/
// computeInternal/iam/iamInternal/loadbalancer/loadbalancerInternal). Для каждого
// backend'а REST-mux дозванивается с ЕГО per-edge creds: mTLS client-cert +
// корректный ServerName, когда mTLS на edge включен; insecure — когда нет.
//
// Per-edge creds обязательны: когда backend'ы работают в режиме
// `tls.RequireAndVerifyClientCert`, единый insecure dial обрывался бы на
// TLS-handshake → connection reset → 503. Composition-root
// (`cmd/api-gateway/main.go`) собирает dialOpts через `buildBackendDialCreds(cfg)`
// (те же per-edge creds, что gRPC-роутинг / authz-dial) — новой cert-обвязки не
// вводится.
//
// dialOpts может быть nil или не содержать ключ — тогда для этого backend'а
// используется insecure dial (dev backward-compat). enable=false на edge также
// дает insecure (creds-резолвер в main.go возвращает insecure-опцию).
func NewMux(
	ctx context.Context,
	addrs map[string]string,
	conns map[string]*grpc.ClientConn,
	dialOpts map[string]grpc.DialOption,
) (http.Handler, error) {
	// JSON-marshallers (отличаются ТОЛЬКО `EmitUnpopulated`):
	//   - public: EmitUnpopulated=true — отдаем явные нулевые значения
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

	// Explicit IncomingHeaderMatcher для x-kacho-principal-*
	// + WithMetadata callback что явно собирает outgoing metadata из
	// HTTP middleware-set headers `X-Kacho-Principal-*`. Без WithMetadata
	// grpc-gateway не пробрасывает кастомные headers — одного
	// IncomingHeaderMatcher мало.
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
		return buildPrincipalMetadata(r)
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

	// optsFor returns the dial-options for one backend-key: that backend's
	// per-edge transport credentials (mTLS client-cert + ServerName when the edge
	// is enabled, else insecure) plus the shared round-robin service-config. When
	// dialOpts has no entry for the key the dial falls back to insecure — dev
	// backward-compat.
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

	// lbAddr / lbInternalAddr обслуживают kacho-nlb (loadbalancer.v1).
	// registryAddr / registryInternalAddr обслуживают kacho-registry (registry.v1).
	var vpcAddr, vpcInternalAddr, computeAddr, computeInternalAddr, iamAddr, iamInternalAddr, lbAddr, lbInternalAddr, geoAddr, geoInternalAddr, registryAddr, registryInternalAddr string
	if addrs != nil {
		vpcAddr = addrs["vpc"]
		vpcInternalAddr = addrs["vpcInternal"]
		computeAddr = addrs["compute"]
		computeInternalAddr = addrs["computeInternal"]
		iamAddr = addrs["iam"]
		iamInternalAddr = addrs["iamInternal"]
		lbAddr = addrs["loadbalancer"]
		lbInternalAddr = addrs["loadbalancerInternal"]
		geoAddr = addrs["geo"]
		geoInternalAddr = addrs["geoInternal"]
		registryAddr = addrs["registry"]
		registryInternalAddr = addrs["registryInternal"]
	}

	// Регистрируем КАЖДЫЙ handler на ОБА mux'а (public + internal). Path-based
	// dispatch (isInternalPath) ниже выбирает, какой из них фактически обработает
	// конкретный запрос — разница только в JSON-маршалинге. Так нам не нужно
	// заранее знать, какой RPC попадет на какой путь: grpc-gateway сам разрулит,
	// а мы лишь подсовываем правильный JSONPb.
	muxes := []*runtime.ServeMux{publicMux, internalMux}

	for _, mux := range muxes {
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
		// Эти сервисы экспонируются через apiGW REST для UI/админ-tooling;
		// путь /vpc/v1/addressPools.
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

		// --- compute: Disk + Image + Snapshot + Instance + DiskType ---
		// Geography (Region/Zone) обслуживается отдельным leaf-сервисом kacho-geo
		// (/geo/v1/regions, /geo/v1/zones; см. ниже), а не compute.v1.
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

		// --- compute admin (InternalDiskType) — kacho-only, internal-port (9091) ---
		// CRUD справочника DiskType (POST/PATCH/DELETE на /compute/v1/diskTypes).
		// Доступен только через cluster-internal REST listener для UI/admin-tooling
		// (запрет #6). InternalWatchService — gRPC server-streaming (outbox), через
		// grpc-gateway REST не проксируется; consumer'ы ходят в compute.kacho.svc:9091
		// напрямую gRPC. Admin Region/Zone обслуживает geo.v1.
		if computeInternalAddr != "" {
			if err := computepb.RegisterInternalDiskTypeServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, optsFor("computeInternal")); err != nil {
				return nil, fmt.Errorf("register compute InternalDiskTypeService: %w", err)
			}
		}

		// --- geo.v1: Region + Zone (public read-only) ---
		// Geography (Region/Zone) — отдельный leaf-сервис kacho-geo.
		// RegionService/ZoneService — public read под /geo/v1/regions,
		// /geo/v1/zones. Регистрируется условно по geoAddr (graceful: kacho-geo
		// может быть еще не задеплоен — симметрично lbAddr/iamAddr выше).
		// Geography обслуживается ИСКЛЮЧИТЕЛЬНО geo.v1.
		if geoAddr != "" {
			if err := geopb.RegisterRegionServiceHandlerFromEndpoint(ctx, mux, geoAddr, optsFor("geo")); err != nil {
				return nil, fmt.Errorf("register geo RegionService: %w", err)
			}
			if err := geopb.RegisterZoneServiceHandlerFromEndpoint(ctx, mux, geoAddr, optsFor("geo")); err != nil {
				return nil, fmt.Errorf("register geo ZoneService: %w", err)
			}
		}

		// --- geo admin (InternalRegionService/InternalZoneService) — kacho-only, internal-port (9091) ---
		// Admin-CRUD справочников Region/Zone (POST/PATCH/DELETE на /geo/v1/regions,
		// /geo/v1/zones). Доступен ТОЛЬКО через cluster-internal REST listener для
		// UI/admin-tooling (запрет #6). На external TLS endpoint admin Region/Zone-
		// функции не светятся: gRPC-роутер блокирует Internal*-сервисы через
		// HasInternalSuffix, а authz-каталог гейтит эти RPC relation `system_admin`
		// на cluster-singleton. Мутации Region/Zone — это catalog-паттерн (sync-ответ
		// ресурсом, НЕ Operation; как InternalDiskType).
		if geoInternalAddr != "" {
			if err := geopb.RegisterInternalRegionServiceHandlerFromEndpoint(ctx, mux, geoInternalAddr, optsFor("geoInternal")); err != nil {
				return nil, fmt.Errorf("register geo InternalRegionService: %w", err)
			}
			if err := geopb.RegisterInternalZoneServiceHandlerFromEndpoint(ctx, mux, geoInternalAddr, optsFor("geoInternal")); err != nil {
				return nil, fmt.Errorf("register geo InternalZoneService: %w", err)
			}
		}

		// --- iam.v1: Account + Project + User (read+delete only) + ServiceAccount + Group + Role + AccessBinding ---
		// Public surface: все 7 сервисов под /iam/v1/*.
		// User не имеет публичного Create — User'ы создаются через
		// InternalUserService.UpsertFromIdentity (OIDC-callback в api-gateway);
		// display_name/email берется из Zitadel при следующем UpsertFromIdentity.
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
			// PermissionCatalogService.ListPermissionCatalog — public read under
			// GET /iam/v1/permissionCatalog: an authenticated-floor read (<exempt>
			// in the permission catalog — no FGA Check) that the UI calls to build its
			// role/permission palette. PUBLIC (external) on purpose, NOT an Internal*
			// service — registered here in the public iam block, not the iamInternalAddr
			// block; the gRPC-router allowlists it for the external listener.
			if err := iampb.RegisterPermissionCatalogServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam PermissionCatalogService: %w", err)
			}
			if err := iampb.RegisterAccessBindingServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam AccessBindingService: %w", err)
			}
			// SAKeyService (ServiceAccount OAuth keys). Public under
			// /iam/v1/serviceAccounts/{id}/keys. Без этой регистрации grpc-gateway
			// не имеет REST-route → POST .../keys → 404, и SAKeyService.Issue/Revoke
			// недоступны.
			if err := iampb.RegisterSAKeyServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam SAKeyService: %w", err)
			}
			// AuthorizeService — tenant FGA check (POST /iam/v1/authorize:check).
			if err := iampb.RegisterAuthorizeServiceHandlerFromEndpoint(ctx, mux, iamAddr, optsFor("iam")); err != nil {
				return nil, fmt.Errorf("register iam AuthorizeService: %w", err)
			}
		}

		// --- iam.v1 admin (InternalUserService + InternalIAMService) —
		// kacho-only, internal-port (9091); запрет #6 ---
		// REST HTTP annotations on internal IAM proto RPCs (UpsertFromIdentity,
		// LookupSubject, ListPermissions, Check) make grpc-gateway create routes
		// for /iam/v1/internal/* paths.
		// These handlers are dispatched to the internal mux (isInternalPath
		// returns true for any path containing /internal/); the authz middleware
		// lets them through via the public allowlist (no Bearer JWT required —
		// the IAM service enforces its own per-handler auth via authzguard
		// interceptor whitelist). External TLS listener never serves these
		// paths — the gRPC router's HasInternalSuffix blocks Internal* services
		// on the public listener.
		if iamInternalAddr != "" {
			if err := iampb.RegisterInternalUserServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalUserService: %w", err)
			}
			if err := iampb.RegisterInternalIAMServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalIAMService: %w", err)
			}
			// InternalClusterService — cluster-admin RBAC management
			// (Get / GrantAdmin / RevokeAdmin / ListAdmins) under
			// /iam/v1/internal/cluster/...  Internal-only (запрет #6);
			// isInternalPath sends these paths to the internal sub-mux. Catalog gate
			// (`required_relation: admin`) enforces the FGA computed-alias
			// `system_admin OR emergency_admin` on `cluster:cluster_kacho_root`.
			if err := iampb.RegisterInternalClusterServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalClusterService: %w", err)
			}
			// InternalOperationsService.ListIamOperations — cluster-wide IAM
			// operations dump for admin-UI under GET /iam/v1/internal/operations.
			// Internal-only (запрет #6); isInternalPath routes /iam/v1/internal/* to
			// the internal sub-mux and the dispatcher 404s it on the external TLS
			// listener. The gRPC router's HasInternalSuffix also blocks the
			// InternalOperationsService suffix on the public listener.
			// admin-tier is enforced by the permission-catalog entry
			// (required_relation: system_admin, scope cluster:cluster_kacho_root, acr 2),
			// parity with InternalClusterService/*; the iam :9091 backend additionally
			// runs its own per-RPC authz-Check.
			if err := iampb.RegisterInternalOperationsServiceHandlerFromEndpoint(ctx, mux, iamInternalAddr, optsFor("iamInternal")); err != nil {
				return nil, fmt.Errorf("register iam InternalOperationsService: %w", err)
			}
		}

		// --- loadbalancer.v1 (kacho-nlb): NetworkLoadBalancer + Listener + TargetGroup ---
		// Public RPC под /nlb/v1/*. Регистрируется условно по lbAddr — backend еще
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
		// подписки на CREATED/UPDATED/DELETED события (outbox).
		// В proto НЕТ `option (google.api.http)`, поэтому grpc-gateway не создает REST-routes —
		// consumer'ы (наблюдатели data-plane) дозваниваются по gRPC напрямую до
		// loadbalancer.kacho.svc:9091 через grpc-client. Регистрация здесь — pro-forma
		// reference (симметрично iam InternalUserService); если в будущем добавятся
		// http-аннотации, REST автоматически появится на internal mux.
		// HasInternalSuffix в gRPC-роутере (server.go Resolver / shimproxy.go)
		// блокирует попадание InternalResourceLifecycleService.* на external/TLS
		// endpoint (запрет #6).
		if lbInternalAddr != "" {
			if err := lbpb.RegisterInternalResourceLifecycleServiceHandlerFromEndpoint(ctx, mux, lbInternalAddr, optsFor("loadbalancerInternal")); err != nil {
				return nil, fmt.Errorf("register loadbalancer InternalResourceLifecycleService: %w", err)
			}
		}

		// --- registry.v1 (kacho-registry): RegistryService ---
		// Public control-plane реестра под /registry/v1/*: registries CRUD +
		// per-repo проекции (repositories/tags/DeleteTag). Регистрируется условно
		// по registryAddr — backend еще может быть не задеплоен (поведение
		// симметрично lbAddr / geoAddr выше). Data-plane OCI v2 (/v2/*) — отдельный
		// ingress, НЕ через api-gateway.
		if registryAddr != "" {
			if err := registrypb.RegisterRegistryServiceHandlerFromEndpoint(ctx, mux, registryAddr, optsFor("registry")); err != nil {
				return nil, fmt.Errorf("register registry RegistryService: %w", err)
			}
		}

		// --- registry.v1 admin (InternalRegistryService) — kacho-only, internal-port (9091) ---
		// TriggerGarbageCollection (GC zot-стора) + GetRegistryStats (инфра-проекция
		// namespace: blob/размер — security.md). В proto НЕТ `google.api.http`, поэтому
		// grpc-gateway создает default unbound-route
		// POST /kacho.cloud.registry.v1.InternalRegistryService/<Method> (аналог iam
		// InternalUserService.Get). Доступно ТОЛЬКО через cluster-internal REST listener:
		// dispatcher (isInternalPath → HasInternalSuffix) 404-ит эти пути на external
		// TLS listener (ban #6), а gRPC-роутер блокирует Internal* через HasInternalSuffix.
		// Admin-tooling может ходить и напрямую gRPC до kacho-registry:9091.
		if registryInternalAddr != "" {
			if err := registrypb.RegisterInternalRegistryServiceHandlerFromEndpoint(ctx, mux, registryInternalAddr, optsFor("registryInternal")); err != nil {
				return nil, fmt.Errorf("register registry InternalRegistryService: %w", err)
			}
		}

		// --- OperationService (OpsProxy, in-process) ---
		// Не имеет отдельного backend — живет in-process как OpsProxy.
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
	// маршалинг ответа (EmitUnpopulated). Запрос НЕ переадресуется куда-то еще:
	// internal sub-mux обработает request тем же handler'ом, что и public, но
	// сожмет response пустых полей.
	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isInternalPath(r.URL.Path) {
			// SECURITY (запрет #6): Internal* REST paths are cluster-internal-only.
			// When the request arrived on the advertised external TLS listener
			// (listenerorigin.IsExternal), reject with 404 — existence-hiding,
			// mirroring the gRPC router's HasInternalSuffix block. Internal-listener
			// callers (UI / admin-tooling / port-forward / service self-calls) are
			// unmarked → served as before.
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
