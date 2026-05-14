// Package restmux инициализирует grpc-gateway ServeMux для REST-запросов.
//
// Регистрирует активные сервисы Kachō + OperationService через OpsProxy.
// loadbalancer — НЕ регистрируется (заморожен).
//
// Активные сервисы:
//   - resourcemanager.v1: Cloud, Folder
//   - organizationmanager.v1: Organization (backend: resource-manager)
//   - vpc.v1: Network, Subnet, Address, RouteTable, SecurityGroup, Gateway, PrivateEndpoint, NetworkInterface
//   - vpc.v1 admin (kacho-only, NOT YC-verbatim): AddressPool, Cloud, InternalNetworkInterface —
//     обслуживаются internal-портом vpc backend (9091); см. kacho-vpc/CLAUDE.md §16.
//   - compute.v1: Disk, Image, Snapshot, Instance, DiskType, Zone, Region
//     (Geography Region/Zone перенесены сюда из vpc — эпик KAC-15)
//   - compute.v1 admin (kacho-only, NOT YC-verbatim): InternalDiskType, InternalZone, InternalRegion, InternalHypervisor —
//     обслуживаются internal-портом compute backend (9091); см. kacho-compute/CLAUDE.md.
//   - operation (без v1!): OperationService (in-process OpsProxy)
package restmux

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	computepb   "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/compute/v1"
	orgpb       "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/organizationmanager/v1"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
	rmpb        "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/resourcemanager/v1"
	vpcpb       "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1"
	pepb        "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1/privatelink"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// NewMux создаёт grpc-gateway ServeMux и регистрирует активные публичные сервисы
// плюс OperationService (через OpsProxy).
//
// addrs — карта domain → адрес gRPC backend:
//
//	"resourcemanager"     → resource-manager.kacho.svc.cluster.local:9090
//	"organizationmanager" → resource-manager.kacho.svc.cluster.local:9090 (тот же backend)
//	"vpc"                 → vpc.kacho.svc.cluster.local:9090
//	"vpcInternal"         → vpc.kacho.svc.cluster.local:9091 (admin internal-порт)
//	"compute"             → compute.kacho.svc.cluster.local:9090
//	"computeInternal"     → compute.kacho.svc.cluster.local:9091 (admin internal-порт)
//
// conns — карта domain → *grpc.ClientConn (нужна для OpsProxy);
// при nil — OperationService регистрируется через no-op Unimplemented (тесты).
func NewMux(ctx context.Context, addrs map[string]string, conns map[string]*grpc.ClientConn) (*runtime.ServeMux, error) {
	// JSON-marshaller (общий для public + internal endpoints — единственный mux):
	//   - UseProtoNames=false → camelCase JSON-поля.
	//   - EmitUnpopulated=true → отдаём явные нулевые значения (`""`/`{}`/`[]`/`null`)
	//     для proto-полей. На публичной поверхности (Network/Subnet/Address/NIC/SG/RT/
	//     Gateway/PE) `description`/`labels`/`cidr_blocks`/`v4_address_ids` и т.п. —
	//     полезный контракт, клиент должен видеть поле даже если оно пустое.
	//
	// TODO: для internal endpoints (`/vpc/v1/.../internal`) имеет смысл
	// `EmitUnpopulated=false` (там много инфра-полей `vpn_id`/`hv_id`/`sid`/
	// `host_iface`/`netns`/... которые часто пустые). Сейчас один общий mux,
	// поэтому marshaller единый. Refactor: split internal на отдельный
	// `ServeMux` с собственным marshaller'ом (= отдельный тикет).
	jsonMarshaler := &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames:   false,
			EmitUnpopulated: true,
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	}
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, jsonMarshaler),
	)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Client-side round-robin; pair with `dns:///<headless-svc>:<port>` dial target.
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
	}

	var rmAddr, vpcAddr, vpcInternalAddr, computeAddr, computeInternalAddr string
	if addrs != nil {
		rmAddr = addrs["resourcemanager"]
		vpcAddr = addrs["vpc"]
		vpcInternalAddr = addrs["vpcInternal"]
		computeAddr = addrs["compute"]
		computeInternalAddr = addrs["computeInternal"]
	}

	// --- resourcemanager: Cloud + Folder ---
	if err := rmpb.RegisterCloudServiceHandlerFromEndpoint(ctx, mux, rmAddr, opts); err != nil {
		return nil, fmt.Errorf("register CloudService: %w", err)
	}
	if err := rmpb.RegisterFolderServiceHandlerFromEndpoint(ctx, mux, rmAddr, opts); err != nil {
		return nil, fmt.Errorf("register FolderService: %w", err)
	}

	// --- organizationmanager: Organization (backend: resource-manager) ---
	if err := orgpb.RegisterOrganizationServiceHandlerFromEndpoint(ctx, mux, rmAddr, opts); err != nil {
		return nil, fmt.Errorf("register OrganizationService: %w", err)
	}

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
		if err := vpcpb.RegisterInternalNetworkInterfaceServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
			return nil, fmt.Errorf("register InternalNetworkInterfaceService: %w", err)
		}
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
		if err := computepb.RegisterInternalHypervisorServiceHandlerFromEndpoint(ctx, mux, computeInternalAddr, opts); err != nil {
			return nil, fmt.Errorf("register compute InternalHypervisorService: %w", err)
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

	return mux, nil
}
