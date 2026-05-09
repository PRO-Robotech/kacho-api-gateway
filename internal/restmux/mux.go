// Package restmux инициализирует grpc-gateway ServeMux для REST-запросов.
//
// Регистрирует активные сервисы Kachō 1.0 + OperationService через OpsProxy.
// Compute, loadbalancer, SecurityGroup, Gateway — НЕ регистрируются (заморожены).
//
// Активные сервисы:
//   - resourcemanager.v1: Cloud, Folder
//   - organizationmanager.v1: Organization (backend: resource-manager)
//   - vpc.v1: Network, Subnet, Address, RouteTable, SecurityGroup, Gateway, PrivateEndpoint
//   - vpc.v1 admin (kacho-only, NOT YC-verbatim): Region, Zone, AddressPool —
//     обслуживаются internal-портом vpc backend (9091); см. CLAUDE.md §16.
//   - operation (без v1!): OperationService (in-process OpsProxy)
package restmux

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	orgpb    "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/organizationmanager/v1"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
	rmpb    "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/resourcemanager/v1"
	vpcpb   "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1"
	pepb    "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1/privatelink"

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
//
// conns — карта domain → *grpc.ClientConn (нужна для OpsProxy);
// при nil — OperationService регистрируется через no-op Unimplemented (тесты).
func NewMux(ctx context.Context, addrs map[string]string, conns map[string]*grpc.ClientConn) (*runtime.ServeMux, error) {
	// JSON-marshaller verbatim YC contract:
	//   - UseProtoNames=false → camelCase JSON-поля.
	//   - EmitUnpopulated=true → отдаём явные нулевые значения (`false`/`""`/`{}`)
	//     для proto-полей; YC так делает (см. YC-DIFF-EMIT-UNPOPULATED.md).
	//
	// Поломка прошлой попытки EmitUnpopulated была в том, что protojson не мог
	// распаковать `BadRequest.field_violations[]` (Any) без зарегистрированного
	// errdetails-типа в protoregistry. Это решено в `cmd/api-gateway/main.go`
	// blank-import `_ "google.golang.org/genproto/googleapis/rpc/errdetails"`,
	// поэтому EmitUnpopulated теперь безопасно включить.
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
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	var rmAddr, vpcAddr, vpcInternalAddr string
	if addrs != nil {
		rmAddr = addrs["resourcemanager"]
		vpcAddr = addrs["vpc"]
		vpcInternalAddr = addrs["vpcInternal"]
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

	// --- vpc: Network + Subnet + Address + RouteTable ---
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

	// --- vpc admin (Region/Zone/AddressPool) — kacho-only, internal-port (9091) ---
	// Эти сервисы экспонируются через apiGW REST для UI/админ-tooling. Не верстаются
	// на verbatim-YC; путь /vpc/v1/regions, /vpc/v1/zones, /vpc/v1/addressPools.
	if vpcInternalAddr != "" {
		if err := vpcpb.RegisterInternalRegionServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
			return nil, fmt.Errorf("register InternalRegionService: %w", err)
		}
		if err := vpcpb.RegisterInternalZoneServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
			return nil, fmt.Errorf("register InternalZoneService: %w", err)
		}
		if err := vpcpb.RegisterInternalAddressPoolServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
			return nil, fmt.Errorf("register InternalAddressPoolService: %w", err)
		}
		if err := vpcpb.RegisterInternalCloudServiceHandlerFromEndpoint(ctx, mux, vpcInternalAddr, opts); err != nil {
			return nil, fmt.Errorf("register InternalCloudService: %w", err)
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
