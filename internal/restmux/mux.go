// Package restmux инициализирует grpc-gateway ServeMux для REST-запросов.
//
// Регистрирует активные сервисы Kachō 1.0 + OperationService через OpsProxy.
// Compute, loadbalancer, SecurityGroup, Gateway — НЕ регистрируются (заморожены).
// *InternalService* не регистрируются (запрет CLAUDE.md #7).
//
// Активные сервисы:
//   - resourcemanager.v1: Cloud, Folder
//   - organizationmanager.v1: Organization (backend: resource-manager)
//   - vpc.v1: Network, Subnet, Address, RouteTable
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
	// JSON-marshaller с UseProtoNames=false: верстаем JSON-поля в camelCase
	// (verbatim YC contract). EmitUnpopulated=true: отдаём явные нулевые
	// значения для всех полей, чтобы клиент не удивлялся отсутствующим ключам.
	// UI клиент применяет camel↔snake transformer в api/client.ts.
	jsonMarshaler := &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames: false, // verbatim YC contract — camelCase
			// EmitUnpopulated убран: вместе с BadRequest.field_violations[]
			// (Any-message с FieldViolation внутри) protojson возвращает
			// "failed to marshal error message" для error responses.
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	}
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, jsonMarshaler),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	var rmAddr, vpcAddr string
	if addrs != nil {
		rmAddr = addrs["resourcemanager"]
		vpcAddr = addrs["vpc"]
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
