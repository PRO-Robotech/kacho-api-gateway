// Package restmux инициализирует grpc-gateway ServeMux для REST-запросов.
//
// Регистрирует все 14 публичных сервисов Kachō через RegisterXxxServiceHandlerFromEndpoint.
// *InternalService* не регистрируются (запрет CLAUDE.md #7).
//
// URL-конвенция: POST /v1/<resource-plural-kebab>/<action>
// Примеры:
//
//	POST /v1/organizations/list
//	POST /v1/instances/restart
//	POST /v1/network-load-balancers/upsert
package restmux

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	cmpv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/compute/v1"
	lbv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/loadbalancer/v1"
	rmv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/resourcemanager/v1"
	vpcv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/vpc/v1"
)

// NewMux создаёт grpc-gateway ServeMux и регистрирует все 14 публичных сервисов.
// addrs — карта domain → адрес gRPC backend:
//
//	"resourcemanager" → resource-manager.kacho.svc.cluster.local:9090
//	"vpc"             → vpc.kacho.svc.cluster.local:9090
//	"compute"         → compute.kacho.svc.cluster.local:9090
//	"loadbalancer"    → loadbalancer.kacho.svc.cluster.local:9090
func NewMux(ctx context.Context, addrs map[string]string) (*runtime.ServeMux, error) {
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	rmAddr := addrs["resourcemanager"]
	vpcAddr := addrs["vpc"]
	cmpAddr := addrs["compute"]
	lbAddr := addrs["loadbalancer"]

	// --- resourcemanager ---
	if err := rmv1.RegisterOrganizationServiceHandlerFromEndpoint(ctx, mux, rmAddr, opts); err != nil {
		return nil, fmt.Errorf("register OrganizationService: %w", err)
	}
	if err := rmv1.RegisterCloudServiceHandlerFromEndpoint(ctx, mux, rmAddr, opts); err != nil {
		return nil, fmt.Errorf("register CloudService: %w", err)
	}
	if err := rmv1.RegisterFolderServiceHandlerFromEndpoint(ctx, mux, rmAddr, opts); err != nil {
		return nil, fmt.Errorf("register FolderService: %w", err)
	}

	// --- vpc ---
	if err := vpcv1.RegisterNetworkServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
		return nil, fmt.Errorf("register NetworkService: %w", err)
	}
	if err := vpcv1.RegisterSubnetServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
		return nil, fmt.Errorf("register SubnetService: %w", err)
	}
	if err := vpcv1.RegisterSecurityGroupServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
		return nil, fmt.Errorf("register SecurityGroupService: %w", err)
	}
	if err := vpcv1.RegisterRouteTableServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
		return nil, fmt.Errorf("register RouteTableService: %w", err)
	}
	if err := vpcv1.RegisterAddressServiceHandlerFromEndpoint(ctx, mux, vpcAddr, opts); err != nil {
		return nil, fmt.Errorf("register AddressService: %w", err)
	}

	// --- compute ---
	if err := cmpv1.RegisterInstanceServiceHandlerFromEndpoint(ctx, mux, cmpAddr, opts); err != nil {
		return nil, fmt.Errorf("register InstanceService: %w", err)
	}
	if err := cmpv1.RegisterDiskServiceHandlerFromEndpoint(ctx, mux, cmpAddr, opts); err != nil {
		return nil, fmt.Errorf("register DiskService: %w", err)
	}
	if err := cmpv1.RegisterImageServiceHandlerFromEndpoint(ctx, mux, cmpAddr, opts); err != nil {
		return nil, fmt.Errorf("register ImageService: %w", err)
	}
	if err := cmpv1.RegisterSnapshotServiceHandlerFromEndpoint(ctx, mux, cmpAddr, opts); err != nil {
		return nil, fmt.Errorf("register SnapshotService: %w", err)
	}

	// --- loadbalancer ---
	if err := lbv1.RegisterNetworkLoadBalancerServiceHandlerFromEndpoint(ctx, mux, lbAddr, opts); err != nil {
		return nil, fmt.Errorf("register NetworkLoadBalancerService: %w", err)
	}
	if err := lbv1.RegisterTargetGroupServiceHandlerFromEndpoint(ctx, mux, lbAddr, opts); err != nil {
		return nil, fmt.Errorf("register TargetGroupService: %w", err)
	}

	return mux, nil
}
