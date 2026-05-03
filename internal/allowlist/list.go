package allowlist

import "strings"

// AllowedMethods — публичные RPC-пути, маршрутизируемые через api-gateway.
// Методы *InternalService.* НИКОГДА не включаются (запрет #7, CLAUDE.md).
// Sub-phase 1.0: Get/List/Create/Update/Delete вместо Upsert/Watch.
var AllowedMethods = map[string]struct{}{
	// resource-manager — OrganizationService
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Get":    {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/List":   {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Create": {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Update": {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Delete": {},
	// resource-manager — CloudService
	"/kacho.cloud.resourcemanager.v1.CloudService/Get":    {},
	"/kacho.cloud.resourcemanager.v1.CloudService/List":   {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Create": {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Update": {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Delete": {},
	// resource-manager — FolderService
	"/kacho.cloud.resourcemanager.v1.FolderService/Get":    {},
	"/kacho.cloud.resourcemanager.v1.FolderService/List":   {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Create": {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Update": {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Delete": {},

	// vpc — NetworkService
	"/kacho.cloud.vpc.v1.NetworkService/Get":    {},
	"/kacho.cloud.vpc.v1.NetworkService/List":   {},
	"/kacho.cloud.vpc.v1.NetworkService/Create": {},
	"/kacho.cloud.vpc.v1.NetworkService/Update": {},
	"/kacho.cloud.vpc.v1.NetworkService/Delete": {},
	// vpc — SubnetService
	"/kacho.cloud.vpc.v1.SubnetService/Get":    {},
	"/kacho.cloud.vpc.v1.SubnetService/List":   {},
	"/kacho.cloud.vpc.v1.SubnetService/Create": {},
	"/kacho.cloud.vpc.v1.SubnetService/Update": {},
	"/kacho.cloud.vpc.v1.SubnetService/Delete": {},
	// vpc — SecurityGroupService
	"/kacho.cloud.vpc.v1.SecurityGroupService/Get":    {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/List":   {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Create": {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Update": {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Delete": {},
	// vpc — RouteTableService
	"/kacho.cloud.vpc.v1.RouteTableService/Get":    {},
	"/kacho.cloud.vpc.v1.RouteTableService/List":   {},
	"/kacho.cloud.vpc.v1.RouteTableService/Create": {},
	"/kacho.cloud.vpc.v1.RouteTableService/Update": {},
	"/kacho.cloud.vpc.v1.RouteTableService/Delete": {},
	// vpc — AddressService
	"/kacho.cloud.vpc.v1.AddressService/Get":    {},
	"/kacho.cloud.vpc.v1.AddressService/List":   {},
	"/kacho.cloud.vpc.v1.AddressService/Create": {},
	"/kacho.cloud.vpc.v1.AddressService/Update": {},
	"/kacho.cloud.vpc.v1.AddressService/Delete": {},

	// compute — InstanceService (Get/List/Create/Update/Delete + Start/Stop/Restart)
	"/kacho.cloud.compute.v1.InstanceService/Get":     {},
	"/kacho.cloud.compute.v1.InstanceService/List":    {},
	"/kacho.cloud.compute.v1.InstanceService/Create":  {},
	"/kacho.cloud.compute.v1.InstanceService/Update":  {},
	"/kacho.cloud.compute.v1.InstanceService/Delete":  {},
	"/kacho.cloud.compute.v1.InstanceService/Start":   {},
	"/kacho.cloud.compute.v1.InstanceService/Stop":    {},
	"/kacho.cloud.compute.v1.InstanceService/Restart": {},
	// compute — DiskService
	"/kacho.cloud.compute.v1.DiskService/Get":    {},
	"/kacho.cloud.compute.v1.DiskService/List":   {},
	"/kacho.cloud.compute.v1.DiskService/Create": {},
	"/kacho.cloud.compute.v1.DiskService/Update": {},
	"/kacho.cloud.compute.v1.DiskService/Delete": {},
	// compute — ImageService (только Get/List — read-only)
	"/kacho.cloud.compute.v1.ImageService/Get":  {},
	"/kacho.cloud.compute.v1.ImageService/List": {},
	// compute — SnapshotService
	"/kacho.cloud.compute.v1.SnapshotService/Get":    {},
	"/kacho.cloud.compute.v1.SnapshotService/List":   {},
	"/kacho.cloud.compute.v1.SnapshotService/Create": {},
	"/kacho.cloud.compute.v1.SnapshotService/Update": {},
	"/kacho.cloud.compute.v1.SnapshotService/Delete": {},

	// loadbalancer — NetworkLoadBalancerService
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get":    {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List":   {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create": {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Update": {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete": {},
	// loadbalancer — TargetGroupService
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Get":    {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/List":   {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Create": {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Update": {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Delete": {},

	// operations — OperationService (фан-аут proxy по domain-prefix в Operation.id)
	"/kacho.cloud.operation.v1.OperationService/Get":    {},
	"/kacho.cloud.operation.v1.OperationService/List":   {},
	"/kacho.cloud.operation.v1.OperationService/Cancel": {},
}

// IsAllowed проверяет, что метод находится в списке разрешённых публичных RPC.
func IsAllowed(methodPath string) bool {
	_, ok := AllowedMethods[methodPath]
	return ok
}

// HasInternalSuffix — эшелонированная защита: любой метод, чей путь содержит
// "InternalService", блокируется автоматически, даже если он случайно попал в AllowedMethods.
func HasInternalSuffix(methodPath string) bool {
	return strings.Contains(methodPath, "InternalService")
}
