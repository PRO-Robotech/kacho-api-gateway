package allowlist

import "strings"

// AllowedMethods — публичные RPC-пути, маршрутизируемые через api-gateway.
// Методы *InternalService.* НИКОГДА не включаются (запрет #7, CLAUDE.md).
var AllowedMethods = map[string]struct{}{
	// resource-manager — OrganizationService
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Upsert": {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Delete": {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/List":   {},
	"/kacho.cloud.resourcemanager.v1.OrganizationService/Watch":  {},
	// resource-manager — CloudService
	"/kacho.cloud.resourcemanager.v1.CloudService/Upsert": {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Delete": {},
	"/kacho.cloud.resourcemanager.v1.CloudService/List":   {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Watch":  {},
	// resource-manager — FolderService
	"/kacho.cloud.resourcemanager.v1.FolderService/Upsert": {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Delete": {},
	"/kacho.cloud.resourcemanager.v1.FolderService/List":   {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Watch":  {},

	// vpc — NetworkService
	"/kacho.cloud.vpc.v1.NetworkService/Upsert": {},
	"/kacho.cloud.vpc.v1.NetworkService/Delete": {},
	"/kacho.cloud.vpc.v1.NetworkService/List":   {},
	"/kacho.cloud.vpc.v1.NetworkService/Watch":  {},
	// vpc — SubnetService
	"/kacho.cloud.vpc.v1.SubnetService/Upsert": {},
	"/kacho.cloud.vpc.v1.SubnetService/Delete": {},
	"/kacho.cloud.vpc.v1.SubnetService/List":   {},
	"/kacho.cloud.vpc.v1.SubnetService/Watch":  {},
	// vpc — SecurityGroupService
	"/kacho.cloud.vpc.v1.SecurityGroupService/Upsert": {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Delete": {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/List":   {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Watch":  {},
	// vpc — RouteTableService
	"/kacho.cloud.vpc.v1.RouteTableService/Upsert": {},
	"/kacho.cloud.vpc.v1.RouteTableService/Delete": {},
	"/kacho.cloud.vpc.v1.RouteTableService/List":   {},
	"/kacho.cloud.vpc.v1.RouteTableService/Watch":  {},
	// vpc — AddressService
	"/kacho.cloud.vpc.v1.AddressService/Upsert": {},
	"/kacho.cloud.vpc.v1.AddressService/Delete": {},
	"/kacho.cloud.vpc.v1.AddressService/List":   {},
	"/kacho.cloud.vpc.v1.AddressService/Watch":  {},

	// compute — InstanceService (5 методов, включая Restart)
	"/kacho.cloud.compute.v1.InstanceService/Upsert":  {},
	"/kacho.cloud.compute.v1.InstanceService/Delete":  {},
	"/kacho.cloud.compute.v1.InstanceService/List":    {},
	"/kacho.cloud.compute.v1.InstanceService/Watch":   {},
	"/kacho.cloud.compute.v1.InstanceService/Restart": {},
	// compute — DiskService
	"/kacho.cloud.compute.v1.DiskService/Upsert": {},
	"/kacho.cloud.compute.v1.DiskService/Delete": {},
	"/kacho.cloud.compute.v1.DiskService/List":   {},
	"/kacho.cloud.compute.v1.DiskService/Watch":  {},
	// compute — ImageService (только Get/List — read-only)
	"/kacho.cloud.compute.v1.ImageService/Get":  {},
	"/kacho.cloud.compute.v1.ImageService/List": {},
	// compute — SnapshotService
	"/kacho.cloud.compute.v1.SnapshotService/Upsert": {},
	"/kacho.cloud.compute.v1.SnapshotService/Delete": {},
	"/kacho.cloud.compute.v1.SnapshotService/List":   {},
	"/kacho.cloud.compute.v1.SnapshotService/Watch":  {},

	// loadbalancer — NetworkLoadBalancerService
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Upsert": {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete": {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List":   {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Watch":  {},
	// loadbalancer — TargetGroupService
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Upsert": {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Delete": {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/List":   {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Watch":  {},
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
