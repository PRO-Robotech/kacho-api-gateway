package allowlist

import "strings"

// AllowedMethods — публичные RPC-пути, маршрутизируемые через api-gateway.
// Методы *InternalService.* НИКОГДА не включаются (запрет #7, CLAUDE.md).
// Sub-phase 1.0 (verbatim YC proto): активны resourcemanager, organizationmanager, vpc, operation.
// Compute и loadbalancer заморожены — их методов здесь нет.
var AllowedMethods = map[string]struct{}{
	// resourcemanager.v1 — CloudService
	"/kacho.cloud.resourcemanager.v1.CloudService/Get":            {},
	"/kacho.cloud.resourcemanager.v1.CloudService/List":           {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Create":         {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Update":         {},
	"/kacho.cloud.resourcemanager.v1.CloudService/Delete":         {},
	"/kacho.cloud.resourcemanager.v1.CloudService/ListOperations": {},
	// resourcemanager.v1 — FolderService
	"/kacho.cloud.resourcemanager.v1.FolderService/Get":            {},
	"/kacho.cloud.resourcemanager.v1.FolderService/List":           {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Create":         {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Update":         {},
	"/kacho.cloud.resourcemanager.v1.FolderService/Delete":         {},
	"/kacho.cloud.resourcemanager.v1.FolderService/ListOperations": {},

	// organizationmanager.v1 — OrganizationService
	"/kacho.cloud.organizationmanager.v1.OrganizationService/Get":            {},
	"/kacho.cloud.organizationmanager.v1.OrganizationService/List":           {},
	"/kacho.cloud.organizationmanager.v1.OrganizationService/Create":         {},
	"/kacho.cloud.organizationmanager.v1.OrganizationService/Update":         {},
	"/kacho.cloud.organizationmanager.v1.OrganizationService/Delete":         {},
	"/kacho.cloud.organizationmanager.v1.OrganizationService/ListOperations": {},

	// vpc.v1 — NetworkService
	"/kacho.cloud.vpc.v1.NetworkService/Get":                {},
	"/kacho.cloud.vpc.v1.NetworkService/List":               {},
	"/kacho.cloud.vpc.v1.NetworkService/Create":             {},
	"/kacho.cloud.vpc.v1.NetworkService/Update":             {},
	"/kacho.cloud.vpc.v1.NetworkService/Delete":             {},
	"/kacho.cloud.vpc.v1.NetworkService/ListSubnets":        {},
	"/kacho.cloud.vpc.v1.NetworkService/ListSecurityGroups": {},
	"/kacho.cloud.vpc.v1.NetworkService/ListRouteTables":    {},
	"/kacho.cloud.vpc.v1.NetworkService/ListOperations":     {},
	"/kacho.cloud.vpc.v1.NetworkService/Move":               {},
	// vpc.v1 — SubnetService
	"/kacho.cloud.vpc.v1.SubnetService/Get":               {},
	"/kacho.cloud.vpc.v1.SubnetService/List":              {},
	"/kacho.cloud.vpc.v1.SubnetService/Create":            {},
	"/kacho.cloud.vpc.v1.SubnetService/Update":            {},
	"/kacho.cloud.vpc.v1.SubnetService/Delete":            {},
	"/kacho.cloud.vpc.v1.SubnetService/AddCidrBlocks":     {},
	"/kacho.cloud.vpc.v1.SubnetService/RemoveCidrBlocks":  {},
	"/kacho.cloud.vpc.v1.SubnetService/ListOperations":    {},
	"/kacho.cloud.vpc.v1.SubnetService/ListUsedAddresses": {},
	"/kacho.cloud.vpc.v1.SubnetService/Move":              {},
	"/kacho.cloud.vpc.v1.SubnetService/Relocate":          {},
	// vpc.v1 — AddressService
	"/kacho.cloud.vpc.v1.AddressService/Get":            {},
	"/kacho.cloud.vpc.v1.AddressService/GetByValue":     {},
	"/kacho.cloud.vpc.v1.AddressService/List":           {},
	"/kacho.cloud.vpc.v1.AddressService/ListBySubnet":   {},
	"/kacho.cloud.vpc.v1.AddressService/Create":         {},
	"/kacho.cloud.vpc.v1.AddressService/Update":         {},
	"/kacho.cloud.vpc.v1.AddressService/Delete":         {},
	"/kacho.cloud.vpc.v1.AddressService/ListOperations": {},
	"/kacho.cloud.vpc.v1.AddressService/Move":           {},
	// vpc.v1 — RouteTableService
	"/kacho.cloud.vpc.v1.RouteTableService/Get":            {},
	"/kacho.cloud.vpc.v1.RouteTableService/List":           {},
	"/kacho.cloud.vpc.v1.RouteTableService/Create":         {},
	"/kacho.cloud.vpc.v1.RouteTableService/Update":         {},
	"/kacho.cloud.vpc.v1.RouteTableService/Delete":         {},
	"/kacho.cloud.vpc.v1.RouteTableService/ListOperations": {},
	"/kacho.cloud.vpc.v1.RouteTableService/Move":           {},
	// vpc.v1 — SecurityGroupService
	"/kacho.cloud.vpc.v1.SecurityGroupService/Get":            {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/List":           {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Create":         {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Update":         {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/UpdateRules":    {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/UpdateRule":     {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Delete":         {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/ListOperations": {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Move":           {},
	// vpc.v1 — GatewayService (NAT egress)
	"/kacho.cloud.vpc.v1.GatewayService/Get":            {},
	"/kacho.cloud.vpc.v1.GatewayService/List":           {},
	"/kacho.cloud.vpc.v1.GatewayService/Create":         {},
	"/kacho.cloud.vpc.v1.GatewayService/Update":         {},
	"/kacho.cloud.vpc.v1.GatewayService/Delete":         {},
	"/kacho.cloud.vpc.v1.GatewayService/Move":           {},
	"/kacho.cloud.vpc.v1.GatewayService/ListOperations": {},
	// vpc.v1.privatelink — PrivateEndpointService
	"/kacho.cloud.vpc.v1.privatelink.PrivateEndpointService/Get":            {},
	"/kacho.cloud.vpc.v1.privatelink.PrivateEndpointService/List":           {},
	"/kacho.cloud.vpc.v1.privatelink.PrivateEndpointService/Create":         {},
	"/kacho.cloud.vpc.v1.privatelink.PrivateEndpointService/Update":         {},
	"/kacho.cloud.vpc.v1.privatelink.PrivateEndpointService/Delete":         {},
	"/kacho.cloud.vpc.v1.privatelink.PrivateEndpointService/ListOperations": {},

	// operation (без v1!) — OperationService (in-process OpsProxy, фан-аут по domain-prefix)
	"/kacho.cloud.operation.OperationService/Get":    {},
	"/kacho.cloud.operation.OperationService/Cancel": {},
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
