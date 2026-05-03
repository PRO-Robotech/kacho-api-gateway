package allowlist_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// TestGateway_E_Exists_canonical_AllowlistBlocksAllInternalServices проверяет матрицу Internal-методов:
// ни один *InternalService-метод не должен проходить через allowlist.
func TestGateway_E_Exists_canonical_AllowlistBlocksAllInternalServices(t *testing.T) {
	internalMethods := []string{
		// resource-manager
		"/kacho.cloud.resourcemanager.v1.OrganizationInternalService/Exists",
		"/kacho.cloud.resourcemanager.v1.OrganizationInternalService/HasDependents",
		"/kacho.cloud.resourcemanager.v1.CloudInternalService/Exists",
		"/kacho.cloud.resourcemanager.v1.CloudInternalService/HasDependents",
		"/kacho.cloud.resourcemanager.v1.FolderInternalService/Exists",
		"/kacho.cloud.resourcemanager.v1.FolderInternalService/HasDependents",
		// vpc
		"/kacho.cloud.vpc.v1.NetworkInternalService/Exists",
		"/kacho.cloud.vpc.v1.NetworkInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.SubnetInternalService/Exists",
		"/kacho.cloud.vpc.v1.SubnetInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.SecurityGroupInternalService/Exists",
		"/kacho.cloud.vpc.v1.SecurityGroupInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.RouteTableInternalService/Exists",
		"/kacho.cloud.vpc.v1.RouteTableInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.AddressInternalService/Exists",
		"/kacho.cloud.vpc.v1.AddressInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.AddressInternalService/UpdateStatus",
		// compute
		"/kacho.cloud.compute.v1.InstanceInternalService/Exists",
		"/kacho.cloud.compute.v1.InstanceInternalService/HasDependents",
		"/kacho.cloud.compute.v1.InstanceInternalService/UpdateStatus",
		"/kacho.cloud.compute.v1.DiskInternalService/Exists",
		"/kacho.cloud.compute.v1.DiskInternalService/HasDependents",
		"/kacho.cloud.compute.v1.DiskInternalService/UpdateStatus",
		// loadbalancer
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerInternalService/Exists",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerInternalService/HasDependents",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerInternalService/UpdateStatus",
		"/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/Exists",
		"/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/HasDependents",
		"/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/UpdateStatus",
		"/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/RemoveTarget",
	}

	for _, m := range internalMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("метод %q НЕ должен быть в allowlist", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("метод %q должен определяться как Internal (HasInternalSuffix)", m)
			}
		})
	}
}

// TestGateway_D3_AllowlistPublicMethodsPresent проверяет, что все публичные методы
// присутствуют в allowlist (положительный сценарий).
func TestGateway_D3_AllowlistPublicMethodsPresent(t *testing.T) {
	publicMethods := []string{
		// resource-manager
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Upsert",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Delete",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/List",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Watch",
		"/kacho.cloud.resourcemanager.v1.CloudService/Upsert",
		"/kacho.cloud.resourcemanager.v1.CloudService/Delete",
		"/kacho.cloud.resourcemanager.v1.CloudService/List",
		"/kacho.cloud.resourcemanager.v1.CloudService/Watch",
		"/kacho.cloud.resourcemanager.v1.FolderService/Upsert",
		"/kacho.cloud.resourcemanager.v1.FolderService/Delete",
		"/kacho.cloud.resourcemanager.v1.FolderService/List",
		"/kacho.cloud.resourcemanager.v1.FolderService/Watch",
		// vpc
		"/kacho.cloud.vpc.v1.NetworkService/Upsert",
		"/kacho.cloud.vpc.v1.NetworkService/Delete",
		"/kacho.cloud.vpc.v1.NetworkService/List",
		"/kacho.cloud.vpc.v1.NetworkService/Watch",
		"/kacho.cloud.vpc.v1.SubnetService/Upsert",
		"/kacho.cloud.vpc.v1.SubnetService/Delete",
		"/kacho.cloud.vpc.v1.SubnetService/List",
		"/kacho.cloud.vpc.v1.SubnetService/Watch",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Upsert",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Delete",
		"/kacho.cloud.vpc.v1.SecurityGroupService/List",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Watch",
		"/kacho.cloud.vpc.v1.RouteTableService/Upsert",
		"/kacho.cloud.vpc.v1.RouteTableService/Delete",
		"/kacho.cloud.vpc.v1.RouteTableService/List",
		"/kacho.cloud.vpc.v1.RouteTableService/Watch",
		"/kacho.cloud.vpc.v1.AddressService/Upsert",
		"/kacho.cloud.vpc.v1.AddressService/Delete",
		"/kacho.cloud.vpc.v1.AddressService/List",
		"/kacho.cloud.vpc.v1.AddressService/Watch",
		// compute
		"/kacho.cloud.compute.v1.InstanceService/Upsert",
		"/kacho.cloud.compute.v1.InstanceService/Delete",
		"/kacho.cloud.compute.v1.InstanceService/List",
		"/kacho.cloud.compute.v1.InstanceService/Watch",
		"/kacho.cloud.compute.v1.InstanceService/Restart",
		"/kacho.cloud.compute.v1.DiskService/Upsert",
		"/kacho.cloud.compute.v1.DiskService/Delete",
		"/kacho.cloud.compute.v1.DiskService/List",
		"/kacho.cloud.compute.v1.DiskService/Watch",
		"/kacho.cloud.compute.v1.ImageService/Get",
		"/kacho.cloud.compute.v1.ImageService/List",
		"/kacho.cloud.compute.v1.SnapshotService/Upsert",
		"/kacho.cloud.compute.v1.SnapshotService/Delete",
		"/kacho.cloud.compute.v1.SnapshotService/List",
		"/kacho.cloud.compute.v1.SnapshotService/Watch",
		// loadbalancer
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Upsert",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Watch",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Upsert",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Delete",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/List",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Watch",
	}

	for _, m := range publicMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный метод %q должен быть в allowlist", m)
			}
			if allowlist.HasInternalSuffix(m) {
				t.Errorf("публичный метод %q не должен определяться как Internal", m)
			}
		})
	}
}

// TestGateway_D5_RestartAllowed проверяет сценарий D5: InstanceService/Restart в allowlist.
func TestGateway_D5_RestartAllowed(t *testing.T) {
	const method = "/kacho.cloud.compute.v1.InstanceService/Restart"
	if !allowlist.IsAllowed(method) {
		t.Errorf("Restart должен быть в allowlist")
	}
}

// TestGateway_E1_FolderInternalExistsBlocked проверяет сценарий E1.
func TestGateway_E1_FolderInternalExistsBlocked(t *testing.T) {
	const method = "/kacho.cloud.resourcemanager.v1.FolderInternalService/Exists"
	if allowlist.IsAllowed(method) {
		t.Error("FolderInternalService/Exists не должен быть в allowlist")
	}
	if !allowlist.HasInternalSuffix(method) {
		t.Error("FolderInternalService/Exists должен определяться как Internal")
	}
}

// TestGateway_E6_InstanceUpdateStatusBlocked проверяет сценарий E6.
func TestGateway_E6_InstanceUpdateStatusBlocked(t *testing.T) {
	const method = "/kacho.cloud.compute.v1.InstanceInternalService/UpdateStatus"
	if allowlist.IsAllowed(method) {
		t.Error("InstanceInternalService/UpdateStatus не должен быть в allowlist")
	}
}

// TestGateway_E9_TargetGroupRemoveTargetBlocked проверяет сценарий E9.
func TestGateway_E9_TargetGroupRemoveTargetBlocked(t *testing.T) {
	const method = "/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/RemoveTarget"
	if allowlist.IsAllowed(method) {
		t.Error("TargetGroupInternalService/RemoveTarget не должен быть в allowlist")
	}
}
