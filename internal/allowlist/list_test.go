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
		// compute
		"/kacho.cloud.compute.v1.InstanceInternalService/Exists",
		"/kacho.cloud.compute.v1.InstanceInternalService/HasDependents",
		"/kacho.cloud.compute.v1.DiskInternalService/Exists",
		"/kacho.cloud.compute.v1.DiskInternalService/HasDependents",
		// loadbalancer
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerInternalService/Exists",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerInternalService/HasDependents",
		"/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/Exists",
		"/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/HasDependents",
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

// TestGateway_D3_AllowlistPublicMethodsPresent проверяет, что все публичные методы 1.0 API
// присутствуют в allowlist (положительный сценарий).
func TestGateway_D3_AllowlistPublicMethodsPresent(t *testing.T) {
	publicMethods := []string{
		// resource-manager — Get/List/Create/Update/Delete
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Get",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/List",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Create",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Update",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Delete",
		"/kacho.cloud.resourcemanager.v1.CloudService/Get",
		"/kacho.cloud.resourcemanager.v1.CloudService/List",
		"/kacho.cloud.resourcemanager.v1.CloudService/Create",
		"/kacho.cloud.resourcemanager.v1.CloudService/Update",
		"/kacho.cloud.resourcemanager.v1.CloudService/Delete",
		"/kacho.cloud.resourcemanager.v1.FolderService/Get",
		"/kacho.cloud.resourcemanager.v1.FolderService/List",
		"/kacho.cloud.resourcemanager.v1.FolderService/Create",
		"/kacho.cloud.resourcemanager.v1.FolderService/Update",
		"/kacho.cloud.resourcemanager.v1.FolderService/Delete",
		// vpc
		"/kacho.cloud.vpc.v1.NetworkService/Get",
		"/kacho.cloud.vpc.v1.NetworkService/List",
		"/kacho.cloud.vpc.v1.NetworkService/Create",
		"/kacho.cloud.vpc.v1.NetworkService/Update",
		"/kacho.cloud.vpc.v1.NetworkService/Delete",
		"/kacho.cloud.vpc.v1.SubnetService/Get",
		"/kacho.cloud.vpc.v1.SubnetService/List",
		"/kacho.cloud.vpc.v1.SubnetService/Create",
		"/kacho.cloud.vpc.v1.SubnetService/Update",
		"/kacho.cloud.vpc.v1.SubnetService/Delete",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Get",
		"/kacho.cloud.vpc.v1.SecurityGroupService/List",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Create",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Update",
		"/kacho.cloud.vpc.v1.SecurityGroupService/Delete",
		"/kacho.cloud.vpc.v1.RouteTableService/Get",
		"/kacho.cloud.vpc.v1.RouteTableService/List",
		"/kacho.cloud.vpc.v1.RouteTableService/Create",
		"/kacho.cloud.vpc.v1.RouteTableService/Update",
		"/kacho.cloud.vpc.v1.RouteTableService/Delete",
		"/kacho.cloud.vpc.v1.AddressService/Get",
		"/kacho.cloud.vpc.v1.AddressService/List",
		"/kacho.cloud.vpc.v1.AddressService/Create",
		"/kacho.cloud.vpc.v1.AddressService/Update",
		"/kacho.cloud.vpc.v1.AddressService/Delete",
		// compute — InstanceService: Get/List/Create/Update/Delete + Start/Stop/Restart
		"/kacho.cloud.compute.v1.InstanceService/Get",
		"/kacho.cloud.compute.v1.InstanceService/List",
		"/kacho.cloud.compute.v1.InstanceService/Create",
		"/kacho.cloud.compute.v1.InstanceService/Update",
		"/kacho.cloud.compute.v1.InstanceService/Delete",
		"/kacho.cloud.compute.v1.InstanceService/Start",
		"/kacho.cloud.compute.v1.InstanceService/Stop",
		"/kacho.cloud.compute.v1.InstanceService/Restart",
		// compute — DiskService
		"/kacho.cloud.compute.v1.DiskService/Get",
		"/kacho.cloud.compute.v1.DiskService/List",
		"/kacho.cloud.compute.v1.DiskService/Create",
		"/kacho.cloud.compute.v1.DiskService/Update",
		"/kacho.cloud.compute.v1.DiskService/Delete",
		// compute — ImageService (только Get/List)
		"/kacho.cloud.compute.v1.ImageService/Get",
		"/kacho.cloud.compute.v1.ImageService/List",
		// compute — SnapshotService
		"/kacho.cloud.compute.v1.SnapshotService/Get",
		"/kacho.cloud.compute.v1.SnapshotService/List",
		"/kacho.cloud.compute.v1.SnapshotService/Create",
		"/kacho.cloud.compute.v1.SnapshotService/Update",
		"/kacho.cloud.compute.v1.SnapshotService/Delete",
		// loadbalancer
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Update",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Get",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/List",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Create",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Update",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Delete",
		// operations
		"/kacho.cloud.operation.v1.OperationService/Get",
		"/kacho.cloud.operation.v1.OperationService/List",
		"/kacho.cloud.operation.v1.OperationService/Cancel",
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

// TestGateway_D5_StartStopRestartAllowed проверяет, что новые lifecycle-методы Instance присутствуют.
func TestGateway_D5_StartStopRestartAllowed(t *testing.T) {
	methods := []string{
		"/kacho.cloud.compute.v1.InstanceService/Start",
		"/kacho.cloud.compute.v1.InstanceService/Stop",
		"/kacho.cloud.compute.v1.InstanceService/Restart",
	}
	for _, m := range methods {
		m := m
		t.Run(m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("%s должен быть в allowlist", m)
			}
		})
	}
}

// TestGateway_D6_OperationServiceAllowed проверяет OperationService методы.
func TestGateway_D6_OperationServiceAllowed(t *testing.T) {
	methods := []string{
		"/kacho.cloud.operation.v1.OperationService/Get",
		"/kacho.cloud.operation.v1.OperationService/List",
		"/kacho.cloud.operation.v1.OperationService/Cancel",
	}
	for _, m := range methods {
		m := m
		t.Run(m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("метод %q должен быть в allowlist", m)
			}
		})
	}
}

// TestGateway_D7_OldUpsertWatchBlocked проверяет, что старые методы 0.x удалены из allowlist.
func TestGateway_D7_OldUpsertWatchBlocked(t *testing.T) {
	oldMethods := []string{
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Upsert",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Watch",
		"/kacho.cloud.vpc.v1.NetworkService/Upsert",
		"/kacho.cloud.vpc.v1.NetworkService/Watch",
		"/kacho.cloud.compute.v1.InstanceService/Upsert",
		"/kacho.cloud.compute.v1.InstanceService/Watch",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Upsert",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Watch",
	}
	for _, m := range oldMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("устаревший метод %q НЕ должен быть в allowlist 1.0", m)
			}
		})
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

// TestGateway_E9_TargetGroupRemoveTargetBlocked проверяет сценарий E9.
func TestGateway_E9_TargetGroupRemoveTargetBlocked(t *testing.T) {
	const method = "/kacho.cloud.loadbalancer.v1.TargetGroupInternalService/RemoveTarget"
	if allowlist.IsAllowed(method) {
		t.Error("TargetGroupInternalService/RemoveTarget не должен быть в allowlist")
	}
}
