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
		"/kacho.cloud.resourcemanager.v1.CloudInternalService/Exists",
		"/kacho.cloud.resourcemanager.v1.CloudInternalService/HasDependents",
		"/kacho.cloud.resourcemanager.v1.FolderInternalService/Exists",
		"/kacho.cloud.resourcemanager.v1.FolderInternalService/HasDependents",
		// organizationmanager
		"/kacho.cloud.organizationmanager.v1.OrganizationInternalService/Exists",
		"/kacho.cloud.organizationmanager.v1.OrganizationInternalService/HasDependents",
		// vpc
		"/kacho.cloud.vpc.v1.NetworkInternalService/Exists",
		"/kacho.cloud.vpc.v1.NetworkInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.SubnetInternalService/Exists",
		"/kacho.cloud.vpc.v1.SubnetInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.RouteTableInternalService/Exists",
		"/kacho.cloud.vpc.v1.RouteTableInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.AddressInternalService/Exists",
		"/kacho.cloud.vpc.v1.AddressInternalService/HasDependents",
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
		// resourcemanager.v1 — Cloud/Folder
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
		// organizationmanager.v1
		"/kacho.cloud.organizationmanager.v1.OrganizationService/Get",
		"/kacho.cloud.organizationmanager.v1.OrganizationService/List",
		"/kacho.cloud.organizationmanager.v1.OrganizationService/Create",
		"/kacho.cloud.organizationmanager.v1.OrganizationService/Update",
		"/kacho.cloud.organizationmanager.v1.OrganizationService/Delete",
		// vpc.v1
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
		"/kacho.cloud.vpc.v1.AddressService/Get",
		"/kacho.cloud.vpc.v1.AddressService/List",
		"/kacho.cloud.vpc.v1.AddressService/Create",
		"/kacho.cloud.vpc.v1.AddressService/Update",
		"/kacho.cloud.vpc.v1.AddressService/Delete",
		"/kacho.cloud.vpc.v1.RouteTableService/Get",
		"/kacho.cloud.vpc.v1.RouteTableService/List",
		"/kacho.cloud.vpc.v1.RouteTableService/Create",
		"/kacho.cloud.vpc.v1.RouteTableService/Update",
		"/kacho.cloud.vpc.v1.RouteTableService/Delete",
		// operation (без v1) — только Get и Cancel
		"/kacho.cloud.operation.OperationService/Get",
		"/kacho.cloud.operation.OperationService/Cancel",
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

// TestGateway_D6_OperationServiceAllowed проверяет OperationService методы (verbatim YC: Get+Cancel, без List).
func TestGateway_D6_OperationServiceAllowed(t *testing.T) {
	allowed := []string{
		"/kacho.cloud.operation.OperationService/Get",
		"/kacho.cloud.operation.OperationService/Cancel",
	}
	for _, m := range allowed {
		m := m
		t.Run(m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("метод %q должен быть в allowlist", m)
			}
		})
	}
}

// TestGateway_D6_OperationListNotAllowed проверяет, что List отсутствует (YC такого нет).
func TestGateway_D6_OperationListNotAllowed(t *testing.T) {
	const m = "/kacho.cloud.operation.OperationService/List"
	if allowlist.IsAllowed(m) {
		t.Errorf("метод %q НЕ должен быть в allowlist (YC OperationService не имеет List)", m)
	}
}

// TestGateway_D7_OldUpsertWatchBlocked проверяет, что старые методы 0.x удалены из allowlist.
func TestGateway_D7_OldUpsertWatchBlocked(t *testing.T) {
	oldMethods := []string{
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Upsert",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Watch",
		"/kacho.cloud.vpc.v1.NetworkService/Upsert",
		"/kacho.cloud.vpc.v1.NetworkService/Watch",
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

// TestGateway_D8_ComputeLoadbalancerFrozen проверяет, что compute и loadbalancer заморожены.
func TestGateway_D8_ComputeLoadbalancerFrozen(t *testing.T) {
	frozenMethods := []string{
		"/kacho.cloud.compute.v1.InstanceService/Get",
		"/kacho.cloud.compute.v1.InstanceService/Create",
		"/kacho.cloud.compute.v1.DiskService/Get",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/List",
	}
	for _, m := range frozenMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("замороженный метод %q НЕ должен быть в allowlist", m)
			}
		})
	}
}

// TestGateway_D9_OldOperationV1Blocked проверяет, что старые пути operation/v1 заблокированы.
func TestGateway_D9_OldOperationV1Blocked(t *testing.T) {
	oldMethods := []string{
		"/kacho.cloud.operation.v1.OperationService/Get",
		"/kacho.cloud.operation.v1.OperationService/List",
		"/kacho.cloud.operation.v1.OperationService/Cancel",
	}
	for _, m := range oldMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("старый путь %q НЕ должен быть в allowlist", m)
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

// TestGateway_D10_OldRMOrganizationServiceBlocked проверяет, что старый
// resourcemanager.v1.OrganizationService заблокирован (перенесён в organizationmanager.v1).
func TestGateway_D10_OldRMOrganizationServiceBlocked(t *testing.T) {
	oldMethods := []string{
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Get",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/List",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Create",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Update",
		"/kacho.cloud.resourcemanager.v1.OrganizationService/Delete",
	}
	for _, m := range oldMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("путь %q НЕ должен быть в allowlist — OrganizationService перенесён в organizationmanager.v1", m)
			}
		})
	}
}
