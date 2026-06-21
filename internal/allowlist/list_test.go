package allowlist_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// TestGateway_E_Exists_canonical_AllowlistBlocksAllInternalServices проверяет матрицу Internal-методов:
// ни один *InternalService-метод не должен проходить через allowlist.
// KAC-124: resourcemanager/organizationmanager Internal-методы убраны — backend упразднён.
func TestGateway_E_Exists_canonical_AllowlistBlocksAllInternalServices(t *testing.T) {
	internalMethods := []string{
		// iam (заменили rm/org)
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
		"/kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
		"/kacho.cloud.iam.v1.InternalIAMService/Check",
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
// KAC-124: resourcemanager/organizationmanager заменены на iam (Account/Project/...).
func TestGateway_D3_AllowlistPublicMethodsPresent(t *testing.T) {
	publicMethods := []string{
		// iam.v1 — Account / Project (заменили rm Cloud/Folder и org Organization)
		"/kacho.cloud.iam.v1.AccountService/Get",
		"/kacho.cloud.iam.v1.AccountService/List",
		"/kacho.cloud.iam.v1.AccountService/Create",
		"/kacho.cloud.iam.v1.AccountService/Update",
		"/kacho.cloud.iam.v1.AccountService/Delete",
		"/kacho.cloud.iam.v1.ProjectService/Get",
		"/kacho.cloud.iam.v1.ProjectService/List",
		"/kacho.cloud.iam.v1.ProjectService/Create",
		"/kacho.cloud.iam.v1.ProjectService/Update",
		"/kacho.cloud.iam.v1.ProjectService/Delete",
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

// TestGateway_D8_LoadbalancerActive (KAC-161) проверяет, что kacho-nlb активирован —
// публичные методы NetworkLoadBalancer / Listener / TargetGroup в allowlist, а
// InternalResourceLifecycleService (streaming, gRPC-direct only) — НЕ в allowlist
// (блокируется HasInternalSuffix; workspace CLAUDE.md §запрет #6).
//
// До KAC-161 loadbalancer был заморожен (предыдущий тест TestGateway_D8_LoadbalancerFrozen
// проверял отсутствие методов в allowlist). После регистрации kacho-nlb эти же методы
// должны проходить.
func TestGateway_D8_LoadbalancerActive(t *testing.T) {
	publicMethods := []string{
		// NetworkLoadBalancerService
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Update",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Start",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Stop",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Move",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/AttachTargetGroup",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/DetachTargetGroup",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/GetTargetStates",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/ListOperations",
		// ListenerService
		"/kacho.cloud.loadbalancer.v1.ListenerService/Get",
		"/kacho.cloud.loadbalancer.v1.ListenerService/List",
		"/kacho.cloud.loadbalancer.v1.ListenerService/Create",
		"/kacho.cloud.loadbalancer.v1.ListenerService/Update",
		"/kacho.cloud.loadbalancer.v1.ListenerService/Delete",
		"/kacho.cloud.loadbalancer.v1.ListenerService/ListOperations",
		// TargetGroupService
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Get",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/List",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Create",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Update",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Delete",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Move",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/AddTargets",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/RemoveTargets",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/ListOperations",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный nlb-метод %q должен быть в allowlist (KAC-161)", m)
			}
		})
	}

	internalMethods := []string{
		// streaming gRPC-direct only — никаких HTTP-аннотаций, REST не регистрируется,
		// внешний gRPC-proxy блокирует через HasInternalSuffix (запрет #6).
		"/kacho.cloud.loadbalancer.v1.InternalResourceLifecycleService/Subscribe",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("Internal nlb-метод %q НЕ должен быть в allowlist", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("метод %q должен определяться как Internal (HasInternalSuffix)", m)
			}
		})
	}
}

// TestGateway_D8b_ComputeActive проверяет, что публичные compute-RPC в allowlist,
// а Internal*-методы compute — НЕ в allowlist (и блокируются HasInternalSuffix).
func TestGateway_D8b_ComputeActive(t *testing.T) {
	publicMethods := []string{
		"/kacho.cloud.compute.v1.DiskService/Get",
		"/kacho.cloud.compute.v1.DiskService/Create",
		"/kacho.cloud.compute.v1.ImageService/List",
		"/kacho.cloud.compute.v1.SnapshotService/Create",
		"/kacho.cloud.compute.v1.InstanceService/Get",
		"/kacho.cloud.compute.v1.InstanceService/Start",
		"/kacho.cloud.compute.v1.InstanceService/AttachDisk",
		"/kacho.cloud.compute.v1.DiskTypeService/List",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный compute-метод %q должен быть в allowlist", m)
			}
		})
	}

	internalMethods := []string{
		"/kacho.cloud.compute.v1.InternalDiskTypeService/Create",
		"/kacho.cloud.compute.v1.InternalDiskTypeService/Delete",
		"/kacho.cloud.compute.v1.InternalDiskTypeService/Update",
		"/kacho.cloud.compute.v1.InternalWatchService/Watch",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("Internal compute-метод %q НЕ должен быть в allowlist", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("Internal compute-метод %q должен ловиться HasInternalSuffix", m)
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

// TestGateway_KAC105_IamActive проверяет публичные iam.v1 RPC (KAC-105 E0):
//   - все 7 публичных сервисов (Account/Project/User/ServiceAccount/Group/Role/AccessBinding)
//     зарегистрированы в allowlist;
//   - InternalIAMService.* / InternalUserService.* — НЕ в allowlist и блокируются
//     HasInternalSuffix (запрет #6 workspace CLAUDE.md);
//   - User не имеет Create/Update (создание через InternalUserService.UpsertFromIdentity).
func TestGateway_KAC105_IamActive(t *testing.T) {
	publicMethods := []string{
		// AccountService
		"/kacho.cloud.iam.v1.AccountService/Get",
		"/kacho.cloud.iam.v1.AccountService/Create",
		"/kacho.cloud.iam.v1.AccountService/Update",
		"/kacho.cloud.iam.v1.AccountService/Delete",
		// ProjectService (KAC-266: Move removed)
		"/kacho.cloud.iam.v1.ProjectService/Get",
		"/kacho.cloud.iam.v1.ProjectService/Create",
		// UserService (read+delete only)
		"/kacho.cloud.iam.v1.UserService/Get",
		"/kacho.cloud.iam.v1.UserService/List",
		"/kacho.cloud.iam.v1.UserService/Delete",
		// ServiceAccountService
		"/kacho.cloud.iam.v1.ServiceAccountService/Create",
		"/kacho.cloud.iam.v1.ServiceAccountService/Delete",
		// GroupService (+ AddMember/RemoveMember/ListMembers)
		"/kacho.cloud.iam.v1.GroupService/Create",
		"/kacho.cloud.iam.v1.GroupService/AddMember",
		"/kacho.cloud.iam.v1.GroupService/RemoveMember",
		"/kacho.cloud.iam.v1.GroupService/ListMembers",
		// RoleService
		"/kacho.cloud.iam.v1.RoleService/Create",
		"/kacho.cloud.iam.v1.RoleService/Delete",
		// AccessBindingService (+ ListByResource/ListBySubject/ListByAccount/ListSubjectPrivileges)
		"/kacho.cloud.iam.v1.AccessBindingService/Create",
		"/kacho.cloud.iam.v1.AccessBindingService/Delete",
		"/kacho.cloud.iam.v1.AccessBindingService/ListByResource",
		"/kacho.cloud.iam.v1.AccessBindingService/ListBySubject",
		"/kacho.cloud.iam.v1.AccessBindingService/ListByAccount",
		// sub-phase 1.3 — public, sync read (NOT Internal; goes on external).
		"/kacho.cloud.iam.v1.AccessBindingService/ListSubjectPrivileges",
		// sub-phase 1.5 — public, sync read (NOT Internal; goes on external).
		"/kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles",
		// epic-100 α — public, resource-scoped target mutations (async Operation)
		// + grantable-resources picker (sync read). All on external (NOT Internal;
		// ListGrantableResources returns tenant-facing id/name/type only).
		"/kacho.cloud.iam.v1.AccessBindingService/AddTargetResources",
		"/kacho.cloud.iam.v1.AccessBindingService/RemoveTargetResources",
		"/kacho.cloud.iam.v1.AccessBindingService/ListGrantableResources",
		// epic-rsab γ — public, replace bySelector-target selector (async Operation).
		// On external (NOT Internal); exempt — handler-authoritative grant-authority.
		"/kacho.cloud.iam.v1.AccessBindingService/ReplaceTargetSelector",
		// RBAC rules-model 2026 sub-phase E — public, sync reads (NOT Internal; on external).
		// ListByRole: bindings of a role; ExpandAccess: principals expansion. Both
		// cluster-scoped viewer floor (catalog), acr 2.
		"/kacho.cloud.iam.v1.AccessBindingService/ListByRole",
		"/kacho.cloud.iam.v1.AccessBindingService/ExpandAccess",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный iam-метод %q должен быть в allowlist", m)
			}
			if allowlist.HasInternalSuffix(m) {
				t.Errorf("публичный iam-метод %q не должен ловиться HasInternalSuffix", m)
			}
		})
	}

	// UserService.Create/Update — отсутствуют by-design: на E0 Users создаются
	// через InternalUserService.UpsertFromIdentity (admin via grpcurl), на E2 —
	// из OIDC-callback в api-gateway. Никакого публичного REST POST/PATCH /iam/v1/users.
	excludedUserMethods := []string{
		"/kacho.cloud.iam.v1.UserService/Create",
		"/kacho.cloud.iam.v1.UserService/Update",
	}
	for _, m := range excludedUserMethods {
		m := m
		t.Run("excluded/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("метод %q НЕ должен быть в allowlist — Users создаются через InternalUserService.UpsertFromIdentity", m)
			}
		})
	}

	// InternalIAMService / InternalUserService — internal-only (запрет #6).
	// auth-interceptor api-gateway зовёт kacho-iam:9091 напрямую через gRPC-client.
	internalMethods := []string{
		"/kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
		"/kacho.cloud.iam.v1.InternalIAMService/ListPermissions",
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
		"/kacho.cloud.iam.v1.InternalUserService/Get",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("Internal iam-метод %q НЕ должен быть в allowlist", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("Internal iam-метод %q должен ловиться HasInternalSuffix", m)
			}
		})
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
