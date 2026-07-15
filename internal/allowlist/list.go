// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package allowlist

import "strings"

// AllowedMethods — публичные RPC-пути, маршрутизируемые через api-gateway.
// Методы *InternalService.* НИКОГДА не включаются (запрет #6): их REST-проекция
// доступна только на cluster-internal listener (см. restmux/mux.go).
// Активны: iam, vpc, compute, storage, geo, loadbalancer, registry, operation.
// loadbalancer (kacho-nlb) — NetworkLoadBalancer / Listener / TargetGroup
// публичные методы добавлены ниже. registry (kacho-registry) — RegistryService
// control-plane. InternalResourceLifecycleService (streaming, gRPC-direct only)
// и InternalRegistryService (GC/stats admin, :9091) — НЕ в allowlist;
// блокируются HasInternalSuffix.
var AllowedMethods = map[string]struct{}{
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
	// vpc.v1 — AddressService
	"/kacho.cloud.vpc.v1.AddressService/Get":            {},
	"/kacho.cloud.vpc.v1.AddressService/GetByValue":     {},
	"/kacho.cloud.vpc.v1.AddressService/List":           {},
	"/kacho.cloud.vpc.v1.AddressService/ListBySubnet":   {},
	"/kacho.cloud.vpc.v1.AddressService/Create":         {},
	"/kacho.cloud.vpc.v1.AddressService/Update":         {},
	"/kacho.cloud.vpc.v1.AddressService/Delete":         {},
	"/kacho.cloud.vpc.v1.AddressService/ListOperations": {},
	// vpc.v1 — RouteTableService
	"/kacho.cloud.vpc.v1.RouteTableService/Get":            {},
	"/kacho.cloud.vpc.v1.RouteTableService/List":           {},
	"/kacho.cloud.vpc.v1.RouteTableService/Create":         {},
	"/kacho.cloud.vpc.v1.RouteTableService/Update":         {},
	"/kacho.cloud.vpc.v1.RouteTableService/Delete":         {},
	"/kacho.cloud.vpc.v1.RouteTableService/ListOperations": {},
	// vpc.v1 — SecurityGroupService
	"/kacho.cloud.vpc.v1.SecurityGroupService/Get":            {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/List":           {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Create":         {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Update":         {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/UpdateRules":    {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/UpdateRule":     {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/Delete":         {},
	"/kacho.cloud.vpc.v1.SecurityGroupService/ListOperations": {},
	// vpc.v1 — GatewayService (NAT egress)
	"/kacho.cloud.vpc.v1.GatewayService/Get":            {},
	"/kacho.cloud.vpc.v1.GatewayService/List":           {},
	"/kacho.cloud.vpc.v1.GatewayService/Create":         {},
	"/kacho.cloud.vpc.v1.GatewayService/Update":         {},
	"/kacho.cloud.vpc.v1.GatewayService/Delete":         {},
	"/kacho.cloud.vpc.v1.GatewayService/ListOperations": {},
	// compute.v1 — DiskService
	"/kacho.cloud.compute.v1.DiskService/Get":                   {},
	"/kacho.cloud.compute.v1.DiskService/List":                  {},
	"/kacho.cloud.compute.v1.DiskService/Create":                {},
	"/kacho.cloud.compute.v1.DiskService/Update":                {},
	"/kacho.cloud.compute.v1.DiskService/Delete":                {},
	"/kacho.cloud.compute.v1.DiskService/ListOperations":        {},
	"/kacho.cloud.compute.v1.DiskService/Relocate":              {},
	"/kacho.cloud.compute.v1.DiskService/ListSnapshotSchedules": {},
	"/kacho.cloud.compute.v1.DiskService/ListAccessBindings":    {},
	"/kacho.cloud.compute.v1.DiskService/SetAccessBindings":     {},
	"/kacho.cloud.compute.v1.DiskService/UpdateAccessBindings":  {},
	// compute.v1 — ImageService
	"/kacho.cloud.compute.v1.ImageService/Get":                  {},
	"/kacho.cloud.compute.v1.ImageService/GetLatestByFamily":    {},
	"/kacho.cloud.compute.v1.ImageService/List":                 {},
	"/kacho.cloud.compute.v1.ImageService/Create":               {},
	"/kacho.cloud.compute.v1.ImageService/Update":               {},
	"/kacho.cloud.compute.v1.ImageService/Delete":               {},
	"/kacho.cloud.compute.v1.ImageService/ListOperations":       {},
	"/kacho.cloud.compute.v1.ImageService/ListAccessBindings":   {},
	"/kacho.cloud.compute.v1.ImageService/SetAccessBindings":    {},
	"/kacho.cloud.compute.v1.ImageService/UpdateAccessBindings": {},
	// compute.v1 — SnapshotService
	"/kacho.cloud.compute.v1.SnapshotService/Get":                  {},
	"/kacho.cloud.compute.v1.SnapshotService/List":                 {},
	"/kacho.cloud.compute.v1.SnapshotService/Create":               {},
	"/kacho.cloud.compute.v1.SnapshotService/Update":               {},
	"/kacho.cloud.compute.v1.SnapshotService/Delete":               {},
	"/kacho.cloud.compute.v1.SnapshotService/ListOperations":       {},
	"/kacho.cloud.compute.v1.SnapshotService/ListAccessBindings":   {},
	"/kacho.cloud.compute.v1.SnapshotService/SetAccessBindings":    {},
	"/kacho.cloud.compute.v1.SnapshotService/UpdateAccessBindings": {},
	// compute.v1 — InstanceService
	"/kacho.cloud.compute.v1.InstanceService/Get":                      {},
	"/kacho.cloud.compute.v1.InstanceService/List":                     {},
	"/kacho.cloud.compute.v1.InstanceService/Create":                   {},
	"/kacho.cloud.compute.v1.InstanceService/Update":                   {},
	"/kacho.cloud.compute.v1.InstanceService/Delete":                   {},
	"/kacho.cloud.compute.v1.InstanceService/UpdateMetadata":           {},
	"/kacho.cloud.compute.v1.InstanceService/GetSerialPortOutput":      {},
	"/kacho.cloud.compute.v1.InstanceService/Stop":                     {},
	"/kacho.cloud.compute.v1.InstanceService/Start":                    {},
	"/kacho.cloud.compute.v1.InstanceService/Restart":                  {},
	"/kacho.cloud.compute.v1.InstanceService/AttachDisk":               {},
	"/kacho.cloud.compute.v1.InstanceService/DetachDisk":               {},
	"/kacho.cloud.compute.v1.InstanceService/AttachFilesystem":         {},
	"/kacho.cloud.compute.v1.InstanceService/DetachFilesystem":         {},
	"/kacho.cloud.compute.v1.InstanceService/AttachNetworkInterface":   {},
	"/kacho.cloud.compute.v1.InstanceService/DetachNetworkInterface":   {},
	"/kacho.cloud.compute.v1.InstanceService/AddOneToOneNat":           {},
	"/kacho.cloud.compute.v1.InstanceService/RemoveOneToOneNat":        {},
	"/kacho.cloud.compute.v1.InstanceService/UpdateNetworkInterface":   {},
	"/kacho.cloud.compute.v1.InstanceService/ListOperations":           {},
	"/kacho.cloud.compute.v1.InstanceService/Relocate":                 {},
	"/kacho.cloud.compute.v1.InstanceService/SimulateMaintenanceEvent": {},
	"/kacho.cloud.compute.v1.InstanceService/ListAccessBindings":       {},
	"/kacho.cloud.compute.v1.InstanceService/SetAccessBindings":        {},
	"/kacho.cloud.compute.v1.InstanceService/UpdateAccessBindings":     {},
	// compute.v1 — DiskTypeService (read-only справочник)
	"/kacho.cloud.compute.v1.DiskTypeService/Get":  {},
	"/kacho.cloud.compute.v1.DiskTypeService/List": {},
	// compute.v1 — Geography (Region/Zone) НЕ публичная поверхность compute:
	// выделена в leaf-сервис kacho-geo (см. geo.v1 ниже).

	// storage.v1 — VolumeService (kacho-storage; Volume — block-storage ресурс,
	// выделен из compute Disk). Read — sync; мутации — async Operation (sop-prefix).
	"/kacho.cloud.storage.v1.VolumeService/Get":            {},
	"/kacho.cloud.storage.v1.VolumeService/List":           {},
	"/kacho.cloud.storage.v1.VolumeService/Create":         {},
	"/kacho.cloud.storage.v1.VolumeService/Update":         {},
	"/kacho.cloud.storage.v1.VolumeService/Delete":         {},
	"/kacho.cloud.storage.v1.VolumeService/ListOperations": {},
	// storage.v1 — SnapshotService (StorageSnapshot `snp`, отдельно от compute Snapshot)
	"/kacho.cloud.storage.v1.SnapshotService/Get":    {},
	"/kacho.cloud.storage.v1.SnapshotService/List":   {},
	"/kacho.cloud.storage.v1.SnapshotService/Create": {},
	"/kacho.cloud.storage.v1.SnapshotService/Update": {},
	"/kacho.cloud.storage.v1.SnapshotService/Delete": {},
	// storage.v1 — DiskTypeService (read-only справочник; admin-CRUD — через
	// InternalDiskTypeService на :9091, НЕ в allowlist).
	"/kacho.cloud.storage.v1.DiskTypeService/Get":  {},
	"/kacho.cloud.storage.v1.DiskTypeService/List": {},
	// storage.v1 — InternalVolumeService (Attach/Detach/ListAttachments/GetInternal,
	// инфра-чувствительные placement-поля) и InternalDiskTypeService (admin CRUD) —
	// НЕ в allowlist (HasInternalSuffix блокирует автоматически; ban #6). :9091 only.

	// geo.v1 — RegionService (read-only справочник).
	// Geography живет в leaf-сервисе kacho-geo; теперь единственный owner.
	"/kacho.cloud.geo.v1.RegionService/Get":  {},
	"/kacho.cloud.geo.v1.RegionService/List": {},
	// geo.v1 — ZoneService (read-only справочник)
	"/kacho.cloud.geo.v1.ZoneService/Get":  {},
	"/kacho.cloud.geo.v1.ZoneService/List": {},
	// geo.v1 — InternalRegionService / InternalZoneService.* — НЕ в allowlist
	// (admin-CRUD на :9091; HasInternalSuffix блокирует автоматически, запрет #6).

	// iam.v1 — AccountService
	"/kacho.cloud.iam.v1.AccountService/Get":               {},
	"/kacho.cloud.iam.v1.AccountService/List":              {},
	"/kacho.cloud.iam.v1.AccountService/Create":            {},
	"/kacho.cloud.iam.v1.AccountService/Update":            {},
	"/kacho.cloud.iam.v1.AccountService/Delete":            {},
	"/kacho.cloud.iam.v1.AccountService/ListOperations":    {},
	"/kacho.cloud.iam.v1.AccountService/ListAllOperations": {}, // account-scoped module list (REST GET /iam/v1/accounts/{id}/operations:all)
	// iam.v1 — ProjectService
	"/kacho.cloud.iam.v1.ProjectService/Get":            {},
	"/kacho.cloud.iam.v1.ProjectService/List":           {},
	"/kacho.cloud.iam.v1.ProjectService/Create":         {},
	"/kacho.cloud.iam.v1.ProjectService/Update":         {},
	"/kacho.cloud.iam.v1.ProjectService/Delete":         {},
	"/kacho.cloud.iam.v1.ProjectService/ListOperations": {},
	// iam.v1 — UserService (НЕТ публичного Create — Users создаются через
	// InternalUserService.UpsertFromIdentity).
	// Update — публичная async-мутация: mutable только labels (identity-поля
	// immutable), возвращает Operation; parity с RoleService/ServiceAccountService.
	"/kacho.cloud.iam.v1.UserService/Get":            {},
	"/kacho.cloud.iam.v1.UserService/List":           {},
	"/kacho.cloud.iam.v1.UserService/Update":         {}, // public labels-only mutation (REST PATCH /iam/v1/users/{user_id}); v_update on iam_user, acr 2
	"/kacho.cloud.iam.v1.UserService/Delete":         {},
	"/kacho.cloud.iam.v1.UserService/ListOperations": {}, // per-resource ops (REST GET /iam/v1/users/{user_id}/operations)
	// iam.v1 — ServiceAccountService
	"/kacho.cloud.iam.v1.ServiceAccountService/Get":            {},
	"/kacho.cloud.iam.v1.ServiceAccountService/List":           {},
	"/kacho.cloud.iam.v1.ServiceAccountService/Create":         {},
	"/kacho.cloud.iam.v1.ServiceAccountService/Update":         {},
	"/kacho.cloud.iam.v1.ServiceAccountService/Delete":         {},
	"/kacho.cloud.iam.v1.ServiceAccountService/ListOperations": {},
	// iam.v1 — GroupService
	"/kacho.cloud.iam.v1.GroupService/Get":            {},
	"/kacho.cloud.iam.v1.GroupService/List":           {},
	"/kacho.cloud.iam.v1.GroupService/Create":         {},
	"/kacho.cloud.iam.v1.GroupService/Update":         {},
	"/kacho.cloud.iam.v1.GroupService/Delete":         {},
	"/kacho.cloud.iam.v1.GroupService/AddMember":      {},
	"/kacho.cloud.iam.v1.GroupService/RemoveMember":   {},
	"/kacho.cloud.iam.v1.GroupService/ListMembers":    {},
	"/kacho.cloud.iam.v1.GroupService/ListOperations": {},
	// iam.v1 — RoleService
	// Role.rules[].module — скалярная строка; REST Create/Update маршалят это
	// поле; отдельной allowlist-записи не требуется (новых RPC нет).
	"/kacho.cloud.iam.v1.RoleService/Get":            {},
	"/kacho.cloud.iam.v1.RoleService/List":           {},
	"/kacho.cloud.iam.v1.RoleService/Create":         {},
	"/kacho.cloud.iam.v1.RoleService/Update":         {},
	"/kacho.cloud.iam.v1.RoleService/Delete":         {},
	"/kacho.cloud.iam.v1.RoleService/ListOperations": {},
	// iam.v1 — AccessBindingService
	"/kacho.cloud.iam.v1.AccessBindingService/Get":                   {},
	"/kacho.cloud.iam.v1.AccessBindingService/Create":                {},
	"/kacho.cloud.iam.v1.AccessBindingService/Update":                {}, // public mutation (REST PATCH /iam/v1/accessBindings/{access_binding_id}); clears deletion_protection, editor relation (parity with Delete)
	"/kacho.cloud.iam.v1.AccessBindingService/Delete":                {},
	"/kacho.cloud.iam.v1.AccessBindingService/ListByScope":           {}, // public sync read (REST GET /iam/v1/accessBindings:listByScope)
	"/kacho.cloud.iam.v1.AccessBindingService/ListBySubject":         {},
	"/kacho.cloud.iam.v1.AccessBindingService/ListByAccount":         {},
	"/kacho.cloud.iam.v1.AccessBindingService/ListOperations":        {}, // per-resource ops (REST GET /iam/v1/accessBindings/{access_binding_id}/operations)
	"/kacho.cloud.iam.v1.AccessBindingService/ListSubjectPrivileges": {}, // public sync read
	"/kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles":   {}, // public sync read (REST GET /iam/v1/accessBindings:listAssignableRoles)
	"/kacho.cloud.iam.v1.AccessBindingService/ListByRole":            {}, // public sync read (REST GET /iam/v1/accessBindings:listByRole)
	"/kacho.cloud.iam.v1.AccessBindingService/ExpandAccess":          {}, // public sync read (REST GET /iam/v1/accessBindings:expandAccess)
	// iam.v1 — PermissionCatalogService
	// Public, sync read (REST GET /iam/v1/permissionCatalog): authenticated-floor
	// read (<exempt> в каталоге — no FGA Check), чтобы UI собирал role/permission
	// palette без Internal* RPC. MUST be reachable on the external listener (else
	// 404/NotFound при gRPC-маршрутизации).
	"/kacho.cloud.iam.v1.PermissionCatalogService/ListPermissionCatalog": {},
	// iam.v1 — InternalIAMService / InternalUserService.* — НЕ в allowlist
	// (HasInternalSuffix блокирует автоматически; запрет #6). gRPC-direct only.

	// loadbalancer.v1 — NetworkLoadBalancerService (kacho-nlb)
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get":               {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List":              {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create":            {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Update":            {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete":            {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Start":             {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Stop":              {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Move":              {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/AttachTargetGroup": {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/DetachTargetGroup": {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/GetTargetStates":   {},
	"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/ListOperations":    {},
	// loadbalancer.v1 — ListenerService (first-class FGA object)
	"/kacho.cloud.loadbalancer.v1.ListenerService/Get":            {},
	"/kacho.cloud.loadbalancer.v1.ListenerService/List":           {},
	"/kacho.cloud.loadbalancer.v1.ListenerService/Create":         {},
	"/kacho.cloud.loadbalancer.v1.ListenerService/Update":         {},
	"/kacho.cloud.loadbalancer.v1.ListenerService/Delete":         {},
	"/kacho.cloud.loadbalancer.v1.ListenerService/ListOperations": {},
	// loadbalancer.v1 — TargetGroupService
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Get":            {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/List":           {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Create":         {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Update":         {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Delete":         {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/Move":           {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/AddTargets":     {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/RemoveTargets":  {},
	"/kacho.cloud.loadbalancer.v1.TargetGroupService/ListOperations": {},
	// loadbalancer.v1 — InternalResourceLifecycleService.* — НЕ в allowlist
	// (HasInternalSuffix блокирует автоматически; запрет #6). gRPC-direct only;
	// streaming Subscribe не имеет HTTP-аннотаций, REST не регистрируется.

	// registry.v1 — RegistryService (kacho-registry, control-plane реестра)
	// Read — sync; мутации (Create/Update/Delete/DeleteTag) — async Operation.
	// List/ListRepositories/ListTags авторизуются listauthz внутри сервиса
	// (proto <exempt>), но в allowlist они присутствуют как публичные gRPC-пути.
	// InternalRegistryService.* (GC/stats admin, :9091) — НЕ в allowlist
	// (HasInternalSuffix блокирует автоматически; ban #6). Data-plane OCI v2 —
	// отдельная поверхность, не через api-gateway.
	"/kacho.cloud.registry.v1.RegistryService/Get":              {},
	"/kacho.cloud.registry.v1.RegistryService/List":             {},
	"/kacho.cloud.registry.v1.RegistryService/Create":           {},
	"/kacho.cloud.registry.v1.RegistryService/Update":           {},
	"/kacho.cloud.registry.v1.RegistryService/Delete":           {},
	"/kacho.cloud.registry.v1.RegistryService/ListRepositories": {},
	"/kacho.cloud.registry.v1.RegistryService/ListTags":         {},
	"/kacho.cloud.registry.v1.RegistryService/DeleteTag":        {},
	"/kacho.cloud.registry.v1.RegistryService/ListOperations":   {},
	// registry.v1 — Repository config-overlay (RG-1). Публичные RPC на том же
	// RegistryService: sync-чтение GetRepository/ListReferrers + async-мутации
	// CreateRepository/UpdateRepository/DeleteRepository/RenameRepository. Все
	// шесть — gateway `<exempt>` (per-repo Check + existence-hiding в handler'е:
	// COMPOSITE-объект registry_repository:<reg>/<repo> не выразим gateway
	// scope_extractor'ом; deny → uniform NOT_FOUND, иначе existence-oracle).
	"/kacho.cloud.registry.v1.RegistryService/GetRepository":    {},
	"/kacho.cloud.registry.v1.RegistryService/ListReferrers":    {},
	"/kacho.cloud.registry.v1.RegistryService/CreateRepository": {},
	"/kacho.cloud.registry.v1.RegistryService/UpdateRepository": {},
	"/kacho.cloud.registry.v1.RegistryService/DeleteRepository": {},
	"/kacho.cloud.registry.v1.RegistryService/RenameRepository": {},

	// operation (без v1!) — OperationService (in-process OpsProxy, фан-аут по domain-prefix)
	"/kacho.cloud.operation.OperationService/Get":    {},
	"/kacho.cloud.operation.OperationService/Cancel": {},
}

// IsAllowed проверяет, что метод находится в списке разрешенных публичных RPC.
func IsAllowed(methodPath string) bool {
	_, ok := AllowedMethods[methodPath]
	return ok
}

// HasInternalSuffix — эшелонированная защита: любой метод, чей gRPC-service
// помечен как internal, блокируется автоматически, даже если он случайно попал
// в AllowedMethods.
//
// Покрывает обе принятые в kacho-proto конвенции именования internal-сервисов:
//   - суффикс  "<Xxx>InternalService" (resource-manager: FolderInternalService);
//   - префикс  "Internal<Xxx>Service" (vpc: InternalAddressPoolService,
//     InternalNetworkService; compute: InternalDiskTypeService,
//     InternalWatchService; geo: InternalRegionService, InternalZoneService).
//
// Путь имеет вид "/kacho.cloud.<domain>.v1.<Service>/<Method>"; проверяем сегмент
// между последней "." и "/".
func HasInternalSuffix(methodPath string) bool {
	if strings.Contains(methodPath, "InternalService") {
		return true
	}
	// methodPath = "/kacho.cloud.<domain>.v1.<Service>/<Method>"
	p := strings.TrimPrefix(methodPath, "/")
	slash := strings.IndexByte(p, '/')
	if slash < 1 {
		return false
	}
	pkgService := p[:slash] // "kacho.cloud.<domain>.v1.<Service>"
	dot := strings.LastIndexByte(pkgService, '.')
	if dot < 0 {
		return false
	}
	service := pkgService[dot+1:]
	return strings.HasPrefix(service, "Internal") && strings.HasSuffix(service, "Service")
}
