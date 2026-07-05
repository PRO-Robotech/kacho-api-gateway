// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rest_router_test.go — REST<->gRPC route resolution.
package middleware

import (
	"strings"
	"testing"
)

func TestRestRouter_Resolve_KnownRoutes(t *testing.T) {
	r := NewRestRouter()
	cases := []struct {
		method, path, wantFQN string
	}{
		// collection POST (Create)
		{"POST", "/iam/v1/accounts", "kacho.cloud.iam.v1.AccountService/Create"},
		// item GET with {id} placeholder
		{"GET", "/iam/v1/accounts/acc0000000000000001", "kacho.cloud.iam.v1.AccountService/Get"},
		// item PATCH (Update)
		{"PATCH", "/iam/v1/projects/prj0000000000000001", "kacho.cloud.iam.v1.ProjectService/Update"},
		// item DELETE
		{"DELETE", "/iam/v1/accounts/acc0000000000000001", "kacho.cloud.iam.v1.AccountService/Delete"},
		// suffix-action `:verb`
		{"POST", "/iam/v1/users:invite", "kacho.cloud.iam.v1.UserService/Invite"},
		// UserService.Update — public async mutation (User labels-only); PATCH on the
		// item path `/iam/v1/users/{user_id}`, same template as GET/DELETE. Must resolve
		// so the catalog gate (v_update on iam_user, acr 2 — parity with Role/SA Update)
		// fires instead of "no entry for method".
		{"PATCH", "/iam/v1/users/usr0000000000000001", "kacho.cloud.iam.v1.UserService/Update"},
		// AccessBindingService.ListSubjectPrivileges — public read, GET suffix-action;
		// must resolve so the catalog gate (viewer floor) fires.
		{"GET", "/iam/v1/accessBindings:listSubjectPrivileges", "kacho.cloud.iam.v1.AccessBindingService/ListSubjectPrivileges"},
		// AccessBindingService.ListAssignableRoles — public read, GET suffix-action;
		// must resolve so the scope-polymorphic catalog gate (viewer floor + dynamic
		// object_type) fires.
		{"GET", "/iam/v1/accessBindings:listAssignableRoles", "kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles"},
		// ListByScope — public read, GET suffix-action on the collection; must
		// resolve so the scope-polymorphic catalog gate (viewer floor + dynamic
		// object_type from resource_type) fires.
		{"GET", "/iam/v1/accessBindings:listByScope", "kacho.cloud.iam.v1.AccessBindingService/ListByScope"},
		// ListByRole + ExpandAccess — public reads, GET suffix-actions on the
		// collection; must resolve so the cluster-scoped catalog gate (viewer floor,
		// acr 2) fires.
		{"GET", "/iam/v1/accessBindings:listByRole", "kacho.cloud.iam.v1.AccessBindingService/ListByRole"},
		{"GET", "/iam/v1/accessBindings:expandAccess", "kacho.cloud.iam.v1.AccessBindingService/ExpandAccess"},
		// AccessBindingService.Update — public PATCH on the item path (clears
		// deletion_protection); must resolve so the catalog gate (editor on
		// iam_access_binding, acr 2 — parity with Delete) fires instead of "no entry
		// for method". Same item template as GET/DELETE.
		{"PATCH", "/iam/v1/accessBindings/abd0000000000000001", "kacho.cloud.iam.v1.AccessBindingService/Update"},
		// WhoAmI (GET /iam/v1/me) must resolve so the <exempt> bypass fires;
		// otherwise path->FQN fails → 403 "catalog: no entry for method" breaks the
		// UI permission bootstrap.
		{"GET", "/iam/v1/me", "kacho.cloud.iam.v1.AuthorizeService/WhoAmI"},
		// PermissionCatalogService.ListPermissionCatalog — public read
		// (GET /iam/v1/permissionCatalog) on the EXTERNAL listener; must resolve so
		// the <exempt> catalog bypass fires. The internal-permissions route
		// (GET /iam/v1/internal/iam/permissions) must NOT resolve anymore
		// (see TestRestRouter_TombstonedRoutesGone).
		{"GET", "/iam/v1/permissionCatalog", "kacho.cloud.iam.v1.PermissionCatalogService/ListPermissionCatalog"},
		// list with query string is stripped before matching
		{"GET", "/iam/v1/projects?accountId=acc1", "kacho.cloud.iam.v1.ProjectService/List"},
		// vpc resource
		{"GET", "/vpc/v1/networks/enp0000000000000001", "kacho.cloud.vpc.v1.NetworkService/Get"},
		// InternalAddressPoolService CIDR-block suffix-actions (internal mux).
		{"POST", "/vpc/v1/addressPools/apl0000000000000001:addCidrBlocks", "kacho.cloud.vpc.v1.InternalAddressPoolService/AddCidrBlocks"},
		{"POST", "/vpc/v1/addressPools/apl0000000000000001:removeCidrBlocks", "kacho.cloud.vpc.v1.InternalAddressPoolService/RemoveCidrBlocks"},
	}
	for _, c := range cases {
		fqn, ok := r.Resolve(c.method, c.path)
		if !ok {
			t.Errorf("Resolve(%s %s): no match, want %s", c.method, c.path, c.wantFQN)
			continue
		}
		if fqn != c.wantFQN {
			t.Errorf("Resolve(%s %s) = %s, want %s", c.method, c.path, fqn, c.wantFQN)
		}
	}
}

func TestRestRouter_Resolve_UnknownRoute(t *testing.T) {
	r := NewRestRouter()
	if fqn, ok := r.Resolve("GET", "/no/such/route"); ok {
		t.Errorf("Resolve(unknown) = %s, want no match", fqn)
	}
	// Wrong method for an existing path.
	if _, ok := r.Resolve("DELETE", "/iam/v1/accounts"); ok {
		t.Errorf("Resolve(DELETE /iam/v1/accounts): want no match (collection has no DELETE)")
	}
}

// TestRestRouter_TombstonedRoutesGone — the two tombstoned RPCs must no longer
// resolve to a route:
//   - InternalIAMService.ListPermissions (GET /iam/v1/internal/iam/permissions)
//     replaced by the public PermissionCatalogService.ListPermissionCatalog;
//   - InternalAuthorizeService.RunRegoTest (had no REST gateway binding — never
//     in this table — guarded here so a future re-add does not slip through).
//
// If the route table is not regenerated after the tombstones, the stale
// /iam/v1/internal/iam/permissions entry keeps resolving → this test fails,
// signalling the sync was skipped.
func TestRestRouter_TombstonedRoutesGone(t *testing.T) {
	r := NewRestRouter()
	if fqn, ok := r.Resolve("GET", "/iam/v1/internal/iam/permissions"); ok {
		t.Errorf("Resolve(GET /iam/v1/internal/iam/permissions) = %s, want no match — ListPermissions tombstoned in proto-G", fqn)
	}
	// No route may still map to either tombstoned FQN.
	for _, rt := range generatedRestRoutes {
		switch rt.FQN {
		case "kacho.cloud.iam.v1.InternalIAMService/ListPermissions",
			"kacho.cloud.iam.v1.InternalAuthorizeService/RunRegoTest":
			t.Errorf("route table still contains tombstoned FQN %q (template %q)", rt.FQN, rt.Template)
		}
	}
}

func TestRestRouter_PathTemplates(t *testing.T) {
	r := NewRestRouter()
	tmpls := r.PathTemplates()
	if got := tmpls["kacho.cloud.iam.v1.AccountService/Get"]; got != "/iam/v1/accounts/{account_id}" {
		t.Errorf("PathTemplates[AccountService/Get] = %q, want /iam/v1/accounts/{account_id}", got)
	}
}

// TestRestRouter_Resolve_RegeneratedCoverage — guard against the route-table
// drifting behind the proto tree. When a domain adds a REST-exposed RPC but the
// route table is not regenerated, the path fails to resolve → the authz gate
// returns "catalog: no entry for method" (403) even though the method is
// legitimate. These routes existed only in proto until the table was
// regenerated from `google.api.http`; asserting them here fails loudly if a
// future edit hand-maintains the table and re-introduces the lag.
func TestRestRouter_Resolve_RegeneratedCoverage(t *testing.T) {
	r := NewRestRouter()
	cases := []struct {
		method, path, wantFQN string
	}{
		// Compute InstanceGroup — whole service (own proto sub-package
		// `kacho.cloud.compute.v1.instancegroup`) was absent from the table.
		{"POST", "/compute/v1/instanceGroups", "kacho.cloud.compute.v1.instancegroup.InstanceGroupService/Create"},
		{"POST", "/compute/v1/instanceGroups/igr0000000000000001:start", "kacho.cloud.compute.v1.instancegroup.InstanceGroupService/Start"},
		{"POST", "/compute/v1/instanceGroups/igr0000000000000001:rollingRestart", "kacho.cloud.compute.v1.instancegroup.InstanceGroupService/RollingRestart"},
		// VPC RouteTable mutation verbs (kebab-case suffix-actions).
		{"POST", "/vpc/v1/routeTables/rtb0000000000000001:add-routes", "kacho.cloud.vpc.v1.RouteTableService/AddRoutes"},
		{"POST", "/vpc/v1/routeTables/rtb0000000000000001:remove-routes", "kacho.cloud.vpc.v1.RouteTableService/RemoveRoutes"},
		{"POST", "/vpc/v1/routeTables/rtb0000000000000001:update-route", "kacho.cloud.vpc.v1.RouteTableService/UpdateRoute"},
		// VPC InternalNetworkService read (internal-only `:internal` action).
		{"GET", "/vpc/v1/networks/enp0000000000000001:internal", "kacho.cloud.vpc.v1.InternalNetworkService/GetNetwork"},
		// IAM SAKeyService — service-account key subpaths under the SA item.
		{"POST", "/iam/v1/serviceAccounts/sva0000000000000001/keys", "kacho.cloud.iam.v1.SAKeyService/Issue"},
		{"GET", "/iam/v1/serviceAccounts/sva0000000000000001/keys", "kacho.cloud.iam.v1.SAKeyService/List"},
		{"DELETE", "/iam/v1/serviceAccounts/sva0000000000000001/keys/key0000000000000001", "kacho.cloud.iam.v1.SAKeyService/Revoke"},
		// IAM UserTokenService — personal API-token subpaths under the user item
		// (mirrors SAKeyService, parent-scoped on iam_user).
		{"POST", "/iam/v1/users/usr0000000000000001/tokens", "kacho.cloud.iam.v1.UserTokenService/Issue"},
		{"GET", "/iam/v1/users/usr0000000000000001/tokens", "kacho.cloud.iam.v1.UserTokenService/List"},
		{"DELETE", "/iam/v1/users/usr0000000000000001/tokens/uoc0000000000000001", "kacho.cloud.iam.v1.UserTokenService/Revoke"},
		// IAM AccessBindingService scope-polymorphic reads (GET suffix-actions).
		{"GET", "/iam/v1/accessBindings:listByScope", "kacho.cloud.iam.v1.AccessBindingService/ListByScope"},
		{"GET", "/iam/v1/accessBindings:listBySubject", "kacho.cloud.iam.v1.AccessBindingService/ListBySubject"},
		// Registry — first REST-exposed registry resource.
		{"POST", "/registry/v1/registries", "kacho.cloud.registry.v1.RegistryService/Create"},
		{"DELETE", "/registry/v1/registries/reg0000000000000001/repositories/app/tags/v1", "kacho.cloud.registry.v1.RegistryService/DeleteTag"},
	}
	for _, c := range cases {
		fqn, ok := r.Resolve(c.method, c.path)
		if !ok {
			t.Errorf("Resolve(%s %s): no match, want %s — route table stale (regenerate scripts/gen-rest-route-table.sh)", c.method, c.path, c.wantFQN)
			continue
		}
		if fqn != c.wantFQN {
			t.Errorf("Resolve(%s %s) = %s, want %s", c.method, c.path, fqn, c.wantFQN)
		}
	}

	// Services deleted from proto must not leave dangling routes. If the table
	// is regenerated from the current tree, no route may resolve to them.
	for _, rt := range generatedRestRoutes {
		switch {
		case strings.HasPrefix(rt.FQN, "kacho.cloud.iam.v1.TrustPolicyService/"),
			strings.HasPrefix(rt.FQN, "kacho.cloud.iam.v1.OpaBundleService/"),
			strings.HasPrefix(rt.FQN, "kacho.cloud.iam.v1.FederationExchangeService/"):
			t.Errorf("route table still contains %q — service removed from proto, stale entry", rt.FQN)
		}
	}
}

func TestMatchTemplate(t *testing.T) {
	cases := []struct {
		tmpl, path string
		want       bool
	}{
		{"/iam/v1/accounts", "/iam/v1/accounts", true},
		{"/iam/v1/accounts/{account_id}", "/iam/v1/accounts/acc1", true},
		{"/iam/v1/accounts/{account_id}", "/iam/v1/accounts", false},
		{"/iam/v1/accounts/{account_id}", "/iam/v1/accounts/acc1/extra", false},
		{"/iam/v1/users:invite", "/iam/v1/users:invite", true},
		{"/iam/v1/users:invite", "/iam/v1/users", false},
		{"/vpc/v1/networks/{network_id}", "/vpc/v1/networks/enp1", true},
	}
	for _, c := range cases {
		if got := matchTemplate(c.tmpl, c.path); got != c.want {
			t.Errorf("matchTemplate(%q, %q) = %v, want %v", c.tmpl, c.path, got, c.want)
		}
	}
}
