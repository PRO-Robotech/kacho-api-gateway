// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rest_router_test.go — REST<->gRPC route resolution.
package middleware

import "testing"

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
