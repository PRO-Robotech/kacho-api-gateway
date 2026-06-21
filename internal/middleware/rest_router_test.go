// rest_router_test.go — KAC-127 Problem 1: REST<->gRPC route resolution.
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
		// sub-phase 1.3: AccessBindingService.ListSubjectPrivileges — public read,
		// GET suffix-action; must resolve so the catalog gate (viewer floor) fires.
		{"GET", "/iam/v1/accessBindings:listSubjectPrivileges", "kacho.cloud.iam.v1.AccessBindingService/ListSubjectPrivileges"},
		// sub-phase 1.5: AccessBindingService.ListAssignableRoles — public read,
		// GET suffix-action; must resolve so the scope-polymorphic catalog gate
		// (viewer floor + dynamic object_type) fires.
		{"GET", "/iam/v1/accessBindings:listAssignableRoles", "kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles"},
		// epic-100 α: AccessBindingService resource-scoped target mutations +
		// grantable-resources picker. Add/Remove are POST suffix-actions on an
		// existing binding ({access_binding_id}); must resolve so the <exempt>
		// catalog bypass fires (authN enforced, FGA skipped — handler authoritative,
		// parity with Create). ListGrantableResources is a GET suffix-action on the
		// collection; must resolve so the scope-polymorphic catalog gate (viewer
		// floor + dynamic object_type from scope_type) fires.
		{"POST", "/iam/v1/accessBindings/iab0000000000000001:addTargetResources", "kacho.cloud.iam.v1.AccessBindingService/AddTargetResources"},
		{"POST", "/iam/v1/accessBindings/iab0000000000000001:removeTargetResources", "kacho.cloud.iam.v1.AccessBindingService/RemoveTargetResources"},
		// epic-rsab γ: ReplaceTargetSelector — POST suffix-action on an existing
		// binding ({access_binding_id}); must resolve so the <exempt> catalog
		// bypass fires (authN enforced, FGA skipped — handler authoritative).
		{"POST", "/iam/v1/accessBindings/iab0000000000000001:replaceTargetSelector", "kacho.cloud.iam.v1.AccessBindingService/ReplaceTargetSelector"},
		{"GET", "/iam/v1/accessBindings:listGrantableResources", "kacho.cloud.iam.v1.AccessBindingService/ListGrantableResources"},
		// RBAC rules-model 2026 sub-phase E: ListByRole + ExpandAccess — public
		// reads, GET suffix-actions on the collection; must resolve so the
		// cluster-scoped catalog gate (viewer floor, acr 2) fires.
		{"GET", "/iam/v1/accessBindings:listByRole", "kacho.cloud.iam.v1.AccessBindingService/ListByRole"},
		{"GET", "/iam/v1/accessBindings:expandAccess", "kacho.cloud.iam.v1.AccessBindingService/ExpandAccess"},
		// KAC-225: WhoAmI (GET /iam/v1/me) must resolve — was missing from the
		// route table, so path->FQN failed and the <exempt> bypass never fired
		// → 403 "catalog: no entry for method" broke UI permission bootstrap.
		{"GET", "/iam/v1/me", "kacho.cloud.iam.v1.AuthorizeService/WhoAmI"},
		// list with query string is stripped before matching
		{"GET", "/iam/v1/projects?accountId=acc1", "kacho.cloud.iam.v1.ProjectService/List"},
		// vpc resource
		{"GET", "/vpc/v1/networks/enp0000000000000001", "kacho.cloud.vpc.v1.NetworkService/Get"},
		// KAC-269: InternalAddressPoolService CIDR-block suffix-actions (internal mux).
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
