package middleware_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestPermissionCatalog_LoadFromBytes_ArrayShape(t *testing.T) {
	raw := []byte(`[
		{
			"fqn": "kacho.cloud.vpc.v1.NetworkService/Create",
			"permission": "vpc.networks.create",
			"required_relation": "editor",
			"scope_extractor": {"object_type": "project", "from_request_field": "folder_id"},
			"required_acr_min": "2"
		}
	]`)
	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromBytes(raw))

	entry, ok := c.Lookup("kacho.cloud.vpc.v1.NetworkService/Create")
	require.True(t, ok)
	assert.Equal(t, "vpc.networks.create", entry.Permission)
	assert.Equal(t, "editor", entry.RequiredRelation)
	assert.Equal(t, "project", entry.ScopeExtractor.ObjectType)
	assert.Equal(t, "folder_id", entry.ScopeExtractor.FromRequestField)
	assert.Equal(t, "2", entry.RequiredACRMin)
}

func TestPermissionCatalog_LoadFromBytes_ObjectShape(t *testing.T) {
	raw := []byte(`{
		"entries": [
			{
				"fqn": "kacho.cloud.iam.v1.AuthorizeService/Check",
				"permission": "iam.authorize.check",
				"required_relation": "viewer",
				"risk_level": "MEDIUM"
			}
		],
		"critical": {"permissions": ["audit.RewindMerkle"]}
	}`)
	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromBytes(raw))

	entry, ok := c.Lookup("kacho.cloud.iam.v1.AuthorizeService/Check")
	require.True(t, ok)
	assert.Equal(t, "iam.authorize.check", entry.Permission)
	assert.Equal(t, "MEDIUM", entry.RiskLevel)
}

func TestPermissionCatalog_LoadFromBytes_EmptyError(t *testing.T) {
	c := middleware.NewPermissionCatalog()
	err := c.LoadFromBytes([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestPermissionCatalog_LoadFromBytes_DuplicateError(t *testing.T) {
	raw := []byte(`[
		{"fqn": "X/Y", "permission": "a.b.c"},
		{"fqn": "X/Y", "permission": "x.y.z"}
	]`)
	c := middleware.NewPermissionCatalog()
	err := c.LoadFromBytes(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestPermissionCatalog_LoadFromBytes_MissingFQNError(t *testing.T) {
	raw := []byte(`[{"permission": "a.b.c"}]`)
	c := middleware.NewPermissionCatalog()
	err := c.LoadFromBytes(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty fqn")
}

func TestPermissionCatalog_LookupMiss(t *testing.T) {
	raw := []byte(`[{"fqn": "X/Y", "permission": "a.b.c"}]`)
	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromBytes(raw))
	_, ok := c.Lookup("nope/nope")
	assert.False(t, ok)
}

func TestPermissionCatalog_EmbeddedAsset_Loads(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)
	// The embedded asset is the full Phase 3 catalog. KAC-124 removed the
	// resource-manager / organization-manager protos (~39 RPCs); KAC-127
	// then annotated every remaining RPC, so the catalog carries ~264
	// entries and EVERY entry must be classified (no empty permission).
	assert.GreaterOrEqual(t, c.Size(), 240)
	for _, fqn := range c.FQNs() {
		e, _ := c.Lookup(fqn)
		assert.NotEmpty(t, e.Permission, "catalog entry %s has empty permission", fqn)
	}

	// Spot-check a known-populated entry from the catalog.
	entry, ok := c.Lookup("kacho.cloud.iam.v1.AuthorizeService/Check")
	require.True(t, ok)
	assert.Equal(t, "iam.authorize.check", entry.Permission)
	assert.Equal(t, "viewer", entry.RequiredRelation)
}

func TestPermissionCatalog_LoadFromFile_Reload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"fqn":"A/X","permission":"a.x.c"}]`), 0o600))

	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromFile(path))
	assert.Equal(t, 1, c.Size())

	// Modify file, reload.
	require.NoError(t, os.WriteFile(path,
		[]byte(`[
			{"fqn":"A/X","permission":"a.x.c"},
			{"fqn":"B/Y","permission":"b.y.d"}
		]`), 0o600))
	require.NoError(t, c.Reload())
	assert.Equal(t, 2, c.Size())
}

func TestPermissionCatalog_LoadFromFile_Missing(t *testing.T) {
	c := middleware.NewPermissionCatalog()
	err := c.LoadFromFile("/no/such/file.json")
	require.Error(t, err)
}

func TestPermissionCatalog_Reload_NoPrevious(t *testing.T) {
	c := middleware.NewPermissionCatalog()
	err := c.Reload()
	require.Error(t, err)
}

func TestPermissionCatalog_FQNs_Sorted(t *testing.T) {
	raw := []byte(`[
		{"fqn":"Z/Y", "permission":"z.y.c"},
		{"fqn":"A/X", "permission":"a.x.c"},
		{"fqn":"M/N", "permission":"m.n.c"}
	]`)
	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromBytes(raw))
	got := c.FQNs()
	require.Equal(t, []string{"A/X", "M/N", "Z/Y"}, got)
}

func TestPermissionCatalog_IsExempt(t *testing.T) {
	raw := []byte(`[
		{"fqn":"A/X", "permission":"<exempt>"},
		{"fqn":"B/Y", "permission":"vpc.networks.get"}
	]`)
	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromBytes(raw))
	ex, _ := c.Lookup("A/X")
	assert.True(t, ex.IsExempt())
	ne, _ := c.Lookup("B/Y")
	assert.False(t, ne.IsExempt())
}

func TestPermissionCatalog_EmbedBytes_Stable(t *testing.T) {
	b := middleware.EmbeddedPermissionCatalogJSON()
	require.NotEmpty(t, b)
	// Ensure returned slice is a copy — mutating it must not affect future calls.
	b[0] = '!'
	b2 := middleware.EmbeddedPermissionCatalogJSON()
	assert.NotEqual(t, b[0], b2[0])
}

func TestPermissionCatalog_ReloadAfterParseError_Preserves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"fqn":"A/X","permission":"a.x.c"}]`), 0o600))

	c := middleware.NewPermissionCatalog()
	require.NoError(t, c.LoadFromFile(path))
	require.Equal(t, 1, c.Size())

	// Corrupt the file: invalid JSON.
	require.NoError(t, os.WriteFile(path, []byte(`not json {{`), 0o600))
	err := c.Reload()
	require.Error(t, err)
	// Previous good state preserved.
	assert.Equal(t, 1, c.Size())
	entry, ok := c.Lookup("A/X")
	require.True(t, ok)
	assert.Equal(t, "a.x.c", entry.Permission)
}

func TestPermissionCatalog_LookupKnownEntries_FromEmbed(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	for _, want := range []struct {
		fqn    string
		perm   string
		scopeF string
	}{
		{"kacho.cloud.iam.v1.AuthorizeService/Check", "iam.authorize.check", "subject"},
		{"kacho.cloud.iam.v1.AuthorizeService/BatchCheck", "iam.authorize.batchCheck", "scope_id"},
		{"kacho.cloud.iam.v1.ConditionsService/Create", "iam.conditions.create", "folder_id"},
	} {
		t.Run(want.fqn, func(t *testing.T) {
			entry, ok := c.Lookup(want.fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", want.fqn)
			assert.Equal(t, want.perm, entry.Permission)
			assert.Equal(t, want.scopeF, entry.ScopeExtractor.FromRequestField)
		})
	}
}

// TestPermissionCatalog_ListAssignableRoles_ScopePolymorphic (sub-phase 1.5,
// D-5) — the embedded catalog MUST carry AccessBindingService/ListAssignableRoles
// as a scope-polymorphic viewer-floor entry, exactly like ListByScope: the
// FGA object type is derived from the request `resource_type` field (the
// `object_type_from_request_field` directive), not the static `object_type`.
// Without `object_type_from_request_field`, an account/cluster-scoped grant
// palette read would be checked as `project:<id>` → 403 (Bug A regression).
func TestPermissionCatalog_ListAssignableRoles_ScopePolymorphic(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	entry, ok := c.Lookup("kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles")
	require.True(t, ok, "ListAssignableRoles missing from embedded catalog (sub-phase 1.5)")
	assert.Equal(t, "iam.access_bindings_by_resources.listAssignableRoles", entry.Permission)
	assert.Equal(t, "viewer", entry.RequiredRelation,
		"catalog floor must be viewer (handler requireGrantAuthority is the precise gate, D-5)")
	assert.Equal(t, "project", entry.ScopeExtractor.ObjectType,
		"static object_type is the fallback (parity with ListByScope)")
	assert.Equal(t, "resource_id", entry.ScopeExtractor.FromRequestField)
	assert.Equal(t, "resource_type", entry.ScopeExtractor.ObjectTypeFromRequestField,
		"object_type must be derived from request resource_type (scope-polymorphic, Bug A)")
	assert.Equal(t, "2", entry.RequiredACRMin, "anti-anon ACR floor (D-5)")
}

// TestPermissionCatalog_ListByScope_ScopePolymorphic (RBAC rules-model F
// clean-cut) — ListByResource was renamed → ListByScope (proto-F). The embedded
// catalog MUST carry the renamed entry as a scope-polymorphic viewer-floor entry:
// the FGA object type is derived from the request `resource_type` field via
// `object_type_from_request_field`, with static `project` only as fallback
// (Bug A). The permission key was renamed in lockstep (…listByScope).
func TestPermissionCatalog_ListByScope_ScopePolymorphic(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	entry, ok := c.Lookup("kacho.cloud.iam.v1.AccessBindingService/ListByScope")
	require.True(t, ok, "ListByScope missing from embedded catalog (RBAC rules-model F)")
	assert.Equal(t, "iam.access_bindings_by_resources.listByScope", entry.Permission)
	assert.Equal(t, "viewer", entry.RequiredRelation,
		"catalog floor must be viewer (handler is the precise gate)")
	assert.Equal(t, "project", entry.ScopeExtractor.ObjectType,
		"static object_type is the fallback (scope-polymorphic)")
	assert.Equal(t, "resource_id", entry.ScopeExtractor.FromRequestField)
	assert.Equal(t, "resource_type", entry.ScopeExtractor.ObjectTypeFromRequestField,
		"object_type must be derived from request resource_type (scope-polymorphic, Bug A)")
	assert.Equal(t, "2", entry.RequiredACRMin, "anti-anon ACR floor")

	// The removed target/selector RPCs (proto-F clean-cut) must NOT be present.
	for _, gone := range []string{
		"kacho.cloud.iam.v1.AccessBindingService/AddTargetResources",
		"kacho.cloud.iam.v1.AccessBindingService/RemoveTargetResources",
		"kacho.cloud.iam.v1.AccessBindingService/ReplaceTargetSelector",
		"kacho.cloud.iam.v1.AccessBindingService/ListGrantableResources",
		"kacho.cloud.iam.v1.AccessBindingService/ListByResource",
	} {
		_, present := c.Lookup(gone)
		assert.False(t, present, "removed/renamed RPC must NOT be in catalog: %s", gone)
	}
}

// TestPermissionCatalog_AccessBindingUpdate_VerbBearing (Design-B verb-bearing
// complete) — AccessBindingService.Update is an object-self mutation on the
// `iam_access_binding` object. Enforcement references the verb-bearing relation
// `v_update` (not the coarse `editor` tier): the gate resolves on the verb, so
// a v_update-grant satisfies it while a v_list/v_get grant does not (D-6
// see-in-selector-without-content). Object/field scope is unchanged: object
// `iam_access_binding` resolved from `access_binding_id`, acr floor 2. Without
// this embedded entry the per-RPC authz middleware has "no entry for method" →
// the PATCH is denied (catalog miss).
func TestPermissionCatalog_AccessBindingUpdate_VerbBearing(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	entry, ok := c.Lookup("kacho.cloud.iam.v1.AccessBindingService/Update")
	require.True(t, ok, "AccessBindingService/Update missing from embedded catalog")
	assert.Equal(t, "iam.access_bindings.update", entry.Permission)
	assert.Equal(t, "v_update", entry.RequiredRelation, "Update is an object-self mutation — verb-bearing v_update (Design B), not editor tier")
	assert.Equal(t, "iam_access_binding", entry.ScopeExtractor.ObjectType)
	assert.Equal(t, "access_binding_id", entry.ScopeExtractor.FromRequestField)
	assert.Equal(t, "2", entry.RequiredACRMin, "anti-anon ACR floor")
}

// TestPermissionCatalog_InternalClusterService_LockedSystemAdmin (item-2b) —
// regression guard: every RPC of `InternalClusterService` must be gated by
// the FGA relation `system_admin` on `cluster:<cluster-singleton>` in the
// embedded catalog. Non-admin callers MUST NOT be able to even observe
// these RPCs — `Get` / `ListAdmins` would otherwise leak the existence and
// roster of cluster admins. Regressing any of these entries to `<exempt>` /
// `viewer` / non-`cluster` scope would re-open the leak.
func TestPermissionCatalog_InternalClusterService_LockedSystemAdmin(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	want := []struct {
		fqn  string
		perm string
	}{
		{"kacho.cloud.iam.v1.InternalClusterService/Get", "iam.cluster_admins.get"},
		{"kacho.cloud.iam.v1.InternalClusterService/ListAdmins", "iam.cluster_admins.list"},
		{"kacho.cloud.iam.v1.InternalClusterService/GrantAdmin", "iam.cluster_admins.grant"},
		{"kacho.cloud.iam.v1.InternalClusterService/RevokeAdmin", "iam.cluster_admins.revoke"},
	}

	for _, w := range want {
		t.Run(w.fqn, func(t *testing.T) {
			entry, ok := c.Lookup(w.fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", w.fqn)
			assert.False(t, entry.IsExempt(),
				"InternalClusterService.%s must NOT be <exempt> — non-admins would observe cluster-admin roster",
				w.fqn)
			assert.Equal(t, w.perm, entry.Permission,
				"permission identifier drift on %s", w.fqn)
			assert.Equal(t, "system_admin", entry.RequiredRelation,
				"required_relation must be system_admin on %s (acceptance D-11, item-2b)", w.fqn)
			assert.Equal(t, "cluster", entry.ScopeExtractor.ObjectType,
				"scope object_type must be cluster on %s", w.fqn)
			assert.Equal(t, "*", entry.ScopeExtractor.FromRequestField,
				"scope from_request_field must be '*' (cluster singleton) on %s", w.fqn)
		})
	}
}

// TestPermissionCatalog_ListPermissionCatalog_ExemptAndTombstones (RBAC
// rules-model 2026 sub-phase G) — after the proto-G tombstones + catalog resync
// the embedded catalog MUST:
//   - carry PermissionCatalogService.ListPermissionCatalog as an authenticated-
//     floor read (<exempt> permission — no FGA Check; reachable on the external
//     listener so the UI can build its role/permission palette);
//   - NO LONGER carry the two tombstoned RPCs InternalIAMService.ListPermissions
//     and InternalAuthorizeService.RunRegoTest.
//
// Goes RED on the stale embedded copy (still has the tombstones, lacks the new
// entry) and GREEN after `make sync-permission-catalog` resyncs from proto-gen.
func TestPermissionCatalog_ListPermissionCatalog_ExemptAndTombstones(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	entry, ok := c.Lookup("kacho.cloud.iam.v1.PermissionCatalogService/ListPermissionCatalog")
	require.True(t, ok, "ListPermissionCatalog missing from embedded catalog (sub-phase G — resync not run?)")
	assert.Equal(t, "<exempt>", entry.Permission,
		"ListPermissionCatalog must be <exempt> (authenticated-floor read, no FGA Check)")
	assert.True(t, entry.IsExempt(), "ListPermissionCatalog must be exempt")

	for _, gone := range []string{
		"kacho.cloud.iam.v1.InternalIAMService/ListPermissions",
		"kacho.cloud.iam.v1.InternalAuthorizeService/RunRegoTest",
	} {
		_, present := c.Lookup(gone)
		assert.False(t, present, "tombstoned RPC must NOT be in embedded catalog (proto-G): %s", gone)
	}
}

// TestPermissionCatalog_VBC22_VerbBearingFlip (sub-phase flat-authz verb-bearing
// complete, VBC-22) — the embedded catalog must mirror the Design-B proto-gen
// source: object-self get/list/update/delete RPCs are gated by the verb-bearing
// relations v_get/v_list/v_update/v_delete, while create-child stays `editor`
// on the parent (F-7, create on a not-yet-existing object is meaningless),
// Internal.* admin RPCs stay `system_admin` (ban #6 — no surface/relation
// downgrade on cluster-internal admin methods), and exempt RPCs stay exempt.
// Goes RED on the stale (tier) embed; GREEN after `make sync-permission-catalog`
// pulls the Design-B catalog from kacho-proto/gen.
func TestPermissionCatalog_VBC22_VerbBearingFlip(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	cases := []struct {
		fqn      string
		relation string
		note     string
	}{
		// object-self reads → v_get / v_list
		{"kacho.cloud.iam.v1.UserService/Get", "v_get", "object-self get"},
		{"kacho.cloud.vpc.v1.NetworkService/Get", "v_get", "object-self get"},
		{"kacho.cloud.compute.v1.InstanceService/Get", "v_get", "object-self get"},
		{"kacho.cloud.compute.v1.InstanceService/List", "v_list", "object-self list"},
		// account/project get → v_get (R6 default = consistency; List stays use-case viewer∪v_list)
		{"kacho.cloud.iam.v1.AccountService/Get", "v_get", "account get → v_get (R6)"},
		{"kacho.cloud.iam.v1.ProjectService/Get", "v_get", "project get → v_get (R6)"},
		// object-self mutations → v_update / v_delete
		{"kacho.cloud.vpc.v1.NetworkService/Update", "v_update", "object-self update"},
		{"kacho.cloud.vpc.v1.NetworkService/Delete", "v_delete", "object-self delete"},
		{"kacho.cloud.iam.v1.AccessBindingService/Delete", "v_delete", "object-self delete"},
		// create-child stays editor on parent (F-7)
		{"kacho.cloud.vpc.v1.NetworkService/Create", "editor", "create-child → editor on parent (F-7)"},
		{"kacho.cloud.compute.v1.InstanceService/Create", "editor", "create-child → editor on parent (F-7)"},
		// Internal.* admin RPCs unchanged — system_admin (ban #6)
		{"kacho.cloud.iam.v1.InternalClusterService/Get", "system_admin", "Internal admin — no downgrade"},
		{"kacho.cloud.geo.v1.InternalRegionService/Create", "system_admin", "Internal admin — no downgrade"},
		// scope-polymorphic AB reads stay viewer (handler is the precise gate)
		{"kacho.cloud.iam.v1.AccessBindingService/ListByScope", "viewer", "scope-polymorphic read floor"},
		{"kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles", "viewer", "scope-polymorphic read floor"},
	}
	for _, tc := range cases {
		t.Run(tc.fqn, func(t *testing.T) {
			entry, ok := c.Lookup(tc.fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", tc.fqn)
			assert.Equal(t, tc.relation, entry.RequiredRelation, "%s (%s)", tc.fqn, tc.note)
		})
	}

	// Exempt RPCs stay exempt (authenticated-floor reads, no FGA Check).
	for _, fqn := range []string{
		"kacho.cloud.iam.v1.PermissionCatalogService/ListPermissionCatalog",
		"kacho.cloud.iam.v1.AccountService/List",
	} {
		entry, ok := c.Lookup(fqn)
		require.True(t, ok, "exempt fqn missing: %s", fqn)
		assert.True(t, entry.IsExempt(), "%s must stay exempt", fqn)
	}

	// Invariant: no Internal.* RPC carries a v_* verb-bearing relation (ban #6 —
	// cluster-internal admin methods are tier/system_admin, never object-self verbs).
	for _, fqn := range c.FQNs() {
		if !strings.Contains(fqn, "Internal") {
			continue
		}
		entry, _ := c.Lookup(fqn)
		assert.False(t, strings.HasPrefix(entry.RequiredRelation, "v_"),
			"Internal.* RPC %s must not carry a verb-bearing relation %q", fqn, entry.RequiredRelation)
	}
}

func TestPermissionCatalog_RejectBadVersionFlavour(t *testing.T) {
	// Truncated input — must fail with descriptive error.
	raw := []byte(`{"entries":`)
	c := middleware.NewPermissionCatalog()
	err := c.LoadFromBytes(raw)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "decode")
}
