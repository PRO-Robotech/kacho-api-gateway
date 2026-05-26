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

func TestPermissionCatalog_RejectBadVersionFlavour(t *testing.T) {
	// Truncated input — must fail with descriptive error.
	raw := []byte(`{"entries":`)
	c := middleware.NewPermissionCatalog()
	err := c.LoadFromBytes(raw)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "decode")
}
