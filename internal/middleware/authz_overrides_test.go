package middleware_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestAuthzOverrides_LoadAllowDeny(t *testing.T) {
	o := middleware.NewAuthzOverrides()
	require.NoError(t, o.LoadFromBytes([]byte(`
version: 1
overrides:
  - fqn: "X/Y"
    decision: "allow"
    reason: "rollout"
  - fqn: "A/B"
    decision: "deny"
    reason: "lockdown"
`)))
	d, ok := o.Lookup("X/Y")
	require.True(t, ok)
	assert.Equal(t, middleware.OverrideAllow, d)
	assert.Equal(t, "rollout", o.Reason("X/Y"))

	d, ok = o.Lookup("A/B")
	require.True(t, ok)
	assert.Equal(t, middleware.OverrideDeny, d)
	assert.Equal(t, "lockdown", o.Reason("A/B"))

	_, ok = o.Lookup("Q/R")
	assert.False(t, ok)
}

func TestAuthzOverrides_RejectsUnknownDecision(t *testing.T) {
	o := middleware.NewAuthzOverrides()
	err := o.LoadFromBytes([]byte(`
overrides:
  - fqn: "X/Y"
    decision: "shrug"
`))
	require.Error(t, err)
}

func TestAuthzOverrides_RejectsDuplicate(t *testing.T) {
	o := middleware.NewAuthzOverrides()
	err := o.LoadFromBytes([]byte(`
overrides:
  - fqn: "X/Y"
    decision: "allow"
  - fqn: "X/Y"
    decision: "deny"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestAuthzOverrides_EmptyBufferClears(t *testing.T) {
	o := middleware.NewAuthzOverrides()
	require.NoError(t, o.LoadFromBytes([]byte(`
overrides:
  - fqn: "X/Y"
    decision: "allow"
`)))
	require.NoError(t, o.LoadFromBytes(nil))
	assert.Equal(t, 0, o.Size())
}

func TestAuthzOverrides_FileReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
overrides:
  - fqn: "X/Y"
    decision: "allow"
`), 0o600))

	o := middleware.NewAuthzOverrides()
	require.NoError(t, o.LoadFromFile(path))
	d, ok := o.Lookup("X/Y")
	require.True(t, ok)
	assert.Equal(t, middleware.OverrideAllow, d)

	require.NoError(t, os.WriteFile(path, []byte(`
overrides:
  - fqn: "X/Y"
    decision: "deny"
`), 0o600))
	require.NoError(t, o.Reload())
	d, ok = o.Lookup("X/Y")
	require.True(t, ok)
	assert.Equal(t, middleware.OverrideDeny, d)
}

func TestAuthzOverrides_ReloadAfterCorruption_Preserves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
overrides:
  - fqn: "X/Y"
    decision: "allow"
`), 0o600))

	o := middleware.NewAuthzOverrides()
	require.NoError(t, o.LoadFromFile(path))

	require.NoError(t, os.WriteFile(path, []byte(`overrides: ["bad"]`), 0o600))
	err := o.Reload()
	require.Error(t, err)

	// Previous value preserved.
	d, ok := o.Lookup("X/Y")
	require.True(t, ok)
	assert.Equal(t, middleware.OverrideAllow, d)
}

func TestAuthzOverrides_ReloadNoPath(t *testing.T) {
	o := middleware.NewAuthzOverrides()
	err := o.Reload()
	require.Error(t, err)
}

func TestAuthzOverrides_VersionMismatch(t *testing.T) {
	o := middleware.NewAuthzOverrides()
	err := o.LoadFromBytes([]byte(`version: 9
overrides:
  - fqn: "X/Y"
    decision: "allow"
`))
	require.Error(t, err)
}

func TestOverrideDecision_String(t *testing.T) {
	assert.Equal(t, "allow", middleware.OverrideAllow.String())
	assert.Equal(t, "deny", middleware.OverrideDeny.String())
	assert.Equal(t, "none", middleware.OverrideNone.String())
}
