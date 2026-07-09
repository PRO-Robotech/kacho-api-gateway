// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func reloadTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newReloadableAuthz(t *testing.T, catalog *middleware.PermissionCatalog, overrides *middleware.AuthzOverrides) *middleware.AuthzMiddleware {
	t.Helper()
	mw, err := middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{
		Enabled:         true,
		Catalog:         catalog,
		Overrides:       overrides,
		Subjects:        middleware.NewSubjectExtractor(true),
		Context:         middleware.NewContextExtractor(time.Now, true),
		Resources:       middleware.NewResourceExtractor(nil),
		Checker:         &fakeChecker{allowed: true},
		Logger:          reloadTestLogger(),
		CacheTTL:        5 * time.Second,
		CacheMaxEntries: 100,
		PublicAllowlist: middleware.DefaultPublicAllowlist(),
		RestRouter:      middleware.NewRestRouter(),
	})
	require.NoError(t, err)
	return mw
}

// TestAuthzMiddleware_Reload_PicksUpFileChanges locks the SIGHUP-reload
// behaviour end-to-end: after the on-disk override + catalog files change,
// AuthzMiddleware.Reload() must make the new content live. An operator's
// emergency explicit-deny (or catalog fix) must apply without a pod restart.
func TestAuthzMiddleware_Reload_PicksUpFileChanges(t *testing.T) {
	dir := t.TempDir()

	ovPath := filepath.Join(dir, "overrides.yaml")
	require.NoError(t, os.WriteFile(ovPath, []byte(`
overrides:
  - fqn: "kacho.cloud.vpc.v1.NetworkService/Get"
    decision: "allow"
`), 0o600))
	overrides := middleware.NewAuthzOverrides()
	require.NoError(t, overrides.LoadFromFile(ovPath))

	catPath := filepath.Join(dir, "catalog.json")
	require.NoError(t, os.WriteFile(catPath, []byte(`[{"fqn":"S/M1"}]`), 0o600))
	catalog := middleware.NewPermissionCatalog()
	require.NoError(t, catalog.LoadFromFile(catPath))

	mw := newReloadableAuthz(t, catalog, overrides)

	// Baseline: override is "allow", catalog knows only S/M1.
	d, ok := overrides.Lookup("kacho.cloud.vpc.v1.NetworkService/Get")
	require.True(t, ok)
	require.Equal(t, middleware.OverrideAllow, d)
	_, ok = catalog.Lookup("S/M2")
	require.False(t, ok)

	// Operator rewrites both files (emergency deny + new catalog entry).
	require.NoError(t, os.WriteFile(ovPath, []byte(`
overrides:
  - fqn: "kacho.cloud.vpc.v1.NetworkService/Get"
    decision: "deny"
    reason: "incident response"
`), 0o600))
	require.NoError(t, os.WriteFile(catPath, []byte(`[{"fqn":"S/M1"},{"fqn":"S/M2"}]`), 0o600))

	// Before reload the middleware still serves the stale config.
	d, ok = overrides.Lookup("kacho.cloud.vpc.v1.NetworkService/Get")
	require.True(t, ok)
	require.Equal(t, middleware.OverrideAllow, d)

	require.NoError(t, mw.Reload())

	// After reload the new deny + catalog entry are live.
	d, ok = overrides.Lookup("kacho.cloud.vpc.v1.NetworkService/Get")
	require.True(t, ok)
	assert.Equal(t, middleware.OverrideDeny, d)
	_, ok = catalog.Lookup("S/M2")
	assert.True(t, ok)
}

// TestAuthzMiddleware_Reload_EmbeddedNoPath_NoError verifies that a catalog
// backed by the embedded asset (no on-disk path) and absent overrides file are
// skipped by Reload rather than erroring — a plain deployment without a
// ConfigMap override must not log a reload error on every SIGHUP.
func TestAuthzMiddleware_Reload_EmbeddedNoPath_NoError(t *testing.T) {
	catalog := middleware.NewPermissionCatalog()
	require.NoError(t, catalog.LoadFromBytes([]byte(`[{"fqn":"S/M1"}]`)))
	overrides := middleware.NewAuthzOverrides() // never loaded from file

	mw := newReloadableAuthz(t, catalog, overrides)
	assert.NoError(t, mw.Reload())
}

// TestAuthzMiddleware_Reload_Disabled_NoError verifies Reload is a safe no-op
// when authz is disabled (no catalog/overrides wired).
func TestAuthzMiddleware_Reload_Disabled_NoError(t *testing.T) {
	mw, err := middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{Enabled: false})
	require.NoError(t, err)
	assert.NoError(t, mw.Reload())
}
