// authz_as_invalidator_test.go — RED test for the W1.2 AuthzMiddleware.AsInvalidator()
// adapter that exposes a small port consumed by the new
// handler.InternalAuthzCacheServer.
//
// W1.2 (KAC-138 of KAC-136 / KAC-134 epic). Acceptance §4.5:
//
//	// internal_authz_cache_server.go (NEW) takes a small Invalidator port:
//	type Invalidator interface {
//	    InvalidateSubject(subject string) int
//	    Invalidate()                       // fallback whole-cache flush
//	}
//
//	// main.go wires:
//	inv := authzMW.AsInvalidator()    // <-- new method this test pins
//	cacheSrv := handler.NewInternalAuthzCacheServer(inv, logger)
//
// At RED time `AsInvalidator` does NOT exist on *AuthzMiddleware.
package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestW1_2_AuthzMiddleware_AsInvalidator_ReturnsInvalidator — the new
// adapter must:
//   - InvalidateSubject(subject) → drop entries scoped to that subject,
//     return count of dropped entries
//   - Invalidate() → whole-cache flush (safety-net fallback)
//
// At RED: undefined: method m.AsInvalidator.
func TestW1_2_AuthzMiddleware_AsInvalidator_ReturnsInvalidator(t *testing.T) {
	m, err := NewAuthzMiddleware(AuthzMiddlewareConfig{Enabled: false})
	require.NoError(t, err)
	m.cache = newDecisionCache(100, 5*time.Second, time.Now)
	m.cache.put("user:nob|iam.projects.get|project|prj1|", decisionCacheEntry{allowed: true})
	m.cache.put("user:nob|iam.projects.get|project|prj2|", decisionCacheEntry{allowed: true})
	m.cache.put("user:alice|iam.projects.get|project|prj1|", decisionCacheEntry{allowed: true})
	require.Equal(t, 3, m.cache.Size())

	inv := m.AsInvalidator() // RED: undefined method
	require.NotNil(t, inv)

	dropped := inv.InvalidateSubject("user:nob")
	assert.Equal(t, 2, dropped,
		"AsInvalidator().InvalidateSubject must drop only subject's entries")
	assert.Equal(t, 1, m.cache.Size(),
		"unrelated subjects' entries must survive per-subject invalidate")

	inv.Invalidate()
	assert.Equal(t, 0, m.cache.Size(),
		"AsInvalidator().Invalidate must be a whole-cache flush (safety net)")
}

// TestW1_2_AuthzMiddleware_AsInvalidator_NilCache_NoOp — when authz is
// disabled (cache is nil), AsInvalidator must still return a non-nil
// Invalidator whose methods no-op gracefully. Otherwise main.go wiring
// crashes on disabled-authz configs.
func TestW1_2_AuthzMiddleware_AsInvalidator_NilCache_NoOp(t *testing.T) {
	m, err := NewAuthzMiddleware(AuthzMiddlewareConfig{Enabled: false})
	require.NoError(t, err)
	// m.cache remains nil (we never assigned it)
	inv := m.AsInvalidator()
	require.NotNil(t, inv,
		"AsInvalidator must return non-nil even with disabled-authz / nil cache")
	assert.Equal(t, 0, inv.InvalidateSubject("user:any"),
		"InvalidateSubject on nil cache must return 0 (no entries to drop)")
	inv.Invalidate() // must not panic
}
