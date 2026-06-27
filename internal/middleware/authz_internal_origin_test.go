// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// The 4 Internal* FQNs that were wrongly baked into DefaultPublicAllowlist()
// (priv-esc: unauthenticated authz-oracle / user-enumeration / user-mutation
// from the edge). They must NOT be a global FQN allowlist entry — internal
// callers are admitted by the internal-listener-origin gate instead.
var removedInternalFQNs = []string{
	"kacho.cloud.iam.v1.InternalIAMService/Check",
	"kacho.cloud.iam.v1.InternalIAMService/ListPermissions",
	"kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
	"kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
}

// TestDefaultPublicAllowlist_NoInternalFQNs (P0, RED→GREEN) — the public
// allowlist must not contain any Internal* FQN. Before the fix the 4 entries
// above were present, so an unauthenticated external caller short-circuited to
// ALLOW at decide() step 1.
func TestDefaultPublicAllowlist_NoInternalFQNs(t *testing.T) {
	got := middleware.DefaultPublicAllowlist()
	for _, fqn := range got {
		if isInternalFQN(fqn) {
			t.Errorf("DefaultPublicAllowlist contains Internal* FQN %q — must not be globally allowlisted (priv-esc)", fqn)
		}
	}
	// Explicit check for the 4 known-bad entries.
	for _, bad := range removedInternalFQNs {
		assert.NotContains(t, got, bad, "Internal* FQN must be removed from public allowlist")
	}
}

func isInternalFQN(fqn string) bool {
	// "<pkg>.<Service>/<Method>" — check the Service segment for Internal* prefix.
	slash := -1
	for i := 0; i < len(fqn); i++ {
		if fqn[i] == '/' {
			slash = i
			break
		}
	}
	if slash < 1 {
		return false
	}
	pkgSvc := fqn[:slash]
	dot := -1
	for i := len(pkgSvc) - 1; i >= 0; i-- {
		if pkgSvc[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return false
	}
	svc := pkgSvc[dot+1:]
	return len(svc) >= len("Internal") && svc[:len("Internal")] == "Internal" &&
		len(svc) >= len("Service") && svc[len(svc)-len("Service"):] == "Service"
}

// TestInternalExempt_ExternalOrigin_Unauthenticated (P0, RED→GREEN) — an
// unauthenticated call to an Internal* exempt RPC arriving on the EXTERNAL
// listener is rejected with 401 (no global allowlist bypass). Before the fix
// the allowlist short-circuit returned 200/allow with no credentials.
func TestInternalExempt_ExternalOrigin_Unauthenticated(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	rr := middleware.NewRestRouter()
	mw := buildAuthzMiddleware(t, buildCatalog(t, internalCheckExempt), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = rr
		c.Resources = middleware.NewResourceExtractor(rr.PathTemplates())
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := mw.HTTP(next)

	r := httptest.NewRequest(http.MethodPost, "/iam/v1/internal/iam:check", nil)
	r = r.WithContext(listenerorigin.WithExternal(r.Context()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.False(t, called, "external unauth Internal* call must NOT reach handler")
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"external unauth Internal* call must be 401 (no allowlist bypass)")
}

// TestInternalExempt_InternalOrigin_Allowed (P0, RED→GREEN) — the SAME
// unauthenticated call arriving on the INTERNAL listener (default origin) is
// admitted (the internal caller — gateway self-call / drainer / port-forward
// admin — carries no user JWT). This is the internal-origin gate replacing the
// removed FQN allowlist entry.
func TestInternalExempt_InternalOrigin_Allowed(t *testing.T) {
	checker := &fakeChecker{allowed: false} // must NOT be consulted on the exempt+internal path
	rr := middleware.NewRestRouter()
	mw := buildAuthzMiddleware(t, buildCatalog(t, internalCheckExempt), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = rr
		c.Resources = middleware.NewResourceExtractor(rr.PathTemplates())
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) })
	h := mw.HTTP(next)

	r := httptest.NewRequest(http.MethodPost, "/iam/v1/internal/iam:check", nil)
	// No external marker → internal origin.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.True(t, called, "internal-origin Internal* call must reach handler (internal callers keep working)")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, checker.calls.Load(), "internal-origin exempt Internal* call must not invoke FGA Check")
}

const internalCheckExempt = `{"fqn":"kacho.cloud.iam.v1.InternalIAMService/Check","permission":"<exempt>"}`

// TestInternalGated_InternalOrigin_StillChecked (regression guard) — a GATED
// Internal* RPC (catalog has required_relation, NOT <exempt>) on the INTERNAL
// listener must STILL be authorized via the FGA Check. The internal-origin gate
// only replaces the former <exempt> Internal* allowlist entries; it must never
// blanket-bypass authz for gated Internal* RPCs (e.g. InternalClusterService —
// would let an ordinary user perform cluster-admin ops).
func TestInternalGated_InternalOrigin_StillChecked(t *testing.T) {
	checker := &fakeChecker{allowed: false} // FGA denies
	rr := middleware.NewRestRouter()
	mw := buildAuthzMiddleware(t, buildCatalog(t, internalClusterGetGated), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = rr
		c.Resources = middleware.NewResourceExtractor(rr.PathTemplates())
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) })
	h := mw.HTTP(next)

	// Authenticated ordinary user, internal listener.
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/internal/cluster", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_ordinary")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	// No external marker → internal origin.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.False(t, called, "gated Internal* RPC must NOT bypass authz on internal origin")
	assert.Equal(t, http.StatusForbidden, w.Code, "gated Internal* RPC denied by FGA → 403, even on internal listener")
}

const internalClusterGetGated = `{"fqn":"kacho.cloud.iam.v1.InternalClusterService/Get","permission":"iam.cluster_admins.get","required_relation":"system_admin","scope_extractor":{"object_type":"cluster","from_request_field":"*"},"required_acr_min":"2"}`
