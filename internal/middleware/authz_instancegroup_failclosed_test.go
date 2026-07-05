// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_instancegroup_failclosed_test.go — runtime proof that compute
// InstanceGroupService is now a first-class, permission-gated citizen of the
// authz catalog.
//
// Historical note (inverted premise): InstanceGroupService lives in its own
// proto sub-package (kacho.cloud.compute.v1.instancegroup) and USED to ship
// WITHOUT authz options, so the generated permission catalog carried no entry
// for any of its RPCs. Back then this file locked the fail-closed catalog-miss
// deny (every route denied BEFORE the IAM Check ever ran).
//
// The kacho-proto contract bump added the four `kacho.iam.authz.v1.*`
// annotations to all 23 InstanceGroupService RPCs, so the embedded catalog now
// carries a real, permission-gated entry for each. The behaviour therefore
// INVERTS: routes are no longer denied by a catalog miss — they are gated by
// normal authz. A caller lacking the permission is denied THROUGH the IAM
// Check (403, Check consulted), and a caller that the Check authorizes passes
// (200). This test asserts that new, correct behaviour.
package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// igChecker — a configurable authz decision oracle that records how many times
// the IAM Check was consulted. `allow` selects the terminal decision.
type igChecker struct {
	allow bool
	calls int
}

func (c *igChecker) Check(_ context.Context, _ AuthzCheckInput) (AuthzCheckResult, error) {
	c.calls++
	return AuthzCheckResult{Allowed: c.allow, DenyReasons: []string{"no path"}}, nil
}

func silentTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// instanceGroupRoutes returns every generated REST route whose FQN belongs to
// the compute InstanceGroupService.
func instanceGroupRoutes() []restRoute {
	var out []restRoute
	for _, rt := range generatedRestRoutes {
		if strings.Contains(rt.FQN, "instancegroup.InstanceGroupService/") {
			out = append(out, rt)
		}
	}
	return out
}

// concretePath substitutes every {placeholder} in a route template with a
// syntactically valid, well-formed resource id so the request reaches the authz
// Check (not a routing 404 and not the malformed-id short-circuit). The id uses
// a REGISTERED compute-family prefix (`b1g`) — an unregistered prefix would trip
// corevalidate.ResourceID and short-circuit to 400 before the Check phase.
func concretePath(template string) string {
	parts := strings.Split(template, "/")
	for i, seg := range parts {
		// A segment may be "{field}" or "{field}:verb".
		if strings.HasPrefix(seg, "{") {
			verb := ""
			if idx := strings.Index(seg, ":"); idx >= 0 {
				verb = seg[idx:]
			}
			parts[i] = "b1g000000000000001" + verb
		}
	}
	return strings.Join(parts, "/")
}

func newIGAuthzMiddleware(t *testing.T, catalog *PermissionCatalog, checker AuthorizeChecker) *AuthzMiddleware {
	t.Helper()
	mw, err := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enabled:         true,
		Catalog:         catalog,
		Subjects:        NewSubjectExtractor(true),
		Context:         NewContextExtractor(time.Now, true),
		Resources:       NewResourceExtractor(nil),
		Checker:         checker,
		Logger:          silentTestLogger(),
		CacheTTL:        5 * time.Second,
		CacheMaxEntries: 100,
		PublicAllowlist: DefaultPublicAllowlist(),
		RestRouter:      NewRestRouter(),
	})
	require.NoError(t, err)
	return mw
}

// authenticate stamps an authenticated principal (acr 2) on the HTTP request so
// it reaches the authz decision instead of being rejected at authentication.
func authenticate(r *http.Request) {
	r.Header.Set("X-Kacho-Principal-Id", "usr_instancegroup")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
}

// TestAuthz_InstanceGroupService_CatalogGated asserts the static catalog shape:
// every InstanceGroupService route now HAS a permission-gated catalog entry
// (the inversion of the old catalog-miss premise) and none is public.
func TestAuthz_InstanceGroupService_CatalogGated(t *testing.T) {
	routes := instanceGroupRoutes()
	require.NotEmpty(t, routes,
		"expected InstanceGroupService routes in the generated route table")

	allow := map[string]struct{}{}
	for _, fqn := range DefaultPublicAllowlist() {
		allow[fqn] = struct{}{}
	}

	catalog, err := LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	for _, rt := range routes {
		rt := rt
		t.Run(rt.FQN, func(t *testing.T) {
			// 1. Present in the catalog (was: MUST be absent).
			entry, found := catalog.Lookup(rt.FQN)
			require.True(t, found,
				"InstanceGroupService FQN %q must now carry a catalog entry (contract bump added authz options)", rt.FQN)

			// 2. Real permission gate — not exempt, fully annotated.
			require.False(t, entry.IsExempt(),
				"InstanceGroupService FQN %q must be permission-gated, not <exempt>", rt.FQN)
			require.True(t, strings.HasPrefix(entry.Permission, "compute.instanceGroups."),
				"unexpected permission %q on %q", entry.Permission, rt.FQN)
			require.NotEmpty(t, entry.RequiredRelation,
				"InstanceGroupService FQN %q must declare a required_relation", rt.FQN)
			require.NotEmpty(t, entry.ScopeExtractor.ObjectType,
				"InstanceGroupService FQN %q must declare a scope object_type", rt.FQN)
			require.NotEmpty(t, entry.ScopeExtractor.FromRequestField,
				"InstanceGroupService FQN %q must declare a scope from_request_field", rt.FQN)

			// 3. Never on the public allowlist (that would bypass authz).
			_, isPublic := allow[rt.FQN]
			require.False(t, isPublic,
				"InstanceGroupService FQN %q must be gated, not on the public allowlist", rt.FQN)
		})
	}
}

// TestAuthz_InstanceGroupService_DeniedThroughCheck drives every
// InstanceGroupService route with an authenticated principal whose IAM Check
// DENIES. The new correct behaviour: the request is denied (403) BECAUSE the
// Check said no — the Check MUST be consulted (calls > 0). Under the old
// catalog-miss premise the Check was never reached (calls == 0); that is
// exactly the regression this inversion guards against.
func TestAuthz_InstanceGroupService_DeniedThroughCheck(t *testing.T) {
	routes := instanceGroupRoutes()
	require.NotEmpty(t, routes)

	catalog, err := LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	checker := &igChecker{allow: false}
	mw := newIGAuthzMiddleware(t, catalog, checker)

	handlerReached := false
	guarded := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, rt := range routes {
		path := concretePath(rt.Template)
		r := httptest.NewRequest(rt.Method, path, nil)
		authenticate(r)
		rr := httptest.NewRecorder()
		guarded.ServeHTTP(rr, r)

		if rr.Code == http.StatusOK {
			t.Fatalf("%s %s (%s) returned 200 — a caller lacking the permission must be denied", rt.Method, path, rt.FQN)
		}
		// A denied read `Get` (v_get + concrete scope) hides existence and
		// renders as 404; every other route renders the deny as 403. Both are
		// Check-driven denials — what matters is that access is refused and the
		// Check was consulted (asserted below).
		if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s (%s) returned %d, want 403 Forbidden or 404 Not Found (denied through the IAM Check)", rt.Method, path, rt.FQN, rr.Code)
		}
	}
	if handlerReached {
		t.Fatal("downstream handler was reached — a denied InstanceGroupService request slipped past authz")
	}
	// The crux of the inversion: every route reached and consulted the IAM
	// Check (each RPC carries a distinct permission → distinct cache key → its
	// own Check). A catalog miss would have short-circuited with calls == 0.
	if checker.calls != len(routes) {
		t.Fatalf("IAM Check consulted %d times, want %d — denials must flow through normal authz, not a catalog miss",
			checker.calls, len(routes))
	}
}

// TestAuthz_InstanceGroupService_AllowedThroughCheck is the positive half: when
// the IAM Check AUTHORIZES the caller, every InstanceGroupService route passes
// (200) and reaches the downstream handler — proving the gate is a real
// permission gate that OPENS on authorization (no loss of functionality), not a
// blanket deny.
func TestAuthz_InstanceGroupService_AllowedThroughCheck(t *testing.T) {
	routes := instanceGroupRoutes()
	require.NotEmpty(t, routes)

	catalog, err := LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	checker := &igChecker{allow: true}
	mw := newIGAuthzMiddleware(t, catalog, checker)

	reached := 0
	guarded := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))

	for _, rt := range routes {
		path := concretePath(rt.Template)
		r := httptest.NewRequest(rt.Method, path, nil)
		authenticate(r)
		rr := httptest.NewRecorder()
		guarded.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s (%s) returned %d, want 200 — an authorized caller must pass the gate", rt.Method, path, rt.FQN, rr.Code)
		}
	}
	if reached != len(routes) {
		t.Fatalf("downstream handler reached %d times, want %d — authorized InstanceGroupService requests must pass through", reached, len(routes))
	}
	if checker.calls != len(routes) {
		t.Fatalf("IAM Check consulted %d times, want %d — every gated route must consult the Check", checker.calls, len(routes))
	}
}
