// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_instancegroup_failclosed_test.go — explicit runtime closure of the
// proto-authz gap for compute InstanceGroupService.
//
// InstanceGroupService lives in its own proto sub-package
// (kacho.cloud.compute.v1.instancegroup) and its RPCs are NOT annotated with
// authz options, so the generated permission catalog carries NO entry for any
// of them. The REST route table DOES resolve every InstanceGroups path to its
// FQN, so an authenticated request reaches the authz decision. Without proto
// edits (frozen wire contract) we lock the fail-closed behaviour at runtime:
// every InstanceGroupService route must be denied, must NOT be on the public
// allowlist, and must never reach the IAM Check (catalog-miss default-deny).
//
// If someone later adds these RPCs to the public allowlist, or a wildcard
// catalog entry accidentally cascades them open, THIS test fails — that is the
// point.
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

// igFailClosedChecker — records whether IAM Check was ever consulted. For a
// fail-closed catalog-miss it must stay at zero.
type igFailClosedChecker struct{ calls int }

func (c *igFailClosedChecker) Check(_ context.Context, _ AuthzCheckInput) (AuthzCheckResult, error) {
	c.calls++
	// If we ever get here, pretend the subject is allowed — this makes the test
	// STRICT: the only thing preventing access is the catalog-miss default-deny.
	return AuthzCheckResult{Allowed: true}, nil
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
// syntactically valid dummy resource id so the request reaches the authz layer
// (not a routing 404).
func concretePath(template string) string {
	parts := strings.Split(template, "/")
	for i, seg := range parts {
		// A segment may be "{field}" or "{field}:verb".
		if strings.HasPrefix(seg, "{") {
			verb := ""
			if idx := strings.Index(seg, ":"); idx >= 0 {
				verb = seg[idx:]
			}
			parts[i] = "igr0000000000000001" + verb
		}
	}
	return strings.Join(parts, "/")
}

func TestAuthz_InstanceGroupService_FailClosed(t *testing.T) {
	routes := instanceGroupRoutes()
	require.NotEmpty(t, routes,
		"expected InstanceGroupService routes in the generated route table")

	// 1. None of them may be on the public allowlist (that would bypass authz).
	allow := map[string]struct{}{}
	for _, fqn := range DefaultPublicAllowlist() {
		allow[fqn] = struct{}{}
	}
	for _, rt := range routes {
		if _, ok := allow[rt.FQN]; ok {
			t.Fatalf("InstanceGroupService FQN %q is on the public allowlist — must be gated, not public", rt.FQN)
		}
	}

	// 2. Real embedded catalog carries no InstanceGroupService entry.
	catalog, err := LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)
	for _, rt := range routes {
		if _, found := catalog.Lookup(rt.FQN); found {
			t.Fatalf("InstanceGroupService FQN %q unexpectedly present in catalog — "+
				"update this test with its gating expectation", rt.FQN)
		}
	}

	// 3. Drive the authz HTTP middleware (real catalog + real router) with an
	//    AUTHENTICATED principal whose Check would allow. Every InstanceGroups
	//    route must be denied (403) and Check must never be consulted.
	checker := &igFailClosedChecker{}
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

	handlerReached := false
	guarded := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, rt := range routes {
		path := concretePath(rt.Template)
		r := httptest.NewRequest(rt.Method, path, nil)
		// Authenticated principal (HTTP path reads these headers).
		r.Header.Set("X-Kacho-Principal-Id", "usr_failclosed")
		r.Header.Set("X-Kacho-Principal-Type", "user")
		r.Header.Set("X-Kacho-Token-Acr", "2")
		rr := httptest.NewRecorder()
		guarded.ServeHTTP(rr, r)

		if rr.Code == http.StatusOK {
			t.Fatalf("%s %s (%s) returned 200 — InstanceGroupService must be fail-closed", rt.Method, path, rt.FQN)
		}
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s (%s) returned %d, want 403 Forbidden (catalog-miss deny)", rt.Method, path, rt.FQN, rr.Code)
		}
	}
	if handlerReached {
		t.Fatal("downstream handler was reached — an InstanceGroupService request slipped past authz")
	}
	if checker.calls != 0 {
		t.Fatalf("IAM Check consulted %d times — fail-closed must deny before Check on a catalog miss", checker.calls)
	}
}
