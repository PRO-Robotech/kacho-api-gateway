package restmux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
)

// muxAddrs — full backend address map so all Internal* routes are registered.
func muxAddrs() map[string]string {
	return map[string]string{
		"vpc":                  "127.0.0.1:1",
		"vpcInternal":          "127.0.0.1:1",
		"compute":              "127.0.0.1:1",
		"computeInternal":      "127.0.0.1:1",
		"iam":                  "127.0.0.1:1",
		"iamInternal":          "127.0.0.1:1",
		"loadbalancer":         "127.0.0.1:1",
		"loadbalancerInternal": "127.0.0.1:1",
	}
}

// internalRESTPaths — Internal* REST paths that MUST be rejected on the external
// listener (workspace CLAUDE.md §запрет #6). Mirrors the gRPC director's
// HasInternalSuffix block, applied to REST.
var internalRESTPaths = []struct{ method, path string }{
	{"POST", "/iam/v1/internal/users:upsertFromIdentity"},
	{"POST", "/iam/v1/internal/iam:check"},
	{"POST", "/iam/v1/internal/iam:lookupSubject"},
	{"GET", "/iam/v1/internal/iam/permissions"},
	{"GET", "/iam/v1/internal/cluster"},
	{"GET", "/vpc/v1/addressPools"},
	// :internal verb-suffix (InternalNetworkService.GetNetwork REST path) — the
	// real internal projection route. isInternalPath must match this too.
	{"GET", "/vpc/v1/networks/net-1:internal"},
}

// TestExternalListener_RejectsInternalPaths_404 (P0 SECURITY, RED→GREEN) — an
// Internal* REST path arriving on the EXTERNAL TLS listener must return 404
// (existence-hiding). Before the fix the dispatcher routed it to the internal
// sub-mux regardless of listener, so it was answered (route found → non-404
// downstream error).
func TestExternalListener_RejectsInternalPaths_404(t *testing.T) {
	h, err := NewMux(context.Background(), muxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}
	for _, tc := range internalRESTPaths {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// Simulate arrival on the external listener.
			req = req.WithContext(listenerorigin.WithExternal(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("Internal* path %s %s on EXTERNAL listener: got %d, want 404 (CRITICAL: internal path exposed on external endpoint)",
					tc.method, tc.path, rec.Code)
			}
		})
	}
}

// TestInternalListener_ServesInternalPaths (P0 SECURITY, RED→GREEN) — the SAME
// Internal* REST paths arriving on the INTERNAL listener (default origin, no
// marker) must remain reachable: the route is found and dispatched to the
// internal sub-mux. The backend at 127.0.0.1:1 is unreachable → a downstream
// gRPC error (NOT a route-level 404). A bare 404 here means the route was
// rejected — which would break UI / admin-tooling / port-forward / newman.
func TestInternalListener_ServesInternalPaths(t *testing.T) {
	h, err := NewMux(context.Background(), muxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}
	for _, tc := range internalRESTPaths {
		tc := tc
		t.Run("INT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// No external marker → internal origin (the default).
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("Internal* path %s %s on INTERNAL listener: got 404 — route rejected, internal callers (UI/admin/newman) broken",
					tc.method, tc.path)
			}
		})
	}
}

// TestExternalListener_PublicPathsStillServed — public REST paths on the
// external listener are unaffected (not rejected).
func TestExternalListener_PublicPathsStillServed(t *testing.T) {
	h, err := NewMux(context.Background(), muxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}
	publicPaths := []struct{ method, path string }{
		{"GET", "/vpc/v1/networks"},
		{"GET", "/iam/v1/projects/prj-1"},
		{"GET", "/compute/v1/instances"},
		{"GET", "/nlb/v1/networkLoadBalancers"},
	}
	for _, tc := range publicPaths {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = req.WithContext(listenerorigin.WithExternal(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("public path %s %s on EXTERNAL listener: got 404 — public route wrongly rejected", tc.method, tc.path)
			}
		})
	}
}
