// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package restmux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
)

// geoMuxAddrs — backend address map including the geo public + internal keys, so
// the geo public RegionService/ZoneService AND the geo InternalRegionService/
// InternalZoneService admin handlers all register (epic kacho-geo S5).
func geoMuxAddrs() map[string]string {
	return map[string]string{
		"vpc":                  "127.0.0.1:1",
		"vpcInternal":          "127.0.0.1:1",
		"compute":              "127.0.0.1:1",
		"computeInternal":      "127.0.0.1:1",
		"iam":                  "127.0.0.1:1",
		"iamInternal":          "127.0.0.1:1",
		"loadbalancer":         "127.0.0.1:1",
		"loadbalancerInternal": "127.0.0.1:1",
		"geo":                  "127.0.0.1:1",
		"geoInternal":          "127.0.0.1:1",
	}
}

// TestGeo_S5_PublicReadRoutesRegistered — the geo public read REST paths
// (GET /geo/v1/regions, /geo/v1/zones and the {id} variants) must be served on
// BOTH the external and internal listeners: a route must be found (NOT a
// route-level 404). The unreachable backend at 127.0.0.1:1 yields a downstream
// gRPC error, never a 404. A 404 means the geo public handler was not registered.
func TestGeo_S5_PublicReadRoutesRegistered(t *testing.T) {
	h, err := NewMux(context.Background(), geoMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	publicReads := []struct{ method, path string }{
		{"GET", "/geo/v1/regions"},
		{"GET", "/geo/v1/regions/ru-central1"},
		{"GET", "/geo/v1/zones"},
		{"GET", "/geo/v1/zones/ru-central1-a"},
	}
	for _, tc := range publicReads {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// External is the fail-closed default (no internal-origin marker) —
			// public reads stay served.
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("geo public read %s %s on EXTERNAL listener: got 404 — geo public route not registered (S5)",
					tc.method, tc.path)
			}
		})
	}
}

// TestGeo_S5_AdminCRUDRoutesRegistered_InternalListener — the geo admin CRUD
// REST paths (POST/PATCH/DELETE /geo/v1/regions|zones, served by the
// InternalRegionService/InternalZoneService handlers on geoInternalAddr) must be
// reachable on the internal listener: a route is found, the unreachable backend
// at 127.0.0.1:1 yields a downstream gRPC error (NOT a route-level 404). A 404
// means the geo Internal* handler was not registered on the internal mux.
func TestGeo_S5_AdminCRUDRoutesRegistered_InternalListener(t *testing.T) {
	h, err := NewMux(context.Background(), geoMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	adminCRUD := []struct{ method, path string }{
		{"POST", "/geo/v1/regions"},
		{"PATCH", "/geo/v1/regions/ru-central1"},
		{"DELETE", "/geo/v1/regions/ru-central1"},
		{"POST", "/geo/v1/zones"},
		{"PATCH", "/geo/v1/zones/ru-central1-a"},
		{"DELETE", "/geo/v1/zones/ru-central1-a"},
	}
	for _, tc := range adminCRUD {
		tc := tc
		t.Run("INT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// Explicit internal-origin marker → dedicated cluster-internal admin
			// REST listener (UI/admin/port-forward).
			req = req.WithContext(listenerorigin.WithInternal(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("geo admin CRUD %s %s on INTERNAL listener: got 404 — geo Internal* handler not registered (S5)",
					tc.method, tc.path)
			}
		})
	}
}

// TestGeo_S5_GeoInternalGuard_NoInternalAddr — when geoInternalAddr is empty the
// geo Internal* handlers must NOT be registered (graceful degrade, mirrors
// computeInternal / vpcInternal). The geo PUBLIC reads still register from the
// public geoAddr. This proves the *InternalAddr guard wraps only the Internal*
// registrations (Internal* on the internal port only).
func TestGeo_S5_GeoInternalGuard_NoInternalAddr(t *testing.T) {
	addrs := geoMuxAddrs()
	addrs["geoInternal"] = "" // internal backend absent

	h, err := NewMux(context.Background(), addrs, nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	// Public read still registers (served from geoAddr).
	req := httptest.NewRequest("GET", "/geo/v1/regions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("geo public read GET /geo/v1/regions: got 404 with empty geoInternalAddr — public must still register")
	}

	// Admin CRUD (the mutating verbs) come ONLY from the Internal* handler. With
	// geoInternalAddr empty that handler is NOT registered, so POST on the shared
	// /geo/v1/regions path is unhandled. The public ZoneService/RegionService only
	// registers GET on this path, so grpc-gateway answers 501 Not Implemented
	// (method not registered) — NOT a served response. This is identical to how
	// compute behaves with an empty computeInternalAddr (POST /compute/v1/zones →
	// 501). The invariant under test: without the internal backend the admin write
	// handler does not come up (Internal* only via the *InternalAddr block).
	req = httptest.NewRequest("POST", "/geo/v1/regions", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusServiceUnavailable {
		t.Errorf("geo admin POST /geo/v1/regions with empty geoInternalAddr: got %d — Internal* write handler must NOT be registered without geoInternalAddr", rec.Code)
	}
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("geo admin POST /geo/v1/regions with empty geoInternalAddr: got %d, want 501 Not Implemented (mutating verb has no registered handler)", rec.Code)
	}
}
