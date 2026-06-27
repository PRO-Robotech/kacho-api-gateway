// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestPermissionCatalog_Geo_S5_PublicReadViewer (epic kacho-geo S5) — the
// embedded permission catalog must carry the geo.v1 public read RPCs gated by the
// `viewer` relation on the cluster singleton, mirroring how compute Region/Zone
// reads were classified. The intentional `compute.regionses.list` / `zoneses.list`
// double-"es" typo is NOT carried over: geo uses `geo.regions.list` / `geo.zones.list`.
func TestPermissionCatalog_Geo_S5_PublicReadViewer(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	want := []struct {
		fqn  string
		perm string
	}{
		{"kacho.cloud.geo.v1.RegionService/Get", "geo.regions.get"},
		{"kacho.cloud.geo.v1.RegionService/List", "geo.regions.list"},
		{"kacho.cloud.geo.v1.ZoneService/Get", "geo.zones.get"},
		{"kacho.cloud.geo.v1.ZoneService/List", "geo.zones.list"},
	}
	for _, w := range want {
		t.Run(w.fqn, func(t *testing.T) {
			entry, ok := c.Lookup(w.fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", w.fqn)
			assert.Equal(t, w.perm, entry.Permission, "permission identifier on %s", w.fqn)
			assert.Equal(t, "viewer", entry.RequiredRelation, "public geo read must be viewer-gated on %s", w.fqn)
			assert.Equal(t, "cluster", entry.ScopeExtractor.ObjectType, "geo scope object_type must be cluster on %s", w.fqn)
			assert.False(t, entry.IsExempt(), "geo read must NOT be <exempt> on %s", w.fqn)
		})
	}
}

// TestPermissionCatalog_Geo_S5_InternalAdminSystemAdmin — the geo Internal* admin
// CRUD RPCs must be gated by `system_admin` on the cluster singleton, mirroring
// compute InternalZone/InternalRegion. Regressing any to viewer/<exempt> would
// let non-admins mutate the geography catalog.
func TestPermissionCatalog_Geo_S5_InternalAdminSystemAdmin(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	want := []struct {
		fqn  string
		perm string
	}{
		{"kacho.cloud.geo.v1.InternalRegionService/Create", "geo.regions.create"},
		{"kacho.cloud.geo.v1.InternalRegionService/Update", "geo.regions.update"},
		{"kacho.cloud.geo.v1.InternalRegionService/Delete", "geo.regions.delete"},
		{"kacho.cloud.geo.v1.InternalZoneService/Create", "geo.zones.create"},
		{"kacho.cloud.geo.v1.InternalZoneService/Update", "geo.zones.update"},
		{"kacho.cloud.geo.v1.InternalZoneService/Delete", "geo.zones.delete"},
	}
	for _, w := range want {
		t.Run(w.fqn, func(t *testing.T) {
			entry, ok := c.Lookup(w.fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", w.fqn)
			assert.Equal(t, w.perm, entry.Permission, "permission identifier on %s", w.fqn)
			assert.Equal(t, "system_admin", entry.RequiredRelation, "geo admin CRUD must be system_admin on %s", w.fqn)
			assert.Equal(t, "cluster", entry.ScopeExtractor.ObjectType, "geo admin scope object_type must be cluster on %s", w.fqn)
			assert.Equal(t, "*", entry.ScopeExtractor.FromRequestField, "geo admin scope from_request_field must be '*' on %s", w.fqn)
			assert.False(t, entry.IsExempt(), "geo admin CRUD must NOT be <exempt> on %s", w.fqn)
		})
	}
}

// TestRestRouter_Geo_S5_PathFQN — the REST route table must resolve geo paths to
// the right gRPC FQNs: GET /geo/v1/{regions,zones}[/{id}] → public RegionService/
// ZoneService; POST/PATCH/DELETE → InternalRegionService/InternalZoneService
// (admin CRUD share the public path, distinguished by HTTP method — same shape as
// compute today). Without these the authz middleware cannot map geo requests to
// catalog entries and every geo REST call is denied.
func TestRestRouter_Geo_S5_PathFQN(t *testing.T) {
	r := middleware.NewRestRouter()

	cases := []struct {
		method, path, fqn string
	}{
		{"GET", "/geo/v1/regions", "kacho.cloud.geo.v1.RegionService/List"},
		{"GET", "/geo/v1/regions/ru-central1", "kacho.cloud.geo.v1.RegionService/Get"},
		{"POST", "/geo/v1/regions", "kacho.cloud.geo.v1.InternalRegionService/Create"},
		{"PATCH", "/geo/v1/regions/ru-central1", "kacho.cloud.geo.v1.InternalRegionService/Update"},
		{"DELETE", "/geo/v1/regions/ru-central1", "kacho.cloud.geo.v1.InternalRegionService/Delete"},
		{"GET", "/geo/v1/zones", "kacho.cloud.geo.v1.ZoneService/List"},
		{"GET", "/geo/v1/zones/ru-central1-a", "kacho.cloud.geo.v1.ZoneService/Get"},
		{"POST", "/geo/v1/zones", "kacho.cloud.geo.v1.InternalZoneService/Create"},
		{"PATCH", "/geo/v1/zones/ru-central1-a", "kacho.cloud.geo.v1.InternalZoneService/Update"},
		{"DELETE", "/geo/v1/zones/ru-central1-a", "kacho.cloud.geo.v1.InternalZoneService/Delete"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got, ok := r.Resolve(tc.method, tc.path)
			require.True(t, ok, "no route for %s %s", tc.method, tc.path)
			assert.Equal(t, tc.fqn, got)
		})
	}
}
