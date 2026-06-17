// geo_test.go — epic kacho-geo S5: the gateway must carry a geo backend (public
// :9090 + internal :9091) so REST clients reach geo.v1 RegionService/ZoneService
// and the cluster-internal InternalRegionService/InternalZoneService admin CRUD.
//
// Mirrors the compute/nlb backend wiring: BackendAddrs() exposes the "geo" /
// "geoInternal" keys (parsed by the gRPC director's domain-prefix routing and the
// REST mux's *InternalAddr block), and the "geo" mTLS edge resolves like the
// other edges.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// TestGeo_S5_BackendAddrs_HasGeoKeys — config.BackendAddrs() must contain the
// "geo" and "geoInternal" keys with the conventional defaults so the director
// (domain-prefix routing) and REST mux (Internal* on internal port) resolve geo.
func TestGeo_S5_BackendAddrs_HasGeoKeys(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	addrs := cfg.BackendAddrs()

	geo, ok := addrs["geo"]
	require.True(t, ok, "BackendAddrs must contain a \"geo\" key (public :9090)")
	require.Equal(t, "geo.kacho.svc.cluster.local:9090", geo,
		"geo public backend default addr")

	geoInternal, ok := addrs["geoInternal"]
	require.True(t, ok, "BackendAddrs must contain a \"geoInternal\" key (internal :9091)")
	require.Equal(t, "geo.kacho.svc.cluster.local:9091", geoInternal,
		"geo internal backend default addr")
}

// TestGeo_S5_GeoEnvOverride — the geo backend addresses are env-configurable
// (KACHO_API_GATEWAY_GEO_GRPC / _GEO_INTERNAL_GRPC).
func TestGeo_S5_GeoEnvOverride(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_GEO_GRPC", "geo-test:7070")
	t.Setenv("KACHO_API_GATEWAY_GEO_INTERNAL_GRPC", "geo-test:7071")

	cfg, err := config.Load()
	require.NoError(t, err)

	addrs := cfg.BackendAddrs()
	require.Equal(t, "geo-test:7070", addrs["geo"])
	require.Equal(t, "geo-test:7071", addrs["geoInternal"])
}

// TestGeo_S5_GeoMTLSEdge — the "geo" mTLS edge resolves (disabled by default,
// like every other edge) so buildBackendDialCreds can map geo / geoInternal
// backend keys to a per-edge transport. An unknown edge would error.
func TestGeo_S5_GeoMTLSEdge(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	tc, berr := cfg.EdgeTLSClient("geo", "geo.kacho.svc.cluster.local:9090")
	require.NoError(t, berr, "geo edge must build without error (default disabled)")
	require.False(t, tc.Enable, "geo edge must be insecure by default")
}
