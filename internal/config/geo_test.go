// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
	// geo cutover: the kacho-geo k8s Service is "kacho-geo" (NOT "geo") — the bare
	// "geo.kacho.svc.cluster.local" host does NOT resolve (NXDOMAIN) → the grpc
	// resolver returns no addresses → "no children to pick from" 503 on every
	// /geo/v1/* request. The default MUST be the real Service name.
	require.Equal(t, "kacho-geo.kacho.svc.cluster.local:9090", geo,
		"geo public backend default addr must target the kacho-geo Service")

	geoInternal, ok := addrs["geoInternal"]
	require.True(t, ok, "BackendAddrs must contain a \"geoInternal\" key (internal :9091)")
	// The internal listener is a separate Service: kacho-geo-internal (mirrors
	// kacho-iam-internal / the iamInternal edge).
	require.Equal(t, "kacho-geo-internal.kacho.svc.cluster.local:9091", geoInternal,
		"geo internal backend default addr must target the kacho-geo-internal Service")
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

	tc, berr := cfg.EdgeTLSClient("geo", "kacho-geo.kacho.svc.cluster.local:9090")
	require.NoError(t, berr, "geo edge must build without error (default disabled)")
	require.False(t, tc.Enable, "geo edge must be insecure by default")
}

// TestGeo_Cutover_GeoMTLSEdge_ServerNameDerivesFromHost — when the geo edge is
// ENABLED, EdgeTLSClient must yield TLS creds whose ServerName (SNI) is the
// kacho-geo dial-host (NOT insecure, NOT the stale "geo.kacho.*" host). The geo
// public listener runs RequireAndVerifyClientCert in dev, so an insecure dial or
// a wrong-SAN SNI fails the handshake → the same 503. ServerName is derived from
// the dial-host (MTLSGeoServerName left empty, mirroring the iam/nlb edges) so
// both kacho-geo (public) and kacho-geo-internal (internal) verify against their
// own SAN.
func TestGeo_Cutover_GeoMTLSEdge_ServerNameDerivesFromHost(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", "/etc/api-gateway/mtls/tls.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", "/etc/api-gateway/mtls/tls.key")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", "/etc/api-gateway/mtls/ca.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_GEO_ENABLE", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	addrs := cfg.BackendAddrs()

	// Public geo edge → SNI = kacho-geo.kacho.svc.cluster.local.
	pub, perr := cfg.EdgeTLSClient("geo", addrs["geo"])
	require.NoError(t, perr)
	require.True(t, pub.Enable, "enabled geo edge must produce TLS creds, not insecure")
	require.Equal(t, "kacho-geo.kacho.svc.cluster.local", pub.ServerName,
		"geo public SNI must match the kacho-geo server-cert SAN (not insecure, not geo.kacho.*)")

	// Internal geo edge → SNI = kacho-geo-internal.kacho.svc.cluster.local.
	internal, ierr := cfg.EdgeTLSClient("geo", addrs["geoInternal"])
	require.NoError(t, ierr)
	require.True(t, internal.Enable, "enabled geoInternal edge must produce TLS creds")
	require.Equal(t, "kacho-geo-internal.kacho.svc.cluster.local", internal.ServerName,
		"geo internal SNI must match the kacho-geo-internal server-cert SAN")
}
