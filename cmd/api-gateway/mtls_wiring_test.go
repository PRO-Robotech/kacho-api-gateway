// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// mtls_wiring_test.go — proves main.go's backend wiring actually consumes the
// per-edge creds (buildBackendDialCreds / loopbackDialCreds) rather than a single
// shared insecure dialOpts.
//
// dialBackends is the composition-root helper that opens one lazy ClientConn per
// backend-domain key with that key's per-edge transport creds, plus the
// always-insecure operation self-loopback. grpc.NewClient is lazy so no network
// is touched here.
package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// Default (all edges off): dialBackends builds a ClientConn for every
// BackendAddrs key plus the "operation" loopback, without error.
func TestSECE01_DialBackends_DefaultAllInsecure(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	backends, cleanup, err := dialBackends(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	for key := range cfg.BackendAddrs() {
		_, ok := backends[key]
		require.True(t, ok, "missing backend conn for %q", key)
	}
	// operation self-loopback is wired in too (Operation rewrite path).
	_, ok := backends["operation"]
	require.True(t, ok, "operation self-loopback must be wired")
}

// An enabled edge with no cert material makes dialBackends fail-fast
// (main.go log.Fatalf's on this). The process must NOT come up half-secured.
func TestSECE03_DialBackends_Enabled_MissingCert_FailFast(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")
	// cert/key/ca intentionally unset.

	cfg, err := config.Load()
	require.NoError(t, err)

	_, cleanup, err := dialBackends(cfg)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	require.Error(t, err, "enable=true with no cert material must fail-fast at wiring")
}

// Mixed profile: iam mTLS-on (full cert), vpc off. dialBackends builds every
// conn without error and the operation loopback is present (always-insecure)
// even with edges enabled.
func TestSECE07_DialBackends_MixedProfile_OK(t *testing.T) {
	cert, key, ca := writePEMTriple(t)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", cert)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", key)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", ca)
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	backends, cleanup, err := dialBackends(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	var _ proxy.Backends = backends
	_, ok := backends["operation"]
	require.True(t, ok, "operation loopback present under mTLS profile")
	_, ok = backends["iam"]
	require.True(t, ok)
}
