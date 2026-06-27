// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// mtls_config_test.go — cmd-level tests for the per-edge backend-dial creds
// selection.
//
// The cmd layer owns: mapping each backend-domain key (vpc/vpcInternal/compute/
// …) to its mTLS edge, building per-edge dial credentials (TLS vs insecure),
// fail-fast on misconfig, and keeping the opsLoopback edge always insecure.
package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// fullCertEnv sets the shared client cert/key/ca env so an enabled edge can
// build TLS creds. Paths point at ephemeral PEM written by the caller.
func fullCertEnv(t *testing.T, cert, key, ca string) {
	t.Helper()
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", cert)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", key)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", ca)
}

// All flags default false → every backend conn (incl. internal-ports +
// iam-subject + iam-authorize) resolves to an insecure dial-option.
// buildBackendDialCreds must return one entry per backend key and not error.
func TestSECE01_BuildBackendDialCreds_DefaultAllInsecure(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	creds, err := buildBackendDialCreds(cfg)
	require.NoError(t, err)

	for key := range cfg.BackendAddrs() {
		opt, ok := creds[key]
		require.True(t, ok, "missing dial-creds for backend %q", key)
		require.NotNil(t, opt, "nil dial-creds for backend %q", key)
		require.False(t, edgeTLSEnabledFor(t, cfg, key), "backend %q must be insecure by default", key)
	}
}

// MTLS_IAM_ENABLE=true + full cert material → iam/iamInternal edges are
// TLS-enabled; vpc/compute/nlb edges stay insecure. Process builds without
// error.
func TestSECE02_BuildBackendDialCreds_IAMEnabled_FullCert(t *testing.T) {
	cert, key, ca := writePEMTriple(t)
	fullCertEnv(t, cert, key, ca)
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	creds, err := buildBackendDialCreds(cfg)
	require.NoError(t, err)
	require.NotNil(t, creds["iam"])
	require.NotNil(t, creds["iamInternal"])

	require.True(t, edgeTLSEnabledFor(t, cfg, "iam"))
	require.True(t, edgeTLSEnabledFor(t, cfg, "iamInternal"))
	require.False(t, edgeTLSEnabledFor(t, cfg, "vpc"))
	require.False(t, edgeTLSEnabledFor(t, cfg, "compute"))
	require.False(t, edgeTLSEnabledFor(t, cfg, "loadbalancer"))
}

// MTLS_IAM_ENABLE=true with NO cert material → buildBackendDialCreds returns
// an error mentioning the edge (fail-fast), NOT a silent insecure fallback.
// main.go log.Fatalf's on this — the process must not start.
func TestSECE03_BuildBackendDialCreds_Enabled_MissingCert_FailFast(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")
	// cert/key/ca intentionally unset.

	cfg, err := config.Load()
	require.NoError(t, err)

	_, berr := buildBackendDialCreds(cfg)
	require.Error(t, berr, "enable=true with no cert material must fail-fast")
	require.True(t, strings.Contains(berr.Error(), "iam"),
		"error should name the offending edge, got: %v", berr)
}

// Per-edge independence: iam TLS-on, vpc TLS-off in one process, built
// atomically without error.
func TestSECE09_BuildBackendDialCreds_PerEdgeSelection(t *testing.T) {
	cert, key, ca := writePEMTriple(t)
	fullCertEnv(t, cert, key, ca)
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "false")

	cfg, err := config.Load()
	require.NoError(t, err)

	creds, err := buildBackendDialCreds(cfg)
	require.NoError(t, err)
	require.NotNil(t, creds["iam"])
	require.NotNil(t, creds["vpc"])
	require.True(t, edgeTLSEnabledFor(t, cfg, "iam"))
	require.False(t, edgeTLSEnabledFor(t, cfg, "vpc"))
}

// edgeTLSEnabledFor resolves the edge for a backend key and reports whether its
// TLSClient is enabled. Helper so the assertions read against the config
// contract rather than a private creds map.
func edgeTLSEnabledFor(t *testing.T, cfg config.Config, backendKey string) bool {
	t.Helper()
	edge := backendEdge(backendKey)
	addr := cfg.BackendAddrs()[backendKey]
	tc, err := cfg.EdgeTLSClient(edge, addr)
	require.NoError(t, err)
	return tc.Enable
}
