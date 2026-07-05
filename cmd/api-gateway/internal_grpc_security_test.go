// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_grpc_security_test.go — unit tests for the cluster-internal gRPC
// listener security wiring: fail-fast config validation, the production guard
// that forbids an insecure internal listener in a production-class env, and the
// reflection debug-gate.
package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// mTLS enabled with NO server cert material must fail-fast (never a silent
// insecure fallback — the process must not come up half-secured).
func TestInternalListenerSecurity_Enabled_MissingCert_FailFast(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_MTLS_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_ALLOWED_SPIFFE", iamDrainerSPIFFE)
	// cert/key/ca intentionally unset.
	cfg, err := config.Load()
	require.NoError(t, err)

	_, err = buildInternalListenerSecurity(cfg)
	require.Error(t, err, "enable=true with no server cert/key/ca must fail-fast")
}

// mTLS enabled with cert material but an EMPTY caller allow-list must fail-fast —
// an mTLS listener that authorises every verified peer is still a cache-flush DoS
// surface for any in-cluster module holding a valid mesh cert.
func TestInternalListenerSecurity_Enabled_EmptyAllowlist_FailFast(t *testing.T) {
	cert, key, ca := writePEMTriple(t) // valid loadable PEM material
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_MTLS_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_TLS_CERT_FILE", cert)
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_TLS_KEY_FILE", key)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", ca)
	// allow-list intentionally unset.
	cfg, err := config.Load()
	require.NoError(t, err)

	_, err = buildInternalListenerSecurity(cfg)
	require.Error(t, err, "enable=true with an empty SPIFFE allow-list must fail-fast")
}

// Disabled (default) → insecure posture, no error, reflection off by default.
func TestInternalListenerSecurity_Disabled_Default(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	sec, err := buildInternalListenerSecurity(cfg)
	require.NoError(t, err)
	require.False(t, sec.mtlsEnabled, "default is insecure (dev/local opt-in)")
	require.Nil(t, sec.serverCreds)
	require.False(t, sec.reflection, "reflection must default OFF (debug gate)")
}

// The reflection debug-gate propagates from config.
func TestInternalListenerSecurity_ReflectionGate(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_REFLECTION", "true")
	cfg, err := config.Load()
	require.NoError(t, err)

	sec, err := buildInternalListenerSecurity(cfg)
	require.NoError(t, err)
	require.True(t, sec.reflection, "reflection flag must propagate when enabled")
}

// The production guard: an insecure internal listener is refused in a
// production-class env (empty/unset label is production-class, secure-by-default),
// tolerated only in the explicit dev-class labels.
func TestValidateProductionInternalListener(t *testing.T) {
	cases := []struct {
		name        string
		env         string
		mtlsEnabled bool
		wantErr     bool
	}{
		{"prod-insecure-refused", "prod", false, true},
		{"production-insecure-refused", "production", false, true},
		{"staging-insecure-refused", "staging", false, true},
		{"empty-env-insecure-refused", "", false, true},
		{"typo-env-insecure-refused", "prd", false, true},
		{"prod-mtls-ok", "prod", true, false},
		{"dev-insecure-ok", "dev", false, false},
		{"local-insecure-ok", "local", false, false},
		{"test-insecure-ok", "test", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProductionInternalListener(tc.env, tc.mtlsEnabled)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
