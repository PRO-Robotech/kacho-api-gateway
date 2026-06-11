// mtls_test.go — SEC-E unit tests for the per-edge backend-dial mTLS config
// contract (acceptance §1.1, §3.1/§3.2/§3.3). RED-first per superpowers TDD.
//
// The config layer owns: parsing the per-edge MTLS_*_ENABLE flags + shared
// client cert/key/ca + per-edge SERVER_NAME override, and assembling the
// corelib grpcclient.TLSClient value-struct for a given backend edge. Fail-fast
// (enable=true with no cert material) is surfaced as an error from the builder,
// never a silent insecure fallback.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// SEC-E-01 — all MTLS_*_ENABLE default false; cert/key/ca empty → every edge
// resolves to a DISABLED (insecure) TLSClient. Backward-compat with current dev.
func TestSECE01_MTLS_DefaultDisabled_AllEdgesInsecure(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	for _, edge := range []string{"vpc", "compute", "iam", "nlb"} {
		tc, berr := cfg.EdgeTLSClient(edge, "x.kacho.svc.cluster.local:9090")
		require.NoError(t, berr, "edge %s default must build without error", edge)
		require.False(t, tc.Enable, "edge %s must be insecure by default (SEC-E-01)", edge)
	}
}

// SEC-E-02 — MTLS_IAM_ENABLE=true with full cert material → iam edge builds an
// ENABLED TLSClient carrying cert/key/ca; other edges remain disabled.
func TestSECE02_MTLS_IAMEnabled_FullCert_BuildsEnabled(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", "/etc/mtls/client.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", "/etc/mtls/client.key")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", "/etc/mtls/ca.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	iam, err := cfg.EdgeTLSClient("iam", "iam.kacho.svc.cluster.local:9091")
	require.NoError(t, err)
	require.True(t, iam.Enable)
	require.Equal(t, "/etc/mtls/client.crt", iam.CertFile)
	require.Equal(t, "/etc/mtls/client.key", iam.KeyFile)
	require.Equal(t, []string{"/etc/mtls/ca.crt"}, iam.CAFiles)
	// server_name derived from the dial host when no per-edge override is set.
	require.Equal(t, "iam.kacho.svc.cluster.local", iam.ServerName)

	// vpc/compute/nlb flags still false → disabled.
	for _, edge := range []string{"vpc", "compute", "nlb"} {
		tc, berr := cfg.EdgeTLSClient(edge, "x.kacho.svc.cluster.local:9090")
		require.NoError(t, berr)
		require.False(t, tc.Enable, "edge %s must stay insecure (SEC-E-02)", edge)
	}
}

// SEC-E-03 — MTLS_IAM_ENABLE=true but cert/key/ca empty → builder returns an
// error (fail-fast), NOT a disabled insecure TLSClient. This is the contract
// guarantee: "enabled without material → process must not start", never silent
// degradation to insecure.
func TestSECE03_MTLS_Enabled_MissingCert_FailFast(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")
	// cert/key/ca intentionally unset.

	cfg, err := config.Load()
	require.NoError(t, err)

	_, berr := cfg.EdgeTLSClient("iam", "iam.kacho.svc.cluster.local:9091")
	require.Error(t, berr, "enable=true with no cert material must fail-fast, not fall back to insecure")
	require.Contains(t, berr.Error(), "iam")
}

// SEC-E-03b — half-set material (cert present, key/ca missing) also fail-fast.
func TestSECE03b_MTLS_Enabled_PartialCert_FailFast(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", "/etc/mtls/client.crt")
	// key + ca intentionally unset.
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	_, berr := cfg.EdgeTLSClient("vpc", "vpc.kacho.svc.cluster.local:9090")
	require.Error(t, berr, "enable=true with partial cert material must fail-fast")
}

// SEC-E-09 — per-edge independence: iam enabled, vpc disabled in one process.
func TestSECE09_MTLS_PerEdgeSelection(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", "/etc/mtls/client.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", "/etc/mtls/client.key")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", "/etc/mtls/ca.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "false")

	cfg, err := config.Load()
	require.NoError(t, err)

	iam, err := cfg.EdgeTLSClient("iam", "iam.kacho.svc.cluster.local:9090")
	require.NoError(t, err)
	require.True(t, iam.Enable)

	vpc, err := cfg.EdgeTLSClient("vpc", "vpc.kacho.svc.cluster.local:9090")
	require.NoError(t, err)
	require.False(t, vpc.Enable)
}

// SEC-E (OQ-SEC-E-2) — per-edge SERVER_NAME override wins over host-derive.
func TestSECE_PerEdgeServerNameOverride(t *testing.T) {
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", "/etc/mtls/client.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", "/etc/mtls/client.key")
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", "/etc/mtls/ca.crt")
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_SERVER_NAME", "spiffe-host.kacho.internal")

	cfg, err := config.Load()
	require.NoError(t, err)

	vpc, err := cfg.EdgeTLSClient("vpc", "vpc.kacho.svc.cluster.local:9090")
	require.NoError(t, err)
	require.True(t, vpc.Enable)
	require.Equal(t, "spiffe-host.kacho.internal", vpc.ServerName, "explicit override must win over host-derive")
}

// SEC-E — unknown edge key is a programming error → builder rejects it.
func TestSECE_UnknownEdge_Rejected(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)
	_, berr := cfg.EdgeTLSClient("bogus", "x:9090")
	require.Error(t, berr)
}
