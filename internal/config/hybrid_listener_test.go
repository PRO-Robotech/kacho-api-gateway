package config_test

// hybrid_listener_test.go — SEC-K hybrid external listener config gating.
//
// The external TLS listener (KACHO_API_GATEWAY_TLS_LISTEN_ADDR) must support an
// OPTIONAL client cert: tls.VerifyClientCertIfGiven with the internal CA as the
// client-CA pool. A browser (no cert) handshakes and goes the JWT path; a client
// presenting a valid Kachō cert is verified so the AuthInterceptor can derive a
// principal from the SPIFFE SAN. Internal service listeners stay strict and are
// untouched.
//
// Default (hybrid disabled) ⇒ ClientAuth=NoClientCert, no ClientCAs — identical
// to the current behaviour. Enabled requires the CA file to be present
// (fail-fast on missing material).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// writeTestCAFile generates an ephemeral CA cert PEM and writes it to a temp
// file, returning the path. Nothing committed; in-memory at test time.
func writeTestCAFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "kacho-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(p, pemBytes, 0o600))
	return p
}

// SEC-K-01: hybrid disabled (default) ⇒ listener TLS config keeps NoClientCert,
// no ClientCAs. Default behaviour unchanged.
func TestSECK01_HybridDisabled_NoClientAuth(t *testing.T) {
	cfg := config.Config{}
	assert.False(t, cfg.HybridMTLSEnabled())

	tlsCfg, err := cfg.ExternalListenerClientAuth(&tls.Config{})
	require.NoError(t, err)
	assert.Equal(t, tls.NoClientCert, tlsCfg.ClientAuth)
	assert.Nil(t, tlsCfg.ClientCAs)
}

// SEC-K-02: hybrid enabled + CA present ⇒ VerifyClientCertIfGiven + ClientCAs
// populated from the internal CA.
func TestSECK02_HybridEnabled_VerifyClientCertIfGiven(t *testing.T) {
	caFile := writeTestCAFile(t)
	cfg := config.Config{
		HybridMTLSExternal: true,
		MTLSCAFile:         caFile,
	}
	assert.True(t, cfg.HybridMTLSEnabled())

	tlsCfg, err := cfg.ExternalListenerClientAuth(&tls.Config{})
	require.NoError(t, err)
	assert.Equal(t, tls.VerifyClientCertIfGiven, tlsCfg.ClientAuth)
	require.NotNil(t, tlsCfg.ClientCAs)
}

// SEC-K-03: hybrid enabled but CA file missing ⇒ fail-fast (no silent fallback
// to a listener that cannot verify any client cert).
func TestSECK03_HybridEnabled_MissingCA_FailFast(t *testing.T) {
	cfg := config.Config{
		HybridMTLSExternal: true,
		MTLSCAFile:         "",
	}
	assert.True(t, cfg.HybridMTLSEnabled())

	_, err := cfg.ExternalListenerClientAuth(&tls.Config{})
	require.Error(t, err)
}
