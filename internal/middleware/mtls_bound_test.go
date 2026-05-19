package middleware_test

// mtls_bound_test.go — RFC 8705 thumbprint matcher.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func generateSelfSignedCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func certThumb(cert *x509.Certificate) string {
	s := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func TestMTLS_HappyPath(t *testing.T) {
	cert := generateSelfSignedCert(t, "sva_ci.kacho.cloud")
	tok := &middleware.VerifiedToken{
		Cnf: middleware.TokenConfirmation{HasX5tS: true, X5tS256: certThumb(cert)},
	}
	v := middleware.NewMTLSBoundValidator()
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	assert.NoError(t, v.Validate(tok, state, nil))
}

func TestMTLS_MissingClientCert(t *testing.T) {
	tok := &middleware.VerifiedToken{
		Cnf: middleware.TokenConfirmation{HasX5tS: true, X5tS256: "any"},
	}
	v := middleware.NewMTLSBoundValidator()
	state := &tls.ConnectionState{} // no PeerCertificates
	err := v.Validate(tok, state, nil)
	assert.ErrorIs(t, err, middleware.ErrMTLSCertMissing)

	// nil connState — same.
	err = v.Validate(tok, nil, nil)
	assert.ErrorIs(t, err, middleware.ErrMTLSCertMissing)
}

func TestMTLS_ThumbprintMismatch(t *testing.T) {
	certA := generateSelfSignedCert(t, "A")
	certB := generateSelfSignedCert(t, "B")
	tok := &middleware.VerifiedToken{
		Cnf: middleware.TokenConfirmation{HasX5tS: true, X5tS256: certThumb(certA)},
	}
	v := middleware.NewMTLSBoundValidator()
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certB}}
	err := v.Validate(tok, state, nil)
	assert.ErrorIs(t, err, middleware.ErrMTLSThumbMismatch)
}

func TestMTLS_NonBoundTokenSkipsCheck(t *testing.T) {
	tok := &middleware.VerifiedToken{Cnf: middleware.TokenConfirmation{IsBearer: true}}
	v := middleware.NewMTLSBoundValidator()
	assert.NoError(t, v.Validate(tok, nil, nil))
}

func TestMTLS_ExplicitCertParamAccepted(t *testing.T) {
	cert := generateSelfSignedCert(t, "explicit")
	tok := &middleware.VerifiedToken{
		Cnf: middleware.TokenConfirmation{HasX5tS: true, X5tS256: certThumb(cert)},
	}
	v := middleware.NewMTLSBoundValidator()
	// Pass cert via explicit param (no TLS conn state).
	assert.NoError(t, v.Validate(tok, nil, cert))
}
