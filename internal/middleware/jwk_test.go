// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// jwk_test.go — unit tests for jwk.go (RFC 7517 / 7638).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestJWK_RSAPublicKey_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := rsaToJWK(t, &priv.PublicKey)

	pub, err := jwk.PublicKey()
	require.NoError(t, err)

	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.N.Cmp(rsaPub.N), 0)
	assert.Equal(t, priv.PublicKey.E, rsaPub.E)
}

func TestJWK_ECDSAPublicKey_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := ecdsaToJWK(t, &priv.PublicKey)

	pub, err := jwk.PublicKey()
	require.NoError(t, err)

	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.X.Cmp(ecPub.X), 0)
	assert.Equal(t, priv.PublicKey.Y.Cmp(ecPub.Y), 0)
}

func TestJWK_Ed25519PublicKey_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk := ed25519ToJWK(t, pub)

	got, err := jwk.PublicKey()
	require.NoError(t, err)
	edPub, ok := got.(ed25519.PublicKey)
	require.True(t, ok)
	assert.True(t, edPub.Equal(pub))
}

func TestJWK_Thumbprint_RSA_Stable(t *testing.T) {
	// RFC 7638 section 3.1 example uses RSA — compute and assert non-empty +
	// 43 chars (SHA-256 → 256 bits → 32 bytes → base64url-no-pad → 43 chars).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := rsaToJWK(t, &priv.PublicKey)

	thumb, err := jwk.Thumbprint()
	require.NoError(t, err)
	assert.Len(t, thumb, 43, "RSA thumbprint must be 43 base64url-no-pad chars")

	// Second call must be identical (deterministic).
	thumb2, err := jwk.Thumbprint()
	require.NoError(t, err)
	assert.Equal(t, thumb, thumb2)
}

func TestJWK_Thumbprint_EC_Stable(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := ecdsaToJWK(t, &priv.PublicKey)

	thumb, err := jwk.Thumbprint()
	require.NoError(t, err)
	assert.Len(t, thumb, 43)
}

func TestJWK_Thumbprint_Ed25519_Stable(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk := ed25519ToJWK(t, pub)

	thumb, err := jwk.Thumbprint()
	require.NoError(t, err)
	assert.Len(t, thumb, 43)
}

func TestJWK_InvalidKty_Rejected(t *testing.T) {
	jwk := &middleware.JWK{Kty: "unknown"}
	_, err := jwk.PublicKey()
	assert.ErrorIs(t, err, middleware.ErrUnsupportedAlg)

	_, err = jwk.Thumbprint()
	assert.ErrorIs(t, err, middleware.ErrUnsupportedAlg)
}

func TestJWK_MissingFields_Rejected(t *testing.T) {
	// RSA without N → invalid.
	jwk := &middleware.JWK{Kty: "RSA", E: "AQAB"}
	_, err := jwk.Thumbprint()
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)
	_, err = jwk.PublicKey()
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)

	// EC without Y.
	jwk = &middleware.JWK{Kty: "EC", Crv: "P-256", X: "abc"}
	_, err = jwk.Thumbprint()
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)
	_, err = jwk.PublicKey()
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)

	// OKP without X.
	jwk = &middleware.JWK{Kty: "OKP", Crv: "Ed25519"}
	_, err = jwk.Thumbprint()
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)
	_, err = jwk.PublicKey()
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)
}

func TestJWK_EC_OffCurve_Rejected(t *testing.T) {
	// Synthetic JWK with invalid (off-curve) point — set both X and Y to 1.
	one := base64.RawURLEncoding.EncodeToString([]byte{1})
	jwk := &middleware.JWK{Kty: "EC", Crv: "P-256", X: one, Y: one}
	_, err := jwk.PublicKey()
	require.Error(t, err)
	assert.ErrorIs(t, err, middleware.ErrInvalidJWK)
}

func TestJWK_FindByKid(t *testing.T) {
	set := &middleware.JWKSet{Keys: []middleware.JWK{
		{Kid: "k1", Kty: "RSA"},
		{Kid: "k2", Kty: "EC"},
	}}
	k, err := set.FindByKid("k2")
	require.NoError(t, err)
	assert.Equal(t, "EC", k.Kty)

	_, err = set.FindByKid("missing")
	assert.ErrorIs(t, err, middleware.ErrKeyNotFound)

	// Empty kid is allowed only with single-key set.
	_, err = set.FindByKid("")
	assert.ErrorIs(t, err, middleware.ErrKeyNotFound, "ambiguous empty-kid in multi-key set must be rejected")
}

func TestJWK_FindByKid_SingleKeySet_AllowsEmptyKid(t *testing.T) {
	set := &middleware.JWKSet{Keys: []middleware.JWK{
		{Kty: "RSA"},
	}}
	k, err := set.FindByKid("")
	require.NoError(t, err)
	assert.Equal(t, "RSA", k.Kty)
}

func TestJWK_AlgForJWT_DerivesFromKty(t *testing.T) {
	cases := []struct {
		name string
		jwk  middleware.JWK
		want string
	}{
		{"RSA implicit", middleware.JWK{Kty: "RSA"}, middleware.AlgRS256},
		{"EC P-256", middleware.JWK{Kty: "EC", Crv: "P-256"}, middleware.AlgES256},
		{"OKP Ed25519", middleware.JWK{Kty: "OKP", Crv: "Ed25519"}, middleware.AlgEdDSA},
		{"explicit alg", middleware.JWK{Kty: "RSA", Alg: "RS512"}, "RS512"},
		{"EC unknown crv", middleware.JWK{Kty: "EC", Crv: "P-521"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.jwk.AlgForJWT())
		})
	}
}

func TestParseJWKHeader_Validates(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := ecdsaToJWK(t, &priv.PublicKey)
	raw, err := json.Marshal(jwk)
	require.NoError(t, err)

	parsed, err := middleware.ParseJWKHeader(raw)
	require.NoError(t, err)
	assert.Equal(t, "EC", parsed.Kty)

	_, err = middleware.ParseJWKHeader(nil)
	assert.Error(t, err)

	_, err = middleware.ParseJWKHeader([]byte(`{"x":"abc"}`)) // missing kty
	assert.Error(t, err)
}

// -- helpers ---------------------------------------------------------------

func rsaToJWK(t *testing.T, pub *rsa.PublicKey) *middleware.JWK {
	t.Helper()
	nBytes := pub.N.Bytes()
	eBytes := bigEndianFromInt(pub.E)
	return &middleware.JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func ecdsaToJWK(t *testing.T, pub *ecdsa.PublicKey) *middleware.JWK {
	t.Helper()
	// Pad to curve byte length (P-256 = 32).
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(x):], x)
	copy(yPadded[byteLen-len(y):], y)
	return &middleware.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

func ed25519ToJWK(t *testing.T, pub ed25519.PublicKey) *middleware.JWK {
	t.Helper()
	return &middleware.JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func bigEndianFromInt(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	return out
}

// Smoke: invalid base64 in N → ErrInvalidJWK.
func TestJWK_InvalidBase64(t *testing.T) {
	jwk := &middleware.JWK{Kty: "RSA", N: "!@#$%^", E: "AQAB"}
	_, err := jwk.PublicKey()
	require.Error(t, err)
	if !errors.Is(err, middleware.ErrInvalidJWK) {
		t.Errorf("expected ErrInvalidJWK, got %v", err)
	}
}
