package middleware_test

// jwt_verifier_test.go — covers RFC 8725-hardened JWT verifier.
//
// Strategy: spin up an httptest server that serves a fresh JWKS document
// signed by a test key; mint tokens with golang-jwt; assert positive +
// negative scenarios (10+ cases per acceptance §6.4).

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

const (
	testIssuer   = "https://hydra.api.kacho.cloud"
	testAudience = "https://api.kacho.cloud"
)

// jwksFixture spins up an httptest server publishing a single signing key
// with the given alg. Returns the JWKS URL + the signing key (private) +
// the kid.
type jwksFixture struct {
	url       string
	server    *httptest.Server
	priv      any // *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
	alg       string
	kid       string
	hitCount  int32
	overrides func(w http.ResponseWriter, r *http.Request) bool // override for failure injection
}

func newJWKSFixture(t *testing.T, alg string) *jwksFixture {
	t.Helper()
	fix := &jwksFixture{alg: alg, kid: "test-kid-" + alg}
	var jwkPub middleware.JWK
	switch alg {
	case "RS256":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		fix.priv = priv
		jwkPub = middleware.JWK{
			Kty: "RSA", Alg: alg, Kid: fix.kid,
			N: b64u(priv.PublicKey.N.Bytes()),
			E: b64u(bigEndianFromInt(priv.PublicKey.E)),
		}
	case "ES256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		fix.priv = priv
		x := priv.PublicKey.X.Bytes()
		y := priv.PublicKey.Y.Bytes()
		xPadded := make([]byte, 32)
		yPadded := make([]byte, 32)
		copy(xPadded[32-len(x):], x)
		copy(yPadded[32-len(y):], y)
		jwkPub = middleware.JWK{
			Kty: "EC", Alg: alg, Kid: fix.kid, Crv: "P-256",
			X: b64u(xPadded), Y: b64u(yPadded),
		}
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		fix.priv = priv
		jwkPub = middleware.JWK{
			Kty: "OKP", Alg: alg, Kid: fix.kid, Crv: "Ed25519",
			X: b64u(pub),
		}
	default:
		t.Fatalf("unsupported alg %q", alg)
	}
	set := middleware.JWKSet{Keys: []middleware.JWK{jwkPub}}
	body, _ := json.Marshal(set)
	fix.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fix.overrides != nil && fix.overrides(w, r) {
			return
		}
		atomic.AddInt32(&fix.hitCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	fix.url = fix.server.URL + "/.well-known/jwks.json"
	t.Cleanup(fix.server.Close)
	return fix
}

func (f *jwksFixture) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	var method jwt.SigningMethod
	switch f.alg {
	case "RS256":
		method = jwt.SigningMethodRS256
	case "ES256":
		method = jwt.SigningMethodES256
	case "EdDSA":
		method = jwt.SigningMethodEdDSA
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = f.kid
	s, err := tok.SignedString(f.priv)
	require.NoError(t, err)
	return s
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func standardClaims() jwt.MapClaims {
	now := time.Now().Unix()
	return jwt.MapClaims{
		"iss": testIssuer,
		"aud": []any{testAudience},
		"sub": "usr_alice_acc_a1b2",
		"jti": "01HZQ8M5J7QTAEXAMPLEUUIDV7",
		"iat": now,
		"nbf": now,
		"exp": now + 900,
		"acr": "2",
		"amr": []any{"webauthn"},
	}
}

// --- Scenarios ------------------------------------------------------------

func TestJWTVerifier_ES256_HappyPath(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)

	token := fix.sign(t, standardClaims())
	got, err := v.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "usr_alice_acc_a1b2", got.Subject)
	assert.Equal(t, "2", got.ACR)
	assert.Equal(t, []string{"webauthn"}, got.AMR)
	assert.Equal(t, "ES256", got.Alg)
}

func TestJWTVerifier_RS256_HappyPath(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)
	got, err := v.Verify(context.Background(), fix.sign(t, standardClaims()))
	require.NoError(t, err)
	assert.Equal(t, "RS256", got.Alg)
}

func TestJWTVerifier_EdDSA_HappyPath(t *testing.T) {
	fix := newJWKSFixture(t, "EdDSA")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)
	got, err := v.Verify(context.Background(), fix.sign(t, standardClaims()))
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", got.Alg)
}

func TestJWTVerifier_AlgNoneRejected(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)

	// Craft a token with alg=none via golang-jwt's UnsafeAllowNoneSignatureType escape hatch.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, standardClaims())
	tok.Header["kid"] = fix.kid
	bad, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alg=")
}

func TestJWTVerifier_HS256AlgorithmConfusionRejected(t *testing.T) {
	// Algorithm-confusion: attacker swaps RS256 → HS256 to abuse JWKS public
	// key as HMAC secret (CVE-2015-9235 family). Our whitelist excludes HS*,
	// so verifier must reject BEFORE any crypto op.
	fix := newJWKSFixture(t, "RS256")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, standardClaims())
	tok.Header["kid"] = fix.kid
	bad, err := tok.SignedString([]byte("symmetric-secret"))
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alg=")
}

func TestJWTVerifier_UnknownKidForceRefreshThenFail(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)

	// Forge a token with an unknown kid.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, standardClaims())
	tok.Header["kid"] = "unknown-kid"
	bad, err := tok.SignedString(priv)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwks resolve")
}

func TestJWTVerifier_ExpiredTokenRejected(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience, ClockSkew: time.Second,
	})
	require.NoError(t, err)
	claims := standardClaims()
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	tok := fix.sign(t, claims)
	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err)
}

func TestJWTVerifier_NotYetValid(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience, ClockSkew: time.Second,
	})
	claims := standardClaims()
	claims["nbf"] = time.Now().Add(1 * time.Hour).Unix()
	_, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.Error(t, err)
}

func TestJWTVerifier_BadIssuer(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	claims := standardClaims()
	claims["iss"] = "https://evil.example.com"
	_, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.ErrorContains(t, err, "iss mismatch")
}

func TestJWTVerifier_BadAudience(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	claims := standardClaims()
	claims["aud"] = []any{"https://other.example.com"}
	_, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.ErrorContains(t, err, "aud")
}

func TestJWTVerifier_TamperedSignature(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	tok := fix.sign(t, standardClaims())
	// Flip the last char of payload then re-encode signature (will not verify).
	if len(tok) > 4 {
		tok = tok[:len(tok)-4] + "AAAA"
	}
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

func TestJWTVerifier_JWKSUnreachable(t *testing.T) {
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: "http://127.0.0.1:1/.well-known/jwks.json", ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
		JWKSFetchTimeout: 200 * time.Millisecond,
	})
	_, err := v.Verify(context.Background(), "x.y.z")
	require.Error(t, err)
}

func TestJWTVerifier_JWKSCacheSecondCallNoNetwork(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
		JWKSCacheTTL: 1 * time.Hour,
	})
	token := fix.sign(t, standardClaims())
	_, err := v.Verify(context.Background(), token)
	require.NoError(t, err)
	hitsAfter1 := atomic.LoadInt32(&fix.hitCount)
	_, err = v.Verify(context.Background(), token)
	require.NoError(t, err)
	hitsAfter2 := atomic.LoadInt32(&fix.hitCount)
	assert.Equal(t, hitsAfter1, hitsAfter2, "second verify should not refetch JWKS within TTL")
}

func TestJWTVerifier_DPoPBoundClaimsExtracted(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	claims := standardClaims()
	claims["cnf"] = map[string]any{"jkt": "expected-thumbprint"}
	got, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.NoError(t, err)
	assert.True(t, got.Cnf.HasJkt)
	assert.Equal(t, "expected-thumbprint", got.Cnf.Jkt)
	assert.False(t, got.Cnf.IsBearer)
}

func TestJWTVerifier_MTLSBoundClaimsExtracted(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	claims := standardClaims()
	claims["cnf"] = map[string]any{"x5t#S256": "client-cert-thumb"}
	got, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.NoError(t, err)
	assert.True(t, got.Cnf.HasX5tS)
	assert.Equal(t, "client-cert-thumb", got.Cnf.X5tS256)
}

func TestJWTVerifier_TypDPoPRejected(t *testing.T) {
	// Defence: an attacker presents a DPoP proof JWT as if it were an access
	// token. typ=dpop+jwt must be rejected by the access-token verifier.
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, standardClaims())
	tok.Header["kid"] = fix.kid
	tok.Header["typ"] = "dpop+jwt"
	s, _ := tok.SignedString(fix.priv)
	_, err := v.Verify(context.Background(), s)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dpop+jwt")
}

func TestJWTVerifier_ExtClaimsExtracted(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	claims := standardClaims()
	claims["ext_claims"] = map[string]any{
		"kacho_external_id":    "krt_id_xxx",
		"kacho_active_account": "acc_a1b2",
		"kacho_principal_type": "user",
	}
	got, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.NoError(t, err)
	require.NotNil(t, got.ExtClaims)
	assert.Equal(t, "acc_a1b2", got.ExtClaims["kacho_active_account"])
}

func TestJWTVerifier_AudAsString(t *testing.T) {
	// RFC 7519 allows aud as string OR array; we must accept both.
	fix := newJWKSFixture(t, "ES256")
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	claims := standardClaims()
	claims["aud"] = testAudience // single string
	got, err := v.Verify(context.Background(), fix.sign(t, claims))
	require.NoError(t, err)
	assert.Equal(t, "usr_alice_acc_a1b2", got.Subject)
}

func TestJWTVerifier_EmptyTokenRejected(t *testing.T) {
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: "http://x", ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	_, err := v.Verify(context.Background(), "")
	require.Error(t, err)
}

func TestJWTVerifier_StructurallyMalformed(t *testing.T) {
	v, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: "http://x", ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	_, err := v.Verify(context.Background(), "notajwt")
	require.Error(t, err)
}

func TestJWTVerifier_Construction_Validates(t *testing.T) {
	_, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{})
	assert.Error(t, err)
	_, err = middleware.NewJWTVerifier(middleware.JWTVerifierConfig{JWKSURL: "x"})
	assert.Error(t, err)
}
