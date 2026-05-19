package middleware_test

// dpop_test.go — RFC 9449 validator unit tests. Covers acceptance §6.4
// scenarios (htm/htu/iat/jti/jkt/ath mismatch).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// --- Helpers --------------------------------------------------------------

type dpopKeypair struct {
	alg   string
	priv  any
	jwk   middleware.JWK
	thumb string
}

func newES256Keypair(t *testing.T) *dpopKeypair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x := priv.PublicKey.X.Bytes()
	y := priv.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)
	j := middleware.JWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(xPadded),
		Y: base64.RawURLEncoding.EncodeToString(yPadded),
	}
	tb, err := j.Thumbprint()
	require.NoError(t, err)
	return &dpopKeypair{alg: "ES256", priv: priv, jwk: j, thumb: tb}
}

func newEdDSAKeypair(t *testing.T) *dpopKeypair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	j := middleware.JWK{
		Kty: "OKP", Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(pub),
	}
	tb, err := j.Thumbprint()
	require.NoError(t, err)
	return &dpopKeypair{alg: "EdDSA", priv: priv, jwk: j, thumb: tb}
}

func (k *dpopKeypair) signDPoP(t *testing.T, htm, htu string, iat time.Time, jti string, extra map[string]any) string {
	t.Helper()
	claims := jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"iat": iat.Unix(),
		"jti": jti,
	}
	for k2, v := range extra {
		claims[k2] = v
	}
	var method jwt.SigningMethod
	switch k.alg {
	case "ES256":
		method = jwt.SigningMethodES256
	case "EdDSA":
		method = jwt.SigningMethodEdDSA
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["typ"] = "dpop+jwt"
	jwkBytes, _ := json.Marshal(k.jwk)
	var jwkMap map[string]any
	_ = json.Unmarshal(jwkBytes, &jwkMap)
	tok.Header["jwk"] = jwkMap
	s, err := tok.SignedString(k.priv)
	require.NoError(t, err)
	return s
}

func newValidator(t *testing.T) (*middleware.DPoPValidator, *middleware.DPoPReplayCache) {
	t.Helper()
	cache := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 1024,
		TTL:        120 * time.Second,
	})
	v, err := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{
		ReplayCache:  cache,
		IatFreshness: 60 * time.Second,
	})
	require.NoError(t, err)
	return v, cache
}

func boundToken(thumbprint, raw string) *middleware.VerifiedToken {
	return &middleware.VerifiedToken{
		Raw: raw,
		Cnf: middleware.TokenConfirmation{HasJkt: true, Jkt: thumbprint},
	}
}

// --- Scenarios ------------------------------------------------------------

// 6.4.1 — Valid DPoP-bound request succeeds.
func TestDPoP_641_HappyPath_ES256(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	htm := "POST"
	htu := "https://api.kacho.cloud/iam/v1/users/me"
	dpop := kp.signDPoP(t, htm, htu, time.Now(), "01HZ-uuid-v7-1", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: htm, URL: htu, DPoPHeader: dpop,
	})
	assert.NoError(t, err)
}

func TestDPoP_HappyPath_EdDSA(t *testing.T) {
	kp := newEdDSAKeypair(t)
	v, _ := newValidator(t)
	htm := "GET"
	htu := "https://api.kacho.cloud/vpc/v1/networks"
	dpop := kp.signDPoP(t, htm, htu, time.Now(), "eddsa-jti-1", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: htm, URL: htu, DPoPHeader: dpop,
	})
	assert.NoError(t, err)
}

// 6.4.2 — htm mismatch.
func TestDPoP_642_HTMMismatch(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	htm := "GET"
	htu := "https://api.kacho.cloud/x"
	dpop := kp.signDPoP(t, htm, htu, time.Now(), "jti", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: "POST", URL: htu, DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPHTMMismatch)
}

// 6.4.3 — htu mismatch.
func TestDPoP_643_HTUMismatch(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	dpop := kp.signDPoP(t, "POST", "https://api.kacho.cloud/vpc/v1/networks", time.Now(), "jti", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://api.kacho.cloud/iam/v1/users/me", DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPHTUMismatch)
}

func TestDPoP_HTU_Canonicalization_StripsQueryAndDefaultPort(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	// Sign with one canonical URL; server sees URL with default port + query — must match.
	htm := "GET"
	htu := "https://api.kacho.cloud/iam/v1/users/me"
	dpop := kp.signDPoP(t, htm, htu, time.Now(), "jti-q1", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method:     htm,
		URL:        "https://API.KACHO.cloud:443/iam/v1/users/me?foo=bar",
		DPoPHeader: dpop,
	})
	assert.NoError(t, err)
}

// 6.4.4 — jti replay.
func TestDPoP_644_JtiReplay(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	htm := "POST"
	htu := "https://api.kacho.cloud/iam/v1/users/me"
	dpop := kp.signDPoP(t, htm, htu, time.Now(), "replay-jti-x", nil)

	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: htm, URL: htu, DPoPHeader: dpop,
	})
	require.NoError(t, err)

	err = v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: htm, URL: htu, DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPReplay)
}

// 6.4.5 — iat freshness exceeded.
func TestDPoP_645_IATTooOld(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	dpop := kp.signDPoP(t, "POST", "https://api.kacho.cloud/x", time.Now().Add(-5*time.Minute), "jti-old", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://api.kacho.cloud/x", DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPIATFresh)
}

func TestDPoP_IATTooNew(t *testing.T) {
	// Defence against clock skew exploit: future-dated iat ≥ window must reject.
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	dpop := kp.signDPoP(t, "POST", "https://api.kacho.cloud/x", time.Now().Add(5*time.Minute), "jti-fut", nil)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://api.kacho.cloud/x", DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPIATFresh)
}

// 6.4.6 — cnf.jkt thumbprint mismatch.
func TestDPoP_646_JktMismatch(t *testing.T) {
	attackerKP := newES256Keypair(t)
	v, _ := newValidator(t)
	// Token bound to a DIFFERENT thumbprint than attacker's keypair.
	tok := boundToken("a-different-thumb", "access")
	dpop := attackerKP.signDPoP(t, "POST", "https://api.kacho.cloud/x", time.Now(), "jti", nil)
	err := v.Validate(tok, middleware.DPoPRequest{
		Method: "POST", URL: "https://api.kacho.cloud/x", DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPJktMismatch)
}

// Missing DPoP header when token is DPoP-bound.
func TestDPoP_MissingHeaderForBoundToken(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://api.kacho.cloud/x", DPoPHeader: "",
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPRequiredButBear)
}

// DPoP header presented but token NOT bound — should reject (suspicious).
func TestDPoP_HeaderPresentForBearerToken(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	bearer := &middleware.VerifiedToken{Raw: "access", Cnf: middleware.TokenConfirmation{IsBearer: true}}
	dpop := kp.signDPoP(t, "POST", "https://x", time.Now(), "jti", nil)
	err := v.Validate(bearer, middleware.DPoPRequest{
		Method: "POST", URL: "https://x", DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPInvalidHeader)
}

func TestDPoP_TypMustBeDPoPJwt(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	// Sign with typ=jwt (default golang-jwt) — header injection.
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST", "htu": "https://x", "iat": time.Now().Unix(), "jti": "j",
	})
	tok.Header["typ"] = "jwt" // wrong
	jwkBytes, _ := json.Marshal(kp.jwk)
	var jwkMap map[string]any
	_ = json.Unmarshal(jwkBytes, &jwkMap)
	tok.Header["jwk"] = jwkMap
	s, _ := tok.SignedString(kp.priv)

	err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://x", DPoPHeader: s,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPBadTyp)
}

func TestDPoP_AlgWhitelistRS256Rejected(t *testing.T) {
	// RFC 9449 §4.2: DPoP MUST use asymmetric alg suitable for sender-constrained
	// tokens. We restrict to ES256 + EdDSA. RS256 in DPoP header → reject.
	v, _ := newValidator(t)
	// Hand-craft a token with alg=RS256 in header — we don't need a real key
	// because alg whitelist is checked before signature.
	header := map[string]any{"typ": "dpop+jwt", "alg": "RS256", "jwk": map[string]any{"kty": "RSA"}}
	payload := map[string]any{"htm": "POST", "htu": "https://x", "iat": time.Now().Unix(), "jti": "j"}
	headB, _ := json.Marshal(header)
	payB, _ := json.Marshal(payload)
	// Signature must be valid base64url to pass splitJWT; alg whitelist check
	// happens AFTER that.
	tok := base64.RawURLEncoding.EncodeToString(headB) + "." +
		base64.RawURLEncoding.EncodeToString(payB) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	err := v.Validate(boundToken("any", "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://x", DPoPHeader: tok,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPBadAlg)
}

func TestDPoP_AthClaimEnforcedWhenPresent(t *testing.T) {
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	rawToken := "the-access-token"
	wantAth := func() string {
		s := sha256.Sum256([]byte(rawToken))
		return base64.RawURLEncoding.EncodeToString(s[:])
	}()
	htm := "POST"
	htu := "https://api.kacho.cloud/x"

	// Happy path: correct ath.
	dpop := kp.signDPoP(t, htm, htu, time.Now(), "jti-ath-1", map[string]any{"ath": wantAth})
	err := v.Validate(boundToken(kp.thumb, rawToken), middleware.DPoPRequest{
		Method: htm, URL: htu, DPoPHeader: dpop,
	})
	assert.NoError(t, err)

	// Wrong ath.
	dpop = kp.signDPoP(t, htm, htu, time.Now(), "jti-ath-2", map[string]any{"ath": "wrong"})
	err = v.Validate(boundToken(kp.thumb, rawToken), middleware.DPoPRequest{
		Method: htm, URL: htu, DPoPHeader: dpop,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPAthMismatch)
}

func TestDPoP_BearerTokenSkipsAllChecks(t *testing.T) {
	v, _ := newValidator(t)
	bearer := &middleware.VerifiedToken{Raw: "x", Cnf: middleware.TokenConfirmation{IsBearer: true}}
	err := v.Validate(bearer, middleware.DPoPRequest{Method: "GET", URL: "https://x"})
	assert.NoError(t, err)
}

func TestDPoP_MTLSBoundSkipsDPoPChecks(t *testing.T) {
	v, _ := newValidator(t)
	mtls := &middleware.VerifiedToken{Raw: "x", Cnf: middleware.TokenConfirmation{HasX5tS: true, X5tS256: "thumb"}}
	err := v.Validate(mtls, middleware.DPoPRequest{Method: "GET", URL: "https://x"})
	assert.NoError(t, err)
}

func TestDPoP_PrivateJWKFieldsRejected(t *testing.T) {
	v, _ := newValidator(t)
	// Hand-craft a DPoP header containing private key field `d` — must reject.
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "PRIVATE-LEAK"},
	}
	payload := map[string]any{"htm": "POST", "htu": "https://x", "iat": time.Now().Unix(), "jti": "j"}
	headB, _ := json.Marshal(header)
	payB, _ := json.Marshal(payload)
	tok := base64.RawURLEncoding.EncodeToString(headB) + "." +
		base64.RawURLEncoding.EncodeToString(payB) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	err := v.Validate(boundToken("any", "access"), middleware.DPoPRequest{
		Method: "POST", URL: "https://x", DPoPHeader: tok,
	})
	assert.ErrorIs(t, err, middleware.ErrDPoPInvalidHeader)
}

func TestDPoP_ConcurrentJtiReplay(t *testing.T) {
	// Race-test: 50 goroutines try to submit the SAME jti — exactly one wins.
	kp := newES256Keypair(t)
	v, _ := newValidator(t)
	htm := "POST"
	htu := "https://api.kacho.cloud/x"
	jti := "race-jti"
	dpop := kp.signDPoP(t, htm, htu, time.Now(), jti, nil)

	var success int32
	var replay int32
	var other int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := v.Validate(boundToken(kp.thumb, "access"), middleware.DPoPRequest{
				Method: htm, URL: htu, DPoPHeader: dpop,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case errors.Is(err, middleware.ErrDPoPReplay):
				replay++
			default:
				other++
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), success, "exactly one goroutine must succeed")
	assert.Equal(t, int32(49), replay, "49 must see ErrDPoPReplay")
	assert.Equal(t, int32(0), other, "no other errors expected")
}
