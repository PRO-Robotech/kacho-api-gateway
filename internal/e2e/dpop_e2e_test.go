// Package e2e — KAC-127 Phase 2 end-to-end test: wires the DPoPMiddleware
// against a fake Hydra (JWKS + introspection) and exercises the full chain:
// JWT verify → DPoP validate → step-up gate → principal injection.
//
// Why a separate package: this is a black-box style integration test that
// composes multiple middleware/* packages and asserts HTTP behavior; keeping
// it out of `middleware_test` avoids polluting unit-test scope.
package e2e_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	apiDomain    = "api.kacho.cloud"
)

// hydraFixture — fake Hydra serving JWKS + (optionally) introspection.
type hydraFixture struct {
	jwksURL     string
	priv        *ecdsa.PrivateKey
	kid         string
	jwksHits    int
	revokedJTIs map[string]bool
	closer      func()
}

func newHydra(t *testing.T) *hydraFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := "hydra-es256-test"

	x := priv.PublicKey.X.Bytes()
	y := priv.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)
	jwk := middleware.JWK{
		Kty: "EC", Alg: "ES256", Kid: kid, Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(xPadded),
		Y: base64.RawURLEncoding.EncodeToString(yPadded),
	}
	set := middleware.JWKSet{Keys: []middleware.JWK{jwk}}
	jwksBody, _ := json.Marshal(set)

	fix := &hydraFixture{priv: priv, kid: kid, revokedJTIs: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		fix.jwksHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	})
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// Real Hydra introspects via raw token; we cheat for tests — decode the
		// token's JTI from claims to look up revocation state.
		token := r.Form.Get("token")
		jti := jtiOf(token)
		active := !fix.revokedJTIs[jti]
		body, _ := json.Marshal(map[string]any{
			"active": active,
			"sub":    "usr_alice_acc_a1b2",
			"exp":    time.Now().Add(15 * time.Minute).Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	fix.jwksURL = srv.URL + "/.well-known/jwks.json"
	fix.closer = srv.Close
	return fix
}

func (h *hydraFixture) close() { h.closer() }

// issueDPoPBoundToken — mint an access token bound to a fresh DPoP keypair.
func (h *hydraFixture) issueDPoPBoundToken(t *testing.T) (rawToken string, dpopPriv any, jkt string) {
	t.Helper()
	dpopPriv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x := dpopPriv2.PublicKey.X.Bytes()
	y := dpopPriv2.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)
	dpopJWK := middleware.JWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(xPadded),
		Y: base64.RawURLEncoding.EncodeToString(yPadded),
	}
	thumb, err := dpopJWK.Thumbprint()
	require.NoError(t, err)

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"iss":       testIssuer,
		"aud":       []any{testAudience},
		"sub":       "usr_alice_acc_a1b2",
		"jti":       "01HZQ8M5J7QTAEXAMPLEUUIDV7",
		"iat":       now,
		"exp":       now + 900,
		"acr":       "2",
		"amr":       []any{"webauthn"},
		"auth_time": now,
		"cnf":       map[string]any{"jkt": thumb},
		"ext_claims": map[string]any{
			"kacho_external_id":    "krt_id_xxx",
			"kacho_active_account": "acc_a1b2",
			"kacho_principal_type": "user",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = h.kid
	s, err := tok.SignedString(h.priv)
	require.NoError(t, err)
	return s, dpopPriv2, thumb
}

// signDPoPHeader — produce a DPoP JWT for a given (method, url) pair.
func signDPoPHeader(t *testing.T, priv *ecdsa.PrivateKey, htm, htu, jti string, iat time.Time, ath string) string {
	t.Helper()
	x := priv.PublicKey.X.Bytes()
	y := priv.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(xPadded),
		"y": base64.RawURLEncoding.EncodeToString(yPadded),
	}
	claims := jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"iat": iat.Unix(),
		"jti": jti,
	}
	if ath != "" {
		claims["ath"] = ath
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	s, err := tok.SignedString(priv)
	require.NoError(t, err)
	return s
}

// jtiOf — extract jti from a JWT payload without verifying. Used by the fake
// introspection endpoint to look up revocation state.
func jtiOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	s, _ := m["jti"].(string)
	return s
}

func buildMiddleware(t *testing.T, hydra *hydraFixture) http.Handler {
	t.Helper()
	verifier, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: hydra.jwksURL, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)
	replayCache := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 1024, TTL: 120 * time.Second,
	})
	dpopValidator, err := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{
		ReplayCache: replayCache, IatFreshness: 60 * time.Second,
	})
	require.NoError(t, err)
	mw, err := middleware.NewDPoPMiddleware(middleware.DPoPMiddlewareConfig{
		Verifier:  verifier,
		DPoP:      dpopValidator,
		MTLS:      middleware.NewMTLSBoundValidator(),
		StepUp:    middleware.NewStepUpGate(time.Now),
		Logger:    slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		APIDomain: apiDomain,
	})
	require.NoError(t, err)
	return mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo principal headers back so the test can assert injection happened.
		out := map[string]any{
			"principal_id":   r.Header.Get("X-Kacho-Principal-Id"),
			"principal_type": r.Header.Get("X-Kacho-Principal-Type"),
			"acr":            r.Header.Get("X-Kacho-Token-Acr"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
}

// --- Scenarios ------------------------------------------------------------

func TestE2E_DPoPBoundRequest_HappyPath(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	handler := buildMiddleware(t, hydra)

	rawTok, dpopPriv, _ := hydra.issueDPoPBoundToken(t)
	htu := "https://" + apiDomain + "/iam/v1/users/me"
	dpop := signDPoPHeader(t, dpopPriv.(*ecdsa.PrivateKey), "POST", htu, "e2e-jti-1", time.Now(), "")

	req := httptest.NewRequest(http.MethodPost, htu, nil)
	req.Header.Set("Authorization", "DPoP "+rawTok)
	req.Header.Set("DPoP", dpop)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(t, string(body), `"principal_id":"usr_alice_acc_a1b2"`)
	assert.Contains(t, string(body), `"principal_type":"user"`)
	assert.Contains(t, string(body), `"acr":"2"`)
}

func TestE2E_DPoPRequiredButMissing(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	handler := buildMiddleware(t, hydra)

	rawTok, _, _ := hydra.issueDPoPBoundToken(t)
	htu := "https://" + apiDomain + "/iam/v1/users/me"
	req := httptest.NewRequest(http.MethodPost, htu, nil)
	req.Header.Set("Authorization", "DPoP "+rawTok)
	// No DPoP header.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "DPoP")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_dpop_proof")
}

func TestE2E_DPoPReplayRejected(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	handler := buildMiddleware(t, hydra)

	rawTok, dpopPriv, _ := hydra.issueDPoPBoundToken(t)
	htu := "https://" + apiDomain + "/iam/v1/users/me"
	dpop := signDPoPHeader(t, dpopPriv.(*ecdsa.PrivateKey), "POST", htu, "replay-jti", time.Now(), "")

	build := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, htu, nil)
		r.Header.Set("Authorization", "DPoP "+rawTok)
		r.Header.Set("DPoP", dpop)
		return r
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, build())
	require.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, build())
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_dpop_proof")
}

func TestE2E_NoAuthorizationHeader_PassesThrough(t *testing.T) {
	// requireForAllRequests=false → no auth header is fine (anonymous).
	hydra := newHydra(t)
	defer hydra.close()
	handler := buildMiddleware(t, hydra)
	req := httptest.NewRequest(http.MethodGet, "https://"+apiDomain+"/iam/v1/users/me", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(t, string(body), `"principal_id":""`)
}

func TestE2E_InvalidTokenSignature(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	handler := buildMiddleware(t, hydra)

	// Sign with a stranger key — kid still hydra's, but signature won't verify.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": testIssuer, "aud": []any{testAudience}, "sub": "usr",
		"iat": now, "exp": now + 900, "acr": "2",
	})
	tok.Header["kid"] = hydra.kid
	bad, _ := tok.SignedString(other)

	req := httptest.NewRequest(http.MethodGet, "https://"+apiDomain+"/iam/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_token")
}

func TestE2E_BearerToken_NoCnf_Accepted(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	handler := buildMiddleware(t, hydra)
	// Issue a plain bearer (no cnf).
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": testIssuer, "aud": []any{testAudience}, "sub": "usr_bearer",
		"iat": now, "exp": now + 900, "acr": "2",
	})
	tok.Header["kid"] = hydra.kid
	bearer, err := tok.SignedString(hydra.priv)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "https://"+apiDomain+"/iam/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(t, string(body), `"principal_id":"usr_bearer"`)
}

func TestE2E_HealthEndpoint_BypassesAuth(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	verifier, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: hydra.jwksURL, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	dpopValidator, _ := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{
		ReplayCache: middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{}),
	})
	mw, _ := middleware.NewDPoPMiddleware(middleware.DPoPMiddlewareConfig{
		Verifier: verifier, DPoP: dpopValidator,
		MTLS:      middleware.NewMTLSBoundValidator(),
		StepUp:    middleware.NewStepUpGate(time.Now),
		Logger:    slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		APIDomain: apiDomain,
		// Even with strict on, /healthz must pass.
		RequireForAllRequests: true,
	})
	called := false
	handler := mw.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "https://"+apiDomain+"/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestE2E_ProductionStrict_RejectsAnonymous(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	verifier, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: hydra.jwksURL, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	dpopValidator, _ := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{
		ReplayCache: middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{}),
	})
	mw, _ := middleware.NewDPoPMiddleware(middleware.DPoPMiddlewareConfig{
		Verifier: verifier, DPoP: dpopValidator,
		MTLS:      middleware.NewMTLSBoundValidator(),
		StepUp:    middleware.NewStepUpGate(time.Now),
		Logger:    slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		APIDomain: apiDomain,
		RequireForAllRequests: true,
	})
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "https://"+apiDomain+"/iam/v1/users/me", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_token")
}

// fixedPermLookup implements middleware.PermissionLookup with a single static
// requirement applied to all calls. Used to drive step-up scenarios.
type fixedPermLookup struct {
	req middleware.PermissionRequirement
}

func (f fixedPermLookup) Lookup(_ string) middleware.PermissionRequirement { return f.req }

func TestE2E_StepUpRequired_Challenge(t *testing.T) {
	hydra := newHydra(t)
	defer hydra.close()
	verifier, _ := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: hydra.jwksURL, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	replay := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{})
	dpopValidator, _ := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{ReplayCache: replay})
	mw, _ := middleware.NewDPoPMiddleware(middleware.DPoPMiddlewareConfig{
		Verifier: verifier, DPoP: dpopValidator,
		MTLS:      middleware.NewMTLSBoundValidator(),
		StepUp:    middleware.NewStepUpGate(time.Now),
		Logger:    slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		APIDomain: apiDomain,
		// Permission for any path requires ACR 3.
		PermissionLookup: fixedPermLookup{
			req: middleware.PermissionRequirement{RequiredACRMin: "3"},
		},
	})
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	rawTok, dpopPriv, _ := hydra.issueDPoPBoundToken(t)
	htu := "https://" + apiDomain + "/iam/v1/admin/grant"
	dpop := signDPoPHeader(t, dpopPriv.(*ecdsa.PrivateKey), "POST", htu, "stepup-jti", time.Now(), "")
	req := httptest.NewRequest(http.MethodPost, htu, nil)
	req.Header.Set("Authorization", "DPoP "+rawTok)
	req.Header.Set("DPoP", dpop)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "insufficient_user_authentication")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `acr_values="3"`)
}

// _ = ed25519 keeps the import used should we add EdDSA tests later.
var _ = ed25519.PublicKey(nil)
