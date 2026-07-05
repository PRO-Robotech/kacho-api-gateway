// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// stepup_wiring_test.go — verifies that the DPoP HTTP middleware's step-up
// (ACR) gate is actually wired to the permission catalog + REST router, so a
// privileged RPC whose catalog entry demands `required_acr_min=2` rejects a
// token presenting a lower ACR with an RFC 9470 step-up challenge.
//
// Regression guard for the "step-up gate is a dead control" finding: before
// wiring, PermissionLookup defaulted to a no-op and the REST→FQN mapper
// produced "//vpc/v1/networks" (never a catalog key), so the gate could never
// fire on any request.

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// buildStepUpMiddleware wires a production-shaped DPoP middleware whose step-up
// gate is backed by the embedded permission catalog + the generated REST route
// table (exactly as cmd/api-gateway/main.go must wire it).
func buildStepUpMiddleware(t *testing.T, verifier *middleware.JWTVerifier) *middleware.DPoPMiddleware {
	t.Helper()
	replay := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 64, TTL: 60 * time.Second,
	})
	dpop, err := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{
		ReplayCache: replay, IatFreshness: 60 * time.Second,
	})
	require.NoError(t, err)

	catalog, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	mw, err := middleware.NewDPoPMiddleware(middleware.DPoPMiddlewareConfig{
		Verifier:         verifier,
		DPoP:             dpop,
		StepUp:           middleware.NewStepUpGate(time.Now),
		PermissionLookup: middleware.NewCatalogPermissionLookup(catalog),
		RestRouter:       middleware.NewRestRouter(),
		Logger:           slog.Default(),
		APIDomain:        "api.kacho.cloud",
	})
	require.NoError(t, err)
	return mw
}

func stepUpVerifier(t *testing.T, fix *jwksFixture) *middleware.JWTVerifier {
	t.Helper()
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL: fix.url, ExpectedIssuer: testIssuer, ExpectedAudience: testAudience,
	})
	require.NoError(t, err)
	return v
}

// A privileged RPC (NetworkService/Create, required_acr_min=2) called with a
// token presenting acr=1 must be rejected with an RFC 9470 step-up challenge —
// the backend handler must never run.
func TestDPoPStepUp_InsufficientACR_ChallengesAndBlocks(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	mw := buildStepUpMiddleware(t, stepUpVerifier(t, fix))

	claims := standardClaims()
	claims["acr"] = "1" // password-only, below the required "2"
	token := fix.sign(t, claims)

	backendHit := false
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "https://api.kacho.cloud/vpc/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "step-up must reject acr=1 on an acr>=2 RPC")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "insufficient_user_authentication",
		"must emit an RFC 9470 step-up challenge")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `acr_values="2"`)
	assert.False(t, backendHit, "backend handler must not run when step-up is required")
}

// The same RPC called with a sufficient ACR passes the gate and reaches the
// backend.
func TestDPoPStepUp_SufficientACR_PassesThrough(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	mw := buildStepUpMiddleware(t, stepUpVerifier(t, fix))

	claims := standardClaims()
	claims["acr"] = "2" // meets requirement
	token := fix.sign(t, claims)

	backendHit := false
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "https://api.kacho.cloud/vpc/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, backendHit, "backend handler must run when ACR is sufficient")
}

// An unknown/unmapped path (no REST route → no catalog entry) carries no
// requirement and passes through — the gate must not fabricate a requirement
// out of a failed FQN resolution.
func TestDPoPStepUp_UnmappedPath_NoRequirement(t *testing.T) {
	fix := newJWKSFixture(t, "ES256")
	mw := buildStepUpMiddleware(t, stepUpVerifier(t, fix))

	claims := standardClaims()
	claims["acr"] = "1"
	token := fix.sign(t, claims)

	backendHit := false
	handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://api.kacho.cloud/no/such/route/xyz", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, backendHit, "unmapped path has no catalog requirement → must pass")
	assert.Equal(t, http.StatusOK, rec.Code)
}
