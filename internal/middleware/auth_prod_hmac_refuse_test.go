// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// auth_prod_hmac_refuse_test.go — SEC (sec-hardening-r8): the symmetric HMAC-dev
// token path must be REFUSED in production / production-strict mode, even when a
// dev-secret is configured. A validly-HS256-signed token (an attacker who learned
// or guessed KACHO_API_GATEWAY_AUTHN_DEV_SECRET) otherwise yields a real
// principal, and a `kacho_principal_type=service_account` claim is injected as a
// service_account with NO IAM lookup — symmetric-key principal forgery (CWE-347).
// In production the ONLY accepted Bearer strategy is the asymmetric JWKS (Hydra)
// verifier.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// makeSAForgeryJWT mints a validly-HS256-signed token asserting a
// service_account principal (kacho_principal_type=service_account + kacho_sa_id).
// This is the forgery payload: on the HMAC-dev path it is injected as a
// service_account with NO IAM lookup.
func makeSAForgeryJWT(t *testing.T, secret, saID string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":                  saID,
		"kacho_principal_type": "service_account",
		"kacho_sa_id":          saID,
		"exp":                  time.Now().Add(15 * time.Minute).Unix(),
		"iat":                  time.Now().Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// gRPC — a forged HMAC service_account token must NOT forge a principal in
// production mode. RED before the fix: the SA claims are trusted verbatim, the
// handler runs with a service_account principal and NO IAM lookup. GREEN: the
// HMAC-dev strategy is refused → Unauthenticated, handler never runs.
func TestAuth_Production_HMACServiceAccountForgery_Rejected(t *testing.T) {
	const secret = "prod-dev-secret-leaked"
	forged := makeSAForgeryJWT(t, secret, "sva-victim-0001")
	// A lookup that would happily resolve a user is provided to prove the reject
	// happens on the HMAC path itself, not because the lookup failed.
	lookup := &fakeLookup{subj: middleware.Subject{Type: "user", ID: "usr-should-not-be-used"}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProduction, secret, lookup, authTestLogger())

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+forged))

	called := false
	handler := func(hctx context.Context, _ any) (any, error) {
		called = true
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.compute.v1.InstanceService/List"}, handler)
	require.Error(t, err, "forged HMAC service_account token must be rejected in production")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, called, "a forged HMAC service_account principal must never reach the backend in production")
}

// gRPC — even a well-formed HMAC USER token whose subject resolves in kacho-iam
// must be refused in production-strict: the symmetric-key path is off entirely,
// only the asymmetric JWKS verifier is accepted. RED before the fix: the token
// validates, the subject resolves, the handler runs with a real user principal.
func TestAuth_ProductionStrict_HMACUserToken_Rejected(t *testing.T) {
	const secret = "prod-dev-secret-leaked"
	lookup := &fakeLookup{subj: middleware.Subject{Type: "user", ID: "usr-alice", DisplayName: "Alice"}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProductionStrict, secret, lookup, authTestLogger())

	tok := makeDevJWT(t, secret, "zit-alice")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+tok))

	called := false
	handler := func(context.Context, any) (any, error) { called = true; return nil, nil }
	_, err := auth.Unary()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.compute.v1.InstanceService/List"}, handler)
	require.Error(t, err, "HMAC-dev token must be refused in production-strict (JWKS-only)")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, called, "HMAC-dev principal must never reach the backend in production-strict")
}

// REST — the same forgery over the HTTP/grpc-gateway path (tryDevSecretJWT). RED
// before the fix: the SA claims are trusted, principal headers are set and `next`
// is served (HTTP 200). GREEN: 401, `next` never runs, no principal headers set.
func TestAuthHTTP_Production_HMACServiceAccountForgery_Rejected(t *testing.T) {
	const secret = "prod-dev-secret-leaked"
	forged := makeSAForgeryJWT(t, secret, "sva-victim-0001")
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProduction, secret, &fakeLookup{}, authTestLogger())

	nextCalled := false
	var sawPrincipalType string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		sawPrincipalType = r.Header.Get(principalmeta.HeaderPrincipalType)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/compute/v1/instances", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	rec := httptest.NewRecorder()
	auth.HTTP(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"forged HMAC service_account token must yield 401 over REST in production")
	assert.False(t, nextCalled, "a forged HMAC SA principal must never reach the backend over REST in production")
	assert.Empty(t, sawPrincipalType, "no forged principal header may be injected")
}

// dev mode is unchanged: the HMAC-dev path still resolves principals so existing
// dev/e2e flows keep working (guard is mode==dev-scoped, not a blanket removal).
func TestAuth_DevMode_HMACServiceAccount_StillResolves(t *testing.T) {
	const secret = "dev-secret-test"
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, secret, &fakeLookup{}, authTestLogger())
	forged := makeSAForgeryJWT(t, secret, "sva-dev-0001")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+forged))

	called := false
	handler := func(hctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(hctx)
		assert.Equal(t, "service_account", p.Type)
		assert.Equal(t, "sva-dev-0001", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.compute.v1.InstanceService/List"}, handler)
	require.NoError(t, err)
	assert.True(t, called, "dev mode must still accept the HMAC-dev SA path (back-compat)")
}
