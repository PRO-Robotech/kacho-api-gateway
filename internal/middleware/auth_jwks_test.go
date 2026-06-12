package middleware_test

// auth_jwks_test.go — SEC-J: AuthInterceptor validates real Hydra RS256 access
// JWTs through the existing JWKS verifier (a SECOND strategy alongside the
// HMAC-dev path) and derives the Kachō Principal from the verified
// `kacho_principal_*` claims (top-level OR ext_claims), falling back to
// SubjectLookuper only when those claims are absent.
//
// Reuses the `jwksFixture` httptest JWKS-server helper + `standardClaims()`
// from jwt_verifier_test.go (same `middleware_test` package).
//
// Acceptance: docs/specs/sub-phase-SEC-J-gateway-hydra-jwks-authn-acceptance.md
// Scenarios A (A2/A3/A4), B/B2 coexistence, D (d1-d7) reject-never-anonymous,
// E fail-closed. Parity across the gRPC interceptor (`authorize`) and the REST
// path (`auth.HTTP`).

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
)

// countingLookup records whether LookupByExternalID was invoked — Scenario A
// asserts the verified-claims path does NOT touch the SubjectLookuper.
type countingLookup struct {
	subj   middleware.Subject
	err    error
	called int
}

func (c *countingLookup) LookupByExternalID(_ context.Context, _ string) (middleware.Subject, error) {
	c.called++
	return c.subj, c.err
}

// rs256Verifier builds a JWTVerifier wired to the fixture's JWKS server with
// the fixture issuer/audience. allowMissing keeps aud optional (Hydra dev may
// not stamp the gateway audience yet).
func rs256Verifier(t *testing.T, fix *jwksFixture) *middleware.JWTVerifier {
	t.Helper()
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL:              fix.url,
		ExpectedIssuer:       testIssuer,
		ExpectedAudience:     testAudience,
		AllowMissingAudience: true,
		JWKSCacheTTL:         time.Hour,
	})
	require.NoError(t, err)
	return v
}

// hydraClaims returns a Hydra-shaped RS256 claim set with the kacho principal
// claims at the TOP LEVEL (Hydra allowed_top_level_claims promotion).
func hydraClaims(pType, pID string) jwt.MapClaims {
	c := standardClaims()
	c["sub"] = pID
	c["kacho_principal_type"] = pType
	c["kacho_principal_id"] = pID
	return c
}

// --- Scenario A: valid RS256 → principal from claims, no lookup ----------

func TestAuthJWKS_RS256_PrincipalFromClaims_NoLookup(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	lookup := &countingLookup{subj: middleware.Subject{Type: "user", ID: "should-not-be-used"}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", lookup, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	token := fix.sign(t, hydraClaims("user", "usr_alice_acc_a1b2"))
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))

	called := false
	handler := func(ctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "user", p.Type)
		assert.Equal(t, "usr_alice_acc_a1b2", p.ID)
		md, _ := metadata.FromOutgoingContext(ctx)
		assert.Equal(t, []string{"user"}, md.Get("x-kacho-principal-type"))
		assert.Equal(t, []string{"usr_alice_acc_a1b2"}, md.Get("x-kacho-principal-id"))
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
	require.NoError(t, err)
	assert.True(t, called, "handler must run for a valid Hydra token")
	assert.Equal(t, 0, lookup.called, "verified kacho_principal_* claims must NOT trigger a SubjectLookuper round-trip")
}

// A2 — service-account token: type=service_account, id=svaId, no User lookup.
func TestAuthJWKS_RS256_ServiceAccountPrincipal(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	lookup := &countingLookup{}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", lookup, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	token := fix.sign(t, hydraClaims("service_account", "sva_robot_acc_a1b2"))
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))

	handler := func(ctx context.Context, _ any) (any, error) {
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "service_account", p.Type)
		assert.Equal(t, "sva_robot_acc_a1b2", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
	require.NoError(t, err)
	assert.Equal(t, 0, lookup.called, "SA principal resolves from claims, never a User lookup")
}

// A3 — claims under ext_claims (nested) resolve to the identical principal.
func TestAuthJWKS_RS256_PrincipalFromExtClaims(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	lookup := &countingLookup{}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", lookup, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	claims := standardClaims()
	claims["sub"] = "usr_bob_acc_c3d4"
	claims["ext_claims"] = map[string]any{
		"kacho_principal_type": "user",
		"kacho_principal_id":   "usr_bob_acc_c3d4",
	}
	token := fix.sign(t, claims)
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))

	handler := func(ctx context.Context, _ any) (any, error) {
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "user", p.Type)
		assert.Equal(t, "usr_bob_acc_c3d4", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
	require.NoError(t, err)
	assert.Equal(t, 0, lookup.called)
}

// A4 — verified token WITHOUT kacho claims falls back to SubjectLookuper(sub).
func TestAuthJWKS_RS256_FallbackToLookupWhenClaimsAbsent(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	lookup := &countingLookup{subj: middleware.Subject{Type: "user", ID: "usr-resolved", DisplayName: "Resolved"}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", lookup, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	claims := standardClaims()
	claims["sub"] = "krt_external_id_xyz"
	// no kacho_principal_* claims at all.
	token := fix.sign(t, claims)
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))

	handler := func(ctx context.Context, _ any) (any, error) {
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "user", p.Type)
		assert.Equal(t, "usr-resolved", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
	require.NoError(t, err)
	assert.Equal(t, 1, lookup.called, "absent claims must fall back to SubjectLookuper exactly like the legacy path")
}

// --- Scenario B/B2: HMAC-dev coexistence (zero regression) ----------------

// B2 — with the JWKS verifier wired AND devSecret set, an HS256-dev token still
// validates via the HMAC branch (neither strategy steals the other's tokens).
func TestAuthJWKS_HMACDevTokenStillValidates_WithVerifierWired(t *testing.T) {
	const secret = "dev-secret-test"
	fix := newJWKSFixture(t, "RS256")
	lookup := &countingLookup{subj: middleware.Subject{Type: "user", ID: "usr-alice", DisplayName: "Alice"}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, secret, lookup, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	devTok := makeDevJWT(t, secret, "zit-12345")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+devTok))

	handler := func(ctx context.Context, _ any) (any, error) {
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "user", p.Type)
		assert.Equal(t, "usr-alice", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
	require.NoError(t, err)
	assert.Equal(t, 1, lookup.called, "HS256-dev token routes through the HMAC branch + SubjectLookuper, unchanged")
}

// --- Scenario D: bad token → REJECTED, never anonymous --------------------

func TestAuthJWKS_BadToken_RejectedNeverAnonymous(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")

	// d1: RS256 token whose signature does not verify against the JWKS (signed
	// by a DIFFERENT key advertising the same kid).
	otherFix := newJWKSFixture(t, "RS256")
	otherFix.kid = fix.kid // collide kid so resolution hits fix's key, sig fails
	d1 := otherFix.sign(t, hydraClaims("user", "usr_evil"))

	// d3: expired RS256 token.
	expClaims := hydraClaims("user", "usr_alice_acc_a1b2")
	expClaims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	expClaims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	d3 := fix.sign(t, expClaims)

	// d4: wrong issuer.
	issClaims := hydraClaims("user", "usr_alice_acc_a1b2")
	issClaims["iss"] = "https://evil.example.com"
	d4 := fix.sign(t, issClaims)

	// d6: structurally malformed.
	const d6 = "not.a.jwt"

	// d7: verified RS256 token missing sub AND missing kacho claims.
	noSub := standardClaims()
	delete(noSub, "sub")
	d7 := fix.sign(t, noSub)

	cases := map[string]string{
		"d1_bad_signature": d1,
		"d3_expired":       d3,
		"d4_wrong_issuer":  d4,
		"d6_malformed":     d6,
		"d7_missing_sub":   d7,
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			lookup := &countingLookup{}
			auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "dev-secret-test", lookup, authTestLogger()).
				WithVerifier(rs256Verifier(t, fix))
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs("authorization", "Bearer "+tok))
			called := false
			handler := func(ctx context.Context, _ any) (any, error) {
				called = true
				return nil, nil
			}
			_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
			require.Error(t, err, "bad token must be rejected")
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Unauthenticated, st.Code())
			assert.False(t, called, "handler must NOT run for a bad token (never anonymous, never principal-less pass-through)")
		})
	}
}

// d5 — alg=none and an HS256 token NOT signed with the dev secret must both be
// rejected (never anonymous). devSecret empty → HMAC path unavailable too.
func TestAuthJWKS_DisallowedAlg_Rejected(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")

	// alg=none.
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, hydraClaims("user", "usr_evil"))
	noneTok.Header["kid"] = fix.kid
	noneStr, err := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	// HS256 NOT signed with the dev secret (devSecret deliberately empty so the
	// HMAC branch cannot accept it either).
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, hydraClaims("user", "usr_evil"))
	hsTok.Header["kid"] = fix.kid
	hsStr, err := hsTok.SignedString([]byte("attacker-secret"))
	require.NoError(t, err)

	for name, tok := range map[string]string{"alg_none": noneStr, "hs256_wrong_secret": hsStr} {
		t.Run(name, func(t *testing.T) {
			auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", &countingLookup{}, authTestLogger()).
				WithVerifier(rs256Verifier(t, fix))
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs("authorization", "Bearer "+tok))
			called := false
			handler := func(context.Context, any) (any, error) { called = true; return nil, nil }
			_, verr := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
			require.Error(t, verr)
			st, _ := status.FromError(verr)
			assert.Equal(t, codes.Unauthenticated, st.Code())
			assert.False(t, called)
		})
	}
}

// --- Scenario E: JWKS unreachable → fail-closed reject (not anonymous) -----

func TestAuthJWKS_JWKSUnreachable_FailClosed(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	token := fix.sign(t, hydraClaims("user", "usr_alice_acc_a1b2"))

	// Verifier points at a dead endpoint; cache is empty → fail-closed.
	v, err := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL:          "http://127.0.0.1:1/.well-known/jwks.json",
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
		JWKSFetchTimeout: 200 * time.Millisecond,
	})
	require.NoError(t, err)
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", &countingLookup{}, authTestLogger()).
		WithVerifier(v)

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
	called := false
	handler := func(context.Context, any) (any, error) { called = true; return nil, nil }
	_, verr := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/iam/WhoAmI"}, handler)
	require.Error(t, verr, "JWKS unreachable + empty cache must fail-closed, not anonymous")
	st, _ := status.FromError(verr)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, called)
}

// --- Parity: REST auth.HTTP path resolves the same principal ---------------

func TestAuthJWKS_REST_RS256_PrincipalFromClaims(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	lookup := &countingLookup{}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", lookup, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	token := fix.sign(t, hydraClaims("user", "usr_alice_acc_a1b2"))

	var gotType, gotID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("X-Kacho-Principal-Type")
		gotID = r.Header.Get("X-Kacho-Principal-Id")
	})
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	auth.HTTP(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user", gotType)
	assert.Equal(t, "usr_alice_acc_a1b2", gotID)
	assert.Equal(t, 0, lookup.called)
}

// REST parity for Scenario D — bad RS256 token over REST → 401, never reaches
// the backend principal-less.
func TestAuthJWKS_REST_BadToken_Rejected401(t *testing.T) {
	fix := newJWKSFixture(t, "RS256")
	other := newJWKSFixture(t, "RS256")
	other.kid = fix.kid
	token := other.sign(t, hydraClaims("user", "usr_evil")) // bad signature

	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", &countingLookup{}, authTestLogger()).
		WithVerifier(rs256Verifier(t, fix))

	reached := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	auth.HTTP(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, reached, "backend must not be reached principal-less on a bad token")
	assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
}
