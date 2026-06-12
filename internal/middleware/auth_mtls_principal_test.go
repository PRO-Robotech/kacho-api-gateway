package middleware_test

// auth_mtls_principal_test.go — SEC-K hybrid external listener: optional-mTLS +
// JWT-fallback. When the external TLS listener runs with
// tls.VerifyClientCertIfGiven, a client that presents a VALID Kachō client cert
// gets its Principal derived from the verified cert's SPIFFE SAN
// (spiffe://kacho.cloud/ns/<ns>/sa/<sa>) — NO JWT required. A client with no cert
// falls through to the existing SEC-J JWT path. Missing BOTH cert and JWT on a
// protected RPC (production-strict) → Unauthenticated.
//
// Trust invariant: the principal is derived ONLY from the verified cert chain
// (peer credentials.TLSInfo.State.VerifiedChains) or a validated JWT — never from
// client-supplied x-kacho-principal-* metadata (which is stripped upstream).
//
// Acceptance: docs/specs/sub-phase-SEC-K-gateway-hybrid-mtls-listener-acceptance.md.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// peerCtxWithVerifiedCert builds a context carrying a gRPC peer whose TLS
// auth-info has a NON-EMPTY VerifiedChains (i.e. the listener verified the client
// cert against the trust anchor — VerifyClientCertIfGiven succeeded), with the
// given SPIFFE URI SAN on the leaf. This is exactly the shape the hybrid external
// listener produces for a client that presented a valid Kachō cert.
func peerCtxWithVerifiedCert(t *testing.T, spiffeURI string) context.Context {
	t.Helper()
	u, err := url.Parse(spiffeURI)
	require.NoError(t, err)
	leaf := &x509.Certificate{
		URIs:      []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{leaf}},
		},
	}
	p := &peer.Peer{AuthInfo: tlsInfo}
	return peer.NewContext(context.Background(), p)
}

// (a) A request with a VERIFIED client cert yields a principal derived from the
// cert SPIFFE identity — WITHOUT a JWT and WITHOUT touching the SubjectLookuper.
func TestAuth_HybridMTLS_VerifiedCert_PrincipalFromSPIFFE_NoJWT(t *testing.T) {
	lookup := &countingLookup{} // must NOT be called
	auth := middleware.NewAuthInterceptor(
		middleware.AuthModeProductionStrict, "", lookup, authTestLogger(),
	).WithMTLSPrincipal(true)

	ctx := peerCtxWithVerifiedCert(t,
		"spiffe://kacho.cloud/ns/kacho-vpc-operator/sa/kacho-vpc-operator")

	called := false
	handler := func(hctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(hctx)
		// service_account principal derived from the SAN's sa segment.
		assert.Equal(t, "service_account", p.Type)
		assert.Equal(t, "kacho-vpc-operator", p.ID)
		// outgoing metadata carries the same principal for the backend hop.
		md, _ := metadata.FromOutgoingContext(hctx)
		assert.Equal(t, []string{"service_account"}, md.Get("x-kacho-principal-type"))
		assert.Equal(t, []string{"kacho-vpc-operator"}, md.Get("x-kacho-principal-id"))
		return nil, nil
	}
	// production-strict has NO Bearer and would otherwise reject — the verified
	// cert must satisfy authN on its own.
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.NoError(t, err)
	assert.True(t, called, "handler must run on a verified-cert request")
	assert.Equal(t, 0, lookup.called, "verified-cert path must NOT touch SubjectLookuper")
}

// (b) No cert + valid JWT still works (SEC-J zero-regression). With hybrid
// enabled but no peer cert, the existing dev-JWT path resolves the principal.
func TestAuth_HybridMTLS_NoCert_ValidJWT_StillWorks(t *testing.T) {
	const secret = "dev-secret-test"
	lookup := &fakeLookup{subj: middleware.Subject{
		Type: "user", ID: "usr-alice", DisplayName: "Alice",
	}}
	auth := middleware.NewAuthInterceptor(
		middleware.AuthModeDev, secret, lookup, authTestLogger(),
	).WithMTLSPrincipal(true)

	jwt := makeDevJWT(t, secret, "zit-12345")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+jwt))

	called := false
	handler := func(hctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(hctx)
		assert.Equal(t, "user", p.Type)
		assert.Equal(t, "usr-alice", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.NoError(t, err)
	assert.True(t, called)
}

// (c) No cert + no JWT on a protected RPC (production-strict) → Unauthenticated.
// Hybrid enabled must not weaken the fail-closed contract when neither
// credential is present.
func TestAuth_HybridMTLS_NoCert_NoJWT_ProtectedRPC_Unauthenticated(t *testing.T) {
	auth := middleware.NewAuthInterceptor(
		middleware.AuthModeProductionStrict, "", &fakeLookup{}, authTestLogger(),
	).WithMTLSPrincipal(true)

	called := false
	handler := func(_ context.Context, _ any) (any, error) {
		called = true
		return nil, nil
	}
	_, err := auth.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, called, "no cert + no JWT must not run the handler")
}

// A presented client-supplied x-kacho-principal-* must NOT be trusted even when
// a verified cert is absent — the trust invariant. Stripped upstream; with no
// cert and no JWT in production-strict this is still Unauthenticated.
func TestAuth_HybridMTLS_SpoofedPrincipalHeader_NotTrusted(t *testing.T) {
	auth := middleware.NewAuthInterceptor(
		middleware.AuthModeProductionStrict, "", &fakeLookup{}, authTestLogger(),
	).WithMTLSPrincipal(true)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-kacho-principal-type", "user",
		"x-kacho-principal-id", "usr-attacker",
	))
	handler := func(_ context.Context, _ any) (any, error) {
		t.Fatal("handler must not run for a spoofed principal header without cert/JWT")
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}
