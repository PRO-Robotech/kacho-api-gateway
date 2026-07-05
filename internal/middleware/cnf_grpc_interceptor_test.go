// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// cnf_grpc_interceptor_test.go — sender-constrained (cnf) binding enforcement on
// the native gRPC surface. The auth interceptor verifies the JWT but never
// inspects cnf; without this interceptor a stolen DPoP-/mTLS-bound token is
// accepted as a plain bearer over gRPC, defeating the binding (CWE-294).

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

type fakeCnfVerifier struct {
	vt  *middleware.VerifiedToken
	err error
}

func (f fakeCnfVerifier) Verify(_ context.Context, _ string) (*middleware.VerifiedToken, error) {
	return f.vt, f.err
}

// asymTokenString returns a compact JWT-looking string whose header advertises
// an asymmetric alg (RS256) so isAsymmetricJWT routes it to the verifier.
func asymTokenString() string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	return hdr + ".payload.sig"
}

func hmacTokenString() string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	return hdr + ".payload.sig"
}

func ctxWithBearer(tok string) context.Context {
	md := metadata.New(map[string]string{"authorization": "Bearer " + tok})
	return metadata.NewIncomingContext(context.Background(), md)
}

func newCnfInterceptorForTest(t *testing.T, vt *middleware.VerifiedToken) *middleware.CnfBindingInterceptor {
	t.Helper()
	ci, err := middleware.NewCnfBindingInterceptor(
		fakeCnfVerifier{vt: vt},
		middleware.NewMTLSBoundValidator(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("NewCnfBindingInterceptor: %v", err)
	}
	return ci
}

func runUnary(t *testing.T, ci *middleware.CnfBindingInterceptor, ctx context.Context) (called bool, err error) {
	t.Helper()
	h := func(context.Context, any) (any, error) { called = true; return "ok", nil }
	_, err = ci.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"}, h)
	return called, err
}

func TestCnfBinding_X5tBound_NoPeerCert_Rejected(t *testing.T) {
	vt := &middleware.VerifiedToken{}
	vt.Cnf.HasX5tS = true
	vt.Cnf.X5tS256 = "thumb"
	ci := newCnfInterceptorForTest(t, vt)

	called, err := runUnary(t, ci, ctxWithBearer(asymTokenString()))
	if called {
		t.Fatal("handler must NOT be called for an mTLS-bound token with no peer cert")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v (%v)", status.Code(err), err)
	}
}

func TestCnfBinding_JktBound_Rejected(t *testing.T) {
	vt := &middleware.VerifiedToken{}
	vt.Cnf.HasJkt = true
	vt.Cnf.Jkt = "thumb"
	ci := newCnfInterceptorForTest(t, vt)

	called, err := runUnary(t, ci, ctxWithBearer(asymTokenString()))
	if called {
		t.Fatal("handler must NOT be called for a DPoP-bound token on the native gRPC surface")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v (%v)", status.Code(err), err)
	}
}

func TestCnfBinding_PlainBearer_PassesThrough(t *testing.T) {
	vt := &middleware.VerifiedToken{}
	vt.Cnf.IsBearer = true
	ci := newCnfInterceptorForTest(t, vt)

	called, err := runUnary(t, ci, ctxWithBearer(asymTokenString()))
	if err != nil {
		t.Fatalf("plain bearer must pass, got %v", err)
	}
	if !called {
		t.Fatal("handler must be called for a plain (non-cnf) bearer")
	}
}

func TestCnfBinding_NoBearer_PassesThrough(t *testing.T) {
	ci := newCnfInterceptorForTest(t, &middleware.VerifiedToken{})
	called, err := runUnary(t, ci, context.Background())
	if err != nil {
		t.Fatalf("no bearer must pass (auth interceptor handles anon), got %v", err)
	}
	if !called {
		t.Fatal("handler must be called when no bearer present")
	}
}

func TestCnfBinding_HMACToken_PassesThrough(t *testing.T) {
	// A dev HMAC token is not asymmetric → verifier is never consulted, no cnf.
	vt := &middleware.VerifiedToken{}
	vt.Cnf.HasJkt = true // even if verifier WOULD return jkt, HMAC path must skip it
	ci := newCnfInterceptorForTest(t, vt)
	called, err := runUnary(t, ci, ctxWithBearer(hmacTokenString()))
	if err != nil {
		t.Fatalf("HMAC dev token must pass the cnf interceptor, got %v", err)
	}
	if !called {
		t.Fatal("handler must be called for an HMAC dev token")
	}
}
