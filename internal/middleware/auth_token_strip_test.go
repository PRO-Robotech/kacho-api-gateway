// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestAuthHTTP_StripsForgedTokenHeaders proves the REST auth path sanitises ALL
// client-supplied identity/token-context headers — both x-kacho-principal-* and
// x-kacho-token-* (acr/jti/scope). Without this, a forged X-Kacho-Token-Acr
// would flow downstream and be trusted by the gateway step-up gate and the
// backend acr-floor.
func TestAuthHTTP_StripsForgedTokenHeaders(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", nil, authTestLogger())
	var seen http.Header
	h := auth.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/iam/v1/projects", nil)
	forged := []string{
		"X-Kacho-Principal-Id",
		"X-Kacho-Token-Acr",
		"Grpc-Metadata-X-Kacho-Token-Acr",
		"X-Kacho-Token-Jti",
		"X-Kacho-Token-Scope",
	}
	for _, k := range forged {
		r.Header.Set(k, "forged")
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	for _, k := range forged {
		if seen.Get(k) != "" {
			t.Errorf("forged inbound %s not stripped (got %q)", k, seen.Get(k))
		}
	}
}

// TestAuthUnary_StripsForgedTokenMetadata proves the gRPC auth interceptor
// strips forged x-kacho-token-* incoming metadata before deriving identity.
func TestAuthUnary_StripsForgedTokenMetadata(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", nil, authTestLogger())
	md := metadata.New(map[string]string{
		"x-kacho-principal-id": "forged",
		"x-kacho-token-acr":    "3",
		"x-kacho-token-scope":  "system_admin",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var seen metadata.MD
	interceptor := auth.Unary()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.ProjectService/Create"},
		func(c context.Context, _ any) (any, error) {
			seen, _ = metadata.FromIncomingContext(c)
			return nil, nil
		})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	for _, k := range []string{"x-kacho-token-acr", "x-kacho-token-scope"} {
		if vals := seen.Get(k); len(vals) != 0 {
			t.Errorf("forged incoming metadata %s not stripped (got %v)", k, vals)
		}
	}
}
