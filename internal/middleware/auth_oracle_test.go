// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestAuth_Unauthenticated_NonOracleMessage — the gRPC auth interceptor must NOT
// (a) echo raw backend/JWT error detail to the caller, nor (b) vary the
// client-visible message by whether the token was malformed vs the subject was
// unprovisioned (a provisioned-subject enumeration oracle, CWE-204/CWE-209).
// Both cases must return an identical, constant Unauthenticated message and log
// the detail server-side only.
func TestAuth_Unauthenticated_NonOracleMessage(t *testing.T) {
	const secret = "prod-secret"

	rejectHandler := func(_ context.Context, _ any) (any, error) {
		t.Fatal("handler must not run for a rejected token")
		return nil, nil
	}

	// Case A — bad signature (malformed/invalid Bearer).
	authBad := middleware.NewAuthInterceptor(middleware.AuthModeProduction, secret, &fakeLookup{}, authTestLogger())
	ctxBad := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer garbage.token.value"))
	_, errBad := authBad.Unary()(ctxBad, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, rejectHandler)
	require.Error(t, errBad)
	stBad, _ := status.FromError(errBad)
	assert.Equal(t, codes.Unauthenticated, stBad.Code())

	// Case B — validly-signed token, subject NOT provisioned in kacho-iam. The
	// lookup error carries distinctive internal detail that must NOT leak.
	const secretDetail = "rpc error: code = NotFound desc = user zit-absent not mirrored"
	lookup := &fakeLookup{err: stderrors.New(secretDetail)}
	authSub := middleware.NewAuthInterceptor(middleware.AuthModeProduction, secret, lookup, authTestLogger())
	jwt := makeDevJWT(t, secret, "zit-absent")
	ctxSub := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+jwt))
	_, errSub := authSub.Unary()(ctxSub, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, rejectHandler)
	require.Error(t, errSub)
	stSub, _ := status.FromError(errSub)
	assert.Equal(t, codes.Unauthenticated, stSub.Code())

	// (a) No backend detail leaked.
	assert.NotContains(t, stSub.Message(), "NotFound")
	assert.NotContains(t, stSub.Message(), "zit-absent")
	assert.NotContains(t, stSub.Message(), "not mirrored")
	assert.NotContains(t, stBad.Message(), "garbage")

	// (b) No oracle: malformed-token and unprovisioned-subject must be
	// indistinguishable to the caller.
	assert.Equal(t, stBad.Message(), stSub.Message(),
		"malformed-token and unprovisioned-subject must return an identical message (no enumeration oracle)")
}
