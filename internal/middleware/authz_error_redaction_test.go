// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// backendDetail — a distinctive string that stands in for raw gRPC/transport
// detail returned by the IAM authz backend. It must NEVER reach the client:
// leaking it aids an attacker mapping the internal fabric. It MUST, however,
// still be logged server-side for operators.
const backendDetail = "backend down: dial tcp 10.42.0.7:9091 connect: connection refused [trace-id=abc123]"

// captureLogger returns a logger writing to buf plus a config-mutator that
// installs it, so a test can assert what was (and wasn't) logged.
func captureLogger(buf *bytes.Buffer) func(*middleware.AuthzMiddlewareConfig) {
	l := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return func(c *middleware.AuthzMiddlewareConfig) { c.Logger = l }
}

// TestAuthz_GRPC_Unary_UnavailableError_Redacted — the fail-closed Unavailable
// error returned to the client on an authz-backend outage must NOT carry the
// raw backend/transport detail, while preserving the gRPC code and logging the
// detail server-side.
func TestAuthz_GRPC_Unary_UnavailableError_Redacted(t *testing.T) {
	var logbuf bytes.Buffer
	checker := &fakeChecker{returnErr: errors.New(backendDetail)}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker, captureLogger(&logbuf))

	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })

	require.Error(t, err)
	st, _ := status.FromError(err)
	// gRPC code preserved (retryable, fail-closed).
	assert.Equal(t, codes.Unavailable, st.Code())
	// Client message carries NO backend/transport detail.
	assert.NotContains(t, st.Message(), backendDetail)
	assert.NotContains(t, st.Message(), "10.42.0.7")
	assert.NotContains(t, st.Message(), "connection refused")
	assert.NotContains(t, st.Message(), "trace-id")
	assert.NotContains(t, st.Message(), "backend down")
	// Detail is logged server-side (operators still see it).
	assert.Contains(t, logbuf.String(), backendDetail)
}

// TestAuthz_GRPC_Stream_UnavailableError_Redacted — same guarantee for the
// streaming interceptor path.
func TestAuthz_GRPC_Stream_UnavailableError_Redacted(t *testing.T) {
	var logbuf bytes.Buffer
	checker := &fakeChecker{returnErr: errors.New(backendDetail)}
	// A wildcard/non-concrete scope entry so the Check actually runs on the
	// stream path (a concrete-scope entry would fail closed before the checker —
	// see TestAuthz_Stream_ConcreteScope_FailClosed); this test exercises the
	// checker-error redaction, which requires reaching the checker.
	mw := buildAuthzMiddleware(t, buildCatalog(t, streamWildcardEntry), checker, captureLogger(&logbuf))

	ss := &fakeServerStream{ctx: withTokenMD("usr_x", "user")}
	err := mw.Stream()(nil, ss,
		&grpc.StreamServerInfo{FullMethod: "/kacho.cloud.compute.v1.InternalWatchService/Watch"},
		func(srv any, ss grpc.ServerStream) error { return nil })

	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.NotContains(t, st.Message(), backendDetail)
	assert.NotContains(t, st.Message(), "10.42.0.7")
	assert.NotContains(t, st.Message(), "connection refused")
	assert.NotContains(t, st.Message(), "trace-id")
	assert.NotContains(t, st.Message(), "backend down")
	assert.Contains(t, logbuf.String(), backendDetail)
}
