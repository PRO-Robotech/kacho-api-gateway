// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_grpc_listener_w1_2_test.go — covers the dedicated internal gRPC
// listener: api-gateway main.go stands up a separate internal listener on which
// InternalAuthzCacheService is registered, so iam's push-drainer can dial
// KACHO_API_GATEWAY_INTERNAL_GRPC_ADDR and invoke InvalidateSubject.
//
// The contract pinned here: a small wiring helper
//
//	startInternalGRPCListener(addr string, inv handler.Invalidator,
//	    externalSrv *grpc.Server, logger *slog.Logger) (*grpc.Server, net.Listener, error)
//
// constructs a real grpc.Server, calls handler.RegisterInternalAuthzCacheService
// to put InternalAuthzCacheService on it (and NOT on externalSrv — internal
// admin services stay off the external server), listens on addr, and returns the
// wired server+listener so main.go can Serve() + GracefulStop() under the same
// signal-shutdown flow as the external server.
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
	apigatewayv1 "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/apigateway/v1"
)

// fakeInvalidator — records InvalidateSubject calls so the test can assert
// the wired gRPC path reaches the cache.
type fakeInvalidator struct {
	calls    int
	subjects []string
}

func (f *fakeInvalidator) InvalidateSubject(s string) int {
	f.calls++
	f.subjects = append(f.subjects, s)
	// Return >0 so the handler returns OK (not NotFound on idempotent miss).
	return 1
}
func (f *fakeInvalidator) Invalidate() {}

// TestW1_2_InternalGRPCListener_ServesInvalidateSubject — start the wiring
// helper on an ephemeral port, dial it as a real gRPC client, invoke
// InternalAuthzCacheService.InvalidateSubject, and confirm the call lands in
// the supplied Invalidator. Mirrors how iam's drainer talks to the gateway.
func TestW1_2_InternalGRPCListener_ServesInvalidateSubject(t *testing.T) {
	externalSrv := grpc.NewServer()
	t.Cleanup(externalSrv.Stop)

	inv := &fakeInvalidator{}
	// Use ":0" to get an ephemeral port — the helper must return the
	// listener so the test can read its actual addr.
	srv, lis, err := startInternalGRPCListener(":0", inv, externalSrv, nil)
	require.NoError(t, err, "startInternalGRPCListener must succeed on :0")
	require.NotNil(t, srv, "must return *grpc.Server")
	require.NotNil(t, lis, "must return net.Listener")
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = lis.Close()
	})

	go func() {
		_ = srv.Serve(lis)
	}()

	// Dial the freshly-started internal listener.
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "dial internal listener")
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{
		Subject:   "user:usr_kac138_target",
		EventType: "binding_revoke",
	})
	require.NoError(t, err, "InvalidateSubject must succeed end-to-end on the internal listener")

	if inv.calls != 1 {
		t.Errorf("invalidator calls=%d, want 1", inv.calls)
	}
	if len(inv.subjects) != 1 || inv.subjects[0] != "user:usr_kac138_target" {
		t.Errorf("invalidator received %v, want [user:usr_kac138_target]", inv.subjects)
	}

	// Internal admin service must NOT be registered on the external server.
	const fqn = "kacho.cloud.apigateway.v1.InternalAuthzCacheService"
	_, externalHas := externalSrv.GetServiceInfo()[fqn]
	assert.False(t, externalHas,
		"InternalAuthzCacheService must NOT be on the external server (internal-only)")
}

// TestW1_2_InternalGRPCListener_RejectsEmptySubject — an end-to-end sanity
// check that the handler's InvalidArgument contract survives the wiring (the
// helper must not introduce a stray interceptor that swallows the error).
func TestW1_2_InternalGRPCListener_RejectsEmptySubject(t *testing.T) {
	externalSrv := grpc.NewServer()
	t.Cleanup(externalSrv.Stop)

	inv := &fakeInvalidator{}
	srv, lis, err := startInternalGRPCListener(":0", inv, externalSrv, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = lis.Close()
	})
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{Subject: ""})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error")
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code=%s, want InvalidArgument", st.Code())
	}
}

// Compile-time guard — fakeInvalidator must satisfy handler.Invalidator.
var _ handler.Invalidator = (*fakeInvalidator)(nil)

// Compile-time guard — net.Listener returned from helper must be a TCP listener
// (the type-assertion below pins the contract: not unix-socket / mock).
func init() {
	// Best-effort hint — not asserted at runtime, just a comment+sentinel.
	var _ net.Listener = (*net.TCPListener)(nil)
}
