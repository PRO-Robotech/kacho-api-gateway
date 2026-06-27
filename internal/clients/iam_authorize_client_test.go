// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/clients"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// stubAuthorizeServer — programmable AuthorizeService implementation for
// tests (no FGA backend needed).
type stubAuthorizeServer struct {
	iamv1.UnimplementedAuthorizeServiceServer
	calls atomic.Int64

	// behaviour controls.
	allowed      bool
	reasons      []string
	failureCount atomic.Int32 // first N calls return Unavailable
	delay        time.Duration
	lastReq      atomic.Pointer[iamv1.AuthorizeCheckRequest]
}

func (s *stubAuthorizeServer) Check(ctx context.Context, req *iamv1.AuthorizeCheckRequest) (*iamv1.AuthorizeCheckResponse, error) {
	s.calls.Add(1)
	// Store the request pointer directly — proto messages hold an internal
	// lock and must not be value-copied (go vet warns "assignment copies lock value").
	s.lastReq.Store(req)
	if s.failureCount.Load() > 0 {
		s.failureCount.Add(-1)
		return nil, status.Error(codes.Unavailable, "transient failure")
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &iamv1.AuthorizeCheckResponse{
		Allowed:              s.allowed,
		DenyReasons:          s.reasons,
		AuthorizationModelId: "model_test",
		CheckedAt:            timestamppb.Now(),
	}, nil
}

func startStubServer(t *testing.T, stub *stubAuthorizeServer) (addr string, cleanup func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	iamv1.RegisterAuthorizeServiceServer(srv, stub)
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), func() {
		srv.GracefulStop()
		_ = lis.Close()
	}
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestIAMAuthorizeClient_NewRequiresAddr(t *testing.T) {
	_, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{Logger: silentLogger()})
	require.Error(t, err)
}

func TestIAMAuthorizeClient_NewRequiresLogger(t *testing.T) {
	_, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{Addr: "x:9090"})
	require.Error(t, err)
}

func TestIAMAuthorizeClient_Check_Allow(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:    addr,
		Timeout: 2 * time.Second,
		Logger:  silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	res, err := client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.create",
		ResourceType: "project",
		ResourceID:   "prj_y",
		Context:      map[string]any{"acr_value": "2"},
		TraceID:      "trace-1",
	})
	require.NoError(t, err)
	assert.True(t, res.Allowed)
	assert.Equal(t, "model_test", res.AuthorizationModelID)
	assert.Equal(t, int64(1), stub.calls.Load())

	last := stub.lastReq.Load()
	require.NotNil(t, last)
	assert.Equal(t, "user:usr_x", last.GetSubject())
	assert.Equal(t, "vpc.networks.create", last.GetAction())
	assert.Equal(t, "trace-1", last.GetTraceId())
	require.NotNil(t, last.GetContext())
	assert.Equal(t, "2", last.GetContext().GetFields()["acr_value"].GetStringValue())
}

func TestIAMAuthorizeClient_Check_Deny(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: false, reasons: []string{"no path"}}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:   addr,
		Logger: silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	res, err := client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.delete",
		ResourceType: "vpc_network",
		ResourceID:   "enp_y",
	})
	require.NoError(t, err)
	assert.False(t, res.Allowed)
	assert.Equal(t, []string{"no path"}, res.DenyReasons)
}

func TestIAMAuthorizeClient_Check_RetriesOnUnavailable(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true}
	stub.failureCount.Store(1)
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:       addr,
		MaxRetries: 1,
		Timeout:    2 * time.Second,
		Logger:     silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	res, err := client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.get",
		ResourceType: "vpc_network",
		ResourceID:   "enp_y",
	})
	require.NoError(t, err)
	assert.True(t, res.Allowed)
	assert.Equal(t, int64(2), stub.calls.Load())
	// Internal counter — one initial + one retry.
	assert.Equal(t, int64(2), client.CallsTotal())
}

func TestIAMAuthorizeClient_Check_PermissionDeniedNotRetried(t *testing.T) {
	// Stub forced to always return PermissionDenied.
	type denyServer struct {
		iamv1.UnimplementedAuthorizeServiceServer
		calls atomic.Int32
	}
	d := &denyServer{}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	iamv1.RegisterAuthorizeServiceServer(srv, &denyAuthorizeWrapper{count: &d.calls})
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()
	defer func() { _ = lis.Close() }()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:       lis.Addr().String(),
		MaxRetries: 3,
		Logger:     silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.delete",
		ResourceType: "vpc_network",
		ResourceID:   "enp_y",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, int32(1), d.calls.Load(), "must not retry on PermissionDenied")
}

type denyAuthorizeWrapper struct {
	iamv1.UnimplementedAuthorizeServiceServer
	count *atomic.Int32
}

func (d *denyAuthorizeWrapper) Check(ctx context.Context, req *iamv1.AuthorizeCheckRequest) (*iamv1.AuthorizeCheckResponse, error) {
	d.count.Add(1)
	return nil, status.Error(codes.PermissionDenied, "explicit FGA deny")
}

func TestIAMAuthorizeClient_Check_TimeoutEnforced(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true, delay: 500 * time.Millisecond}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:       addr,
		Timeout:    50 * time.Millisecond,
		MaxRetries: 0, // disable retries so we observe a single timeout
		Logger:     silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.get",
		ResourceType: "vpc_network",
		ResourceID:   "enp_y",
	})
	require.Error(t, err)
	code := status.Code(err)
	// Either DeadlineExceeded (rare) or just an error from gRPC, but
	// crucially the call did terminate before the 500ms delay.
	assert.NotEqual(t, codes.OK, code)
}

func TestIAMAuthorizeClient_Check_EmptyFieldsRejected(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:   addr,
		Logger: silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "",
		Action:       "vpc.networks.create",
		ResourceType: "project",
		ResourceID:   "prj_y",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty subject")
}

func TestIAMAuthorizeClient_Check_WildcardResource(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:   addr,
		Logger: silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.list",
		ResourceType: "project",
		ResourceID:   "", // wildcard — adapter rewrites to "*"
	})
	require.NoError(t, err)
	last := stub.lastReq.Load()
	require.NotNil(t, last)
	assert.Equal(t, "*", last.GetResource().GetId())
}

func TestIAMAuthorizeClient_ContextWithCoerciblePrimitives(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	client, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:   addr,
		Logger: silentLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Check(context.Background(), clients.AuthorizeCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.get",
		ResourceType: "project",
		ResourceID:   "prj_y",
		Context: map[string]any{
			"current_time": int64(1700000000),
			"amr_claims":   []string{"webauthn"},
		},
	})
	require.NoError(t, err)
	last := stub.lastReq.Load()
	require.NotNil(t, last)
	require.NotNil(t, last.GetContext())
	assert.Equal(t, float64(1700000000), last.GetContext().GetFields()["current_time"].GetNumberValue())
}

// TestAuthzChecker_AdapterSatisfiesInterface ensures the clients.AuthzChecker
// shape satisfies middleware.AuthorizeChecker at compile + runtime.
func TestAuthzChecker_AdapterSatisfiesInterface(t *testing.T) {
	stub := &stubAuthorizeServer{allowed: true}
	addr, cleanup := startStubServer(t, stub)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	inner := clients.NewIAMAuthorizeClientFromConn(conn, silentLogger(), 1*time.Second, 1)
	defer func() { _ = inner.Close() }()

	checker := clients.NewAuthzChecker(inner)
	var ifc middleware.AuthorizeChecker = checker

	res, err := ifc.Check(context.Background(), middleware.AuthzCheckInput{
		Subject:      "user:usr_x",
		Action:       "vpc.networks.get",
		ResourceType: "vpc_network",
		ResourceID:   "enp_y",
	})
	require.NoError(t, err)
	assert.True(t, res.Allowed)
}
