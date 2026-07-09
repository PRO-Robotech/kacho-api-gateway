// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package opsproxy_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// deadlineCapturingServer records the deadline observed on the backend's
// incoming ctx. A per-call deadline set by OpsProxy propagates over the wire
// (gRPC grpc-timeout header) and surfaces here.
type deadlineCapturingServer struct {
	operationpb.UnimplementedOperationServiceServer
	ops         map[string]*operationpb.Operation
	getHadDL    bool
	getUntil    time.Duration
	cancelHadDL bool
	cancelUntil time.Duration
}

func (m *deadlineCapturingServer) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	if dl, ok := ctx.Deadline(); ok {
		m.getHadDL = true
		m.getUntil = time.Until(dl)
	}
	op, ok := m.ops[req.OperationId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.OperationId)
	}
	return op, nil
}

func (m *deadlineCapturingServer) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	if dl, ok := ctx.Deadline(); ok {
		m.cancelHadDL = true
		m.cancelUntil = time.Until(dl)
	}
	op, ok := m.ops[req.OperationId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.OperationId)
	}
	return op, nil
}

func setupDeadlineBackend(t *testing.T, ops map[string]*operationpb.Operation) (*grpc.ClientConn, *deadlineCapturingServer) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &deadlineCapturingServer{ops: ops}
	srv := grpc.NewServer()
	operationpb.RegisterOperationServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, server
}

// TestOpsProxy_Get_AppliesPerCallDeadline — the backend Get call must carry a
// bounded per-call deadline (parity with every sibling unary client in the
// gateway). Without it a wedged backend pins the handler goroutine + HTTP/2
// stream indefinitely (architecture.md "per-call deadline на КАЖДОМ внешнем
// вызове"). Locks the observable: the outgoing call has a deadline ~ the
// configured short timeout, not "no deadline".
func TestOpsProxy_Get_AppliesPerCallDeadline(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{Id: id, PrincipalType: "system", PrincipalId: "bootstrap"}
	conn, backend := setupDeadlineBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": conn})

	// Incoming ctx carries NO deadline — the proxy must impose its own.
	ctx := withPrincipalMD("bootstrap", "system")
	if _, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !backend.getHadDL {
		t.Fatal("backend Get received no deadline: OpsProxy forwarded the raw request ctx without a per-call timeout")
	}
	if backend.getUntil <= 0 || backend.getUntil > 30*time.Second {
		t.Errorf("Get deadline out of expected bounds: %v (want short, ~seconds)", backend.getUntil)
	}
}

// TestOpsProxy_Cancel_AppliesPerCallDeadline — same invariant on the Cancel path.
func TestOpsProxy_Cancel_AppliesPerCallDeadline(t *testing.T) {
	id := "enp0123456789abcdefg"
	op := &operationpb.Operation{Id: id, PrincipalType: "system", PrincipalId: "bootstrap"}
	conn, backend := setupDeadlineBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": conn})

	ctx := withPrincipalMD("bootstrap", "system")
	if _, err := proxy.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: id}); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if !backend.cancelHadDL {
		t.Fatal("backend Cancel received no deadline: OpsProxy forwarded the raw request ctx without a per-call timeout")
	}
	if backend.cancelUntil <= 0 || backend.cancelUntil > 30*time.Second {
		t.Errorf("Cancel deadline out of expected bounds: %v (want short, ~seconds)", backend.cancelUntil)
	}
}
