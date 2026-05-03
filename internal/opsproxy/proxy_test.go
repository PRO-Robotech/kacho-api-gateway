package opsproxy_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// mockOperationServer — простой mock для тестирования OpsProxy.
type mockOperationServer struct {
	operationpb.UnimplementedOperationServiceServer
	// ops — карта operation_id → Operation
	ops map[string]*operationpb.Operation
}

func (m *mockOperationServer) Get(_ context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	op, ok := m.ops[req.OperationId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.OperationId)
	}
	return op, nil
}

func (m *mockOperationServer) Cancel(_ context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	op, ok := m.ops[req.OperationId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.OperationId)
	}
	return op, nil
}

// setupMockBackend запускает mock gRPC backend с OperationService.
func setupMockBackend(t *testing.T, ops map[string]*operationpb.Operation) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	operationpb.RegisterOperationServiceServer(srv, &mockOperationServer{ops: ops})
	go srv.Serve(lis)
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestOpsProxy_Get_RoutesToCorrectBackend проверяет роутинг Get по domain-prefix.
func TestOpsProxy_Get_RoutesToCorrectBackend(t *testing.T) {
	rmOp := &operationpb.Operation{Id: "rm_abc123", Description: "create cloud"}
	vpcOp := &operationpb.Operation{Id: "vpc_def456", Description: "create network"}

	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{"rm_abc123": rmOp})
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_def456": vpcOp})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{
		"resourcemanager": rmConn,
		"vpc":             vpcConn,
	})

	ctx := context.Background()

	// rm_ prefix → resourcemanager backend
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: "rm_abc123"})
	if err != nil {
		t.Fatalf("Get rm: %v", err)
	}
	if resp.Id != "rm_abc123" {
		t.Errorf("ожидали rm_abc123, получили %q", resp.Id)
	}

	// vpc_ prefix → vpc backend
	resp, err = proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: "vpc_def456"})
	if err != nil {
		t.Fatalf("Get vpc: %v", err)
	}
	if resp.Id != "vpc_def456" {
		t.Errorf("ожидали vpc_def456, получили %q", resp.Id)
	}
}

// TestOpsProxy_Get_OrgPrefixRoutesToResourceManager проверяет, что org_ → resourcemanager.
func TestOpsProxy_Get_OrgPrefixRoutesToResourceManager(t *testing.T) {
	orgOp := &operationpb.Operation{Id: "org_org1", Description: "create organization"}
	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{"org_org1": orgOp})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{
		"resourcemanager": rmConn,
	})

	resp, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "org_org1"})
	if err != nil {
		t.Fatalf("Get org: %v", err)
	}
	if resp.Id != "org_org1" {
		t.Errorf("ожидали org_org1, получили %q", resp.Id)
	}
}

// TestOpsProxy_Get_ResourcemanagerPrefixRoutesToRM проверяет resourcemanager_ prefix.
func TestOpsProxy_Get_ResourcemanagerPrefixRoutesToRM(t *testing.T) {
	op := &operationpb.Operation{Id: "resourcemanager_op1"}
	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{"resourcemanager_op1": op})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{
		"resourcemanager": rmConn,
	})

	resp, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "resourcemanager_op1"})
	if err != nil {
		t.Fatalf("Get resourcemanager prefix: %v", err)
	}
	if resp.Id != "resourcemanager_op1" {
		t.Errorf("ожидали resourcemanager_op1, получили %q", resp.Id)
	}
}

// TestOpsProxy_Get_UnknownDomain проверяет NOT_FOUND для неизвестного domain-prefix.
func TestOpsProxy_Get_UnknownDomain(t *testing.T) {
	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"resourcemanager": rmConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "unknown_xyz"})
	if err == nil {
		t.Fatal("ожидали ошибку для неизвестного domain")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Errorf("ожидали NOT_FOUND, получили %v", err)
	}
}

// TestOpsProxy_Get_InvalidIDFormat проверяет INVALID_ARGUMENT для id без prefix.
func TestOpsProxy_Get_InvalidIDFormat(t *testing.T) {
	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"resourcemanager": rmConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "noprefixid"})
	if err == nil {
		t.Fatal("ожидали ошибку для id без prefix")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("ожидали INVALID_ARGUMENT, получили %v", err)
	}
}

// TestOpsProxy_Cancel_RoutesToCorrectBackend проверяет роутинг Cancel.
func TestOpsProxy_Cancel_RoutesToCorrectBackend(t *testing.T) {
	op := &operationpb.Operation{Id: "vpc_op1"}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_op1": op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	resp, err := proxy.Cancel(context.Background(), &operationpb.CancelOperationRequest{OperationId: "vpc_op1"})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if resp.Id != "vpc_op1" {
		t.Errorf("ожидали vpc_op1, получили %q", resp.Id)
	}
}

// TestOpsProxy_Cancel_RmPrefix проверяет Cancel с rm_ prefix.
func TestOpsProxy_Cancel_RmPrefix(t *testing.T) {
	op := &operationpb.Operation{Id: "rm_cancel1"}
	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{"rm_cancel1": op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"resourcemanager": rmConn})

	resp, err := proxy.Cancel(context.Background(), &operationpb.CancelOperationRequest{OperationId: "rm_cancel1"})
	if err != nil {
		t.Fatalf("Cancel rm: %v", err)
	}
	if resp.Id != "rm_cancel1" {
		t.Errorf("ожидали rm_cancel1, получили %q", resp.Id)
	}
}
