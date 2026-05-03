package opsproxy_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// mockOperationServer — простой mock для тестирования OpsProxy.
type mockOperationServer struct {
	operationpb.UnimplementedOperationServiceServer
	ops map[string]*operationpb.Operation
}

func (m *mockOperationServer) Get(_ context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	op, ok := m.ops[req.Id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.Id)
	}
	return op, nil
}

func (m *mockOperationServer) List(_ context.Context, _ *operationpb.ListOperationsRequest) (*operationpb.ListOperationsResponse, error) {
	var ops []*operationpb.Operation
	for _, op := range m.ops {
		ops = append(ops, op)
	}
	return &operationpb.ListOperationsResponse{Operations: ops}, nil
}

func (m *mockOperationServer) Cancel(_ context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	op, ok := m.ops[req.Id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.Id)
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
	computeOp := &operationpb.Operation{Id: "compute_abc123", Description: "create instance"}
	vpcOp := &operationpb.Operation{Id: "vpc_def456", Description: "create network"}

	computeConn := setupMockBackend(t, map[string]*operationpb.Operation{"compute_abc123": computeOp})
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_def456": vpcOp})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{
		"compute": computeConn,
		"vpc":     vpcConn,
	})

	ctx := context.Background()

	// Запрос к compute backend
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{Id: "compute_abc123"})
	if err != nil {
		t.Fatalf("Get compute: %v", err)
	}
	if resp.Id != "compute_abc123" {
		t.Errorf("ожидали compute_abc123, получили %q", resp.Id)
	}

	// Запрос к vpc backend
	resp, err = proxy.Get(ctx, &operationpb.GetOperationRequest{Id: "vpc_def456"})
	if err != nil {
		t.Fatalf("Get vpc: %v", err)
	}
	if resp.Id != "vpc_def456" {
		t.Errorf("ожидали vpc_def456, получили %q", resp.Id)
	}
}

// TestOpsProxy_Get_UnknownDomain проверяет NOT_FOUND для неизвестного domain-prefix.
func TestOpsProxy_Get_UnknownDomain(t *testing.T) {
	computeConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"compute": computeConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{Id: "unknown_xyz"})
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
	computeConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"compute": computeConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{Id: "noprefixid"})
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
	op := &operationpb.Operation{Id: "loadbalancer_op1"}
	lbConn := setupMockBackend(t, map[string]*operationpb.Operation{"loadbalancer_op1": op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"loadbalancer": lbConn})

	resp, err := proxy.Cancel(context.Background(), &operationpb.CancelOperationRequest{Id: "loadbalancer_op1"})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if resp.Id != "loadbalancer_op1" {
		t.Errorf("ожидали loadbalancer_op1, получили %q", resp.Id)
	}
}

// TestOpsProxy_List_WithResourceID проверяет роутинг List по resource_id prefix.
func TestOpsProxy_List_WithResourceID(t *testing.T) {
	op := &operationpb.Operation{Id: "vpc_op2"}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_op2": op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	// resource_id с domain-prefix "vpc_net1" роутится на vpc-backend
	resp, err := proxy.List(context.Background(), &operationpb.ListOperationsRequest{ResourceId: "vpc_net1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// mock возвращает все операции (фильтрация по resource_id не проверяет vpc_net1 точно)
	_ = resp
}

// TestOpsProxy_List_BroadcastNoResourceID проверяет broadcast List без resource_id.
func TestOpsProxy_List_BroadcastNoResourceID(t *testing.T) {
	computeOp := &operationpb.Operation{Id: "compute_op1"}
	vpcOp := &operationpb.Operation{Id: "vpc_op1"}

	computeConn := setupMockBackend(t, map[string]*operationpb.Operation{"compute_op1": computeOp})
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_op1": vpcOp})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{
		"compute": computeConn,
		"vpc":     vpcConn,
	})

	resp, err := proxy.List(context.Background(), &operationpb.ListOperationsRequest{})
	if err != nil {
		t.Fatalf("List broadcast: %v", err)
	}
	// При broadcast оба backend возвращают по 1 операции — итого 2.
	if len(resp.Operations) < 2 {
		t.Errorf("ожидали 2+ операции, получили %d", len(resp.Operations))
	}
}
