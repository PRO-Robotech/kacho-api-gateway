// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package opsproxy_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestOpsProxy_Get_RoutesToCorrectBackend проверяет роутинг Get по domain-prefix.
func TestOpsProxy_Get_RoutesToCorrectBackend(t *testing.T) {
	vpcOp := &operationpb.Operation{Id: "vpc_def456", Description: "create network"}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_def456": vpcOp})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{
		"vpc": vpcConn,
	})

	// Routing probe: owner-less op with the authorized internal system caller
	// (ownership semantics are covered by the dedicated OwnershipCheck tests).
	ctx := withPrincipalMD("bootstrap", "system")
	// vpc_ legacy prefix → vpc backend
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: "vpc_def456"})
	if err != nil {
		t.Fatalf("Get vpc: %v", err)
	}
	if resp.Id != "vpc_def456" {
		t.Errorf("ожидали vpc_def456, получили %q", resp.Id)
	}
}

// TestOpsProxy_Get_RmLegacyPrefixesRemoved — rm_/org_/resourcemanager_/
// organizationmanager_ legacy префиксы не в known set; запросы возвращают
// INVALID_ARGUMENT (как и любой неизвестный legacy-prefix).
func TestOpsProxy_Get_RmLegacyPrefixesRemoved(t *testing.T) {
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	removedPrefixes := []string{"rm_abc", "resourcemanager_x", "org_y", "organizationmanager_z"}
	for _, id := range removedPrefixes {
		id := id
		t.Run(id, func(t *testing.T) {
			_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: id})
			if err == nil {
				t.Fatalf("ожидали ошибку для удаленного legacy-prefix %q", id)
			}
			st, _ := status.FromError(err)
			if st.Code() != codes.InvalidArgument {
				t.Errorf("%q: ожидали INVALID_ARGUMENT, получили %s", id, st.Code())
			}
		})
	}
}

// TestOpsProxy_Get_UnknownDomain проверяет INVALID_ARGUMENT для unknown legacy prefix
// (legacy prefix не из known set → 3, как и любой синтаксис без prefix).
func TestOpsProxy_Get_UnknownDomain(t *testing.T) {
	rmConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"resourcemanager": rmConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "unknown_xyz"})
	if err == nil {
		t.Fatal("ожидали ошибку для неизвестного domain")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("ожидали INVALID_ARGUMENT (unknown prefix), получили %v", err)
	}
}

// TestOpsProxy_Get_RmPrefixIs_InvalidArgument — b1g/bpf prefixes
// не в known set; 20-char id с ними возвращает INVALID_ARGUMENT.
func TestOpsProxy_Get_RmPrefixIs_InvalidArgument(t *testing.T) {
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	for _, id := range []string{"b1g0123456789abcdefg", "bpf0123456789abcdefg"} {
		id := id
		t.Run(id, func(t *testing.T) {
			_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: id})
			if err == nil {
				t.Fatalf("ожидали ошибку для удаленного prefix %q", id)
			}
			st, _ := status.FromError(err)
			if st.Code() != codes.InvalidArgument {
				t.Errorf("ожидали INVALID_ARGUMENT, получили %s", st.Code())
			}
		})
	}
}

// TestOpsProxy_Get_NewFormatVPC проверяет роутинг новых 20-char id с
// 3-char prefix enp (vpc).
func TestOpsProxy_Get_NewFormatVPC(t *testing.T) {
	id := "enpfedcba98765432109" // 20 chars
	op := &operationpb.Operation{Id: id, Description: "create network (new fmt)"}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	// Routing probe: owner-less op with the authorized internal system caller.
	resp, err := proxy.Get(withPrincipalMD("bootstrap", "system"), &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get enp…: %v", err)
	}
	if resp.Id != id {
		t.Errorf("ожидали %q, получили %q", id, resp.Id)
	}
}

// TestOpsProxy_Get_NewFormatNLB проверяет роутинг 20-char id с 3-char
// prefix nlb (loadbalancer/kacho-nlb — все операции домена делят этот prefix,
// PrefixOperationNLB == PrefixLoadBalancer в kacho-corelib/ids).
func TestOpsProxy_Get_NewFormatNLB(t *testing.T) {
	id := "nlb0123456789abcdefg" // 20 chars, nlb prefix
	op := &operationpb.Operation{Id: id, Description: "create network load balancer"}
	nlbConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{"loadbalancer": nlbConn})

	// Routing probe: owner-less op with the authorized internal system caller.
	ctx := withPrincipalMD("bootstrap", "system")
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get nlb…: %v", err)
	}
	if resp.Id != id {
		t.Errorf("ожидали %q, получили %q", id, resp.Id)
	}

	// Cancel должен ходить туда же.
	if _, err := proxy.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: id}); err != nil {
		t.Fatalf("Cancel nlb…: %v", err)
	}
}

// TestOpsProxy_Get_NewFormatCompute проверяет роутинг 20-char id с 3-char
// prefix epd (compute — все операции домена делят этот prefix).
func TestOpsProxy_Get_NewFormatCompute(t *testing.T) {
	id := "epd0123456789abcdefg" // 20 chars
	op := &operationpb.Operation{Id: id, Description: "create instance"}
	computeConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{"compute": computeConn})

	// Routing probe: owner-less op with the authorized internal system caller.
	ctx := withPrincipalMD("bootstrap", "system")
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get epd…: %v", err)
	}
	if resp.Id != id {
		t.Errorf("ожидали %q, получили %q", id, resp.Id)
	}

	// Cancel должен ходить туда же.
	if _, err := proxy.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: id}); err != nil {
		t.Fatalf("Cancel epd…: %v", err)
	}
}

// TestOpsProxy_Get_InvalidIDFormat проверяет INVALID_ARGUMENT для id без prefix.
func TestOpsProxy_Get_InvalidIDFormat(t *testing.T) {
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "noprefixid"})
	if err == nil {
		t.Fatal("ожидали ошибку для id без prefix")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("ожидали INVALID_ARGUMENT, получили %v", err)
	}
}

// TestOpsProxy_Get_UnknownPrefix_20chars: 20-символьный id с неизвестным prefix → InvalidArgument.
func TestOpsProxy_Get_UnknownPrefix_20chars(t *testing.T) {
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "zzz0123456789abcdefg"})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("ожидали INVALID_ARGUMENT, получили %v", err)
	}
}

// TestOpsProxy_Get_KnownPrefixNoBackend: enp-prefix известен, но vpc backend не подключен → NotFound.
func TestOpsProxy_Get_KnownPrefixNoBackend(t *testing.T) {
	// Подключаем ТОЛЬКО compute; запрос на enp-id (vpc) → vpc-backend отсутствует.
	computeConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"compute": computeConn})

	_, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: "enp0123456789abcdefg"})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Errorf("ожидали NOT_FOUND, получили %v", err)
	}
}

// TestOpsProxy_Cancel_RoutesToCorrectBackend проверяет роутинг Cancel.
func TestOpsProxy_Cancel_RoutesToCorrectBackend(t *testing.T) {
	op := &operationpb.Operation{Id: "vpc_op1"}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{"vpc_op1": op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	// Routing probe: owner-less op with the authorized internal system caller.
	resp, err := proxy.Cancel(withPrincipalMD("bootstrap", "system"), &operationpb.CancelOperationRequest{OperationId: "vpc_op1"})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if resp.Id != "vpc_op1" {
		t.Errorf("ожидали vpc_op1, получили %q", resp.Id)
	}
}

// withPrincipalMD — ctx с incoming gRPC metadata для principal (имитирует
// grpc-gateway WithMetadata callback после auth.HTTP).
func withPrincipalMD(id, ptype string) context.Context {
	md := metadata.New(map[string]string{
		"x-kacho-principal-id":   id,
		"x-kacho-principal-type": ptype,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

// TestOpsProxy_Get_OwnershipCheck_AllowsOwner — owner principal видит свою операцию.
// Ownership check не блокирует владельца.
func TestOpsProxy_Get_OwnershipCheck_AllowsOwner(t *testing.T) {
	id := "iop0123456789abcdefg" // 20 chars, iam prefix
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner1",
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("usr_owner1", "user")
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get own operation: %v", err)
	}
	if resp.Id != id {
		t.Errorf("ожидали %q, получили %q", id, resp.Id)
	}
}

// TestOpsProxy_Get_OwnershipCheck_DeniesOther — чужой principal не видит операцию.
// Ownership check блокирует доступ к чужой операции (PermissionDenied).
func TestOpsProxy_Get_OwnershipCheck_DeniesOther(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner1",
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("usr_other", "user")
	_, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err == nil {
		t.Fatal("ожидали ошибку для чужого principal")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("ожидали PERMISSION_DENIED, получили %s", st.Code())
	}
}

// TestOpsProxy_Get_OwnershipCheck_AllowsBootstrap — system/bootstrap пропускается
// (внутренние воркеры, не tenant).
func TestOpsProxy_Get_OwnershipCheck_AllowsBootstrap(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner1",
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("bootstrap", "system")
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get as bootstrap: %v", err)
	}
	if resp.Id != id {
		t.Errorf("ожидали %q, получили %q", id, resp.Id)
	}
}

// TestOpsProxy_Get_OwnershipCheck_DeniesTenantReadingOwnerlessOp — операция без
// записанного owner'а (пустой principal_id: legacy pre-owner-tracking строка) НЕ
// world-readable на публичной поверхности. Реальный owner неизвестен, поэтому
// tenant-caller получает PermissionDenied (fail-closed, defense-in-depth против
// cross-tenant BOLA — CWE-639). Внутренний system-caller по-прежнему её читает
// (см. TestOpsProxy_Get_OwnershipCheck_AllowsSystemCallerReadingOwnerlessOp в
// ownership_hardening_test.go).
func TestOpsProxy_Get_OwnershipCheck_DeniesTenantReadingOwnerlessOp(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id: id,
		// PrincipalType / PrincipalId отсутствуют (legacy op без owner'а)
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("usr_anyone", "user")
	_, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err == nil {
		t.Fatal("ожидали PermissionDenied для tenant, читающего операцию без owner'а")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("ожидали PERMISSION_DENIED, получили %s", st.Code())
	}
}

// TestOpsProxy_Cancel_OwnershipCheck_DeniesOther — Cancel тоже требует ownership.
func TestOpsProxy_Cancel_OwnershipCheck_DeniesOther(t *testing.T) {
	id := "enp0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner2",
	}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	ctx := withPrincipalMD("usr_attacker", "user")
	_, err := proxy.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: id})
	if err == nil {
		t.Fatal("ожидали ошибку для чужого Cancel")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("ожидали PERMISSION_DENIED, получили %s", st.Code())
	}
}

// TestOpsProxy_Cancel_RmLegacyPrefixRemoved — Cancel с rm_… возвращает InvalidArgument.
func TestOpsProxy_Cancel_RmLegacyPrefixRemoved(t *testing.T) {
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	_, err := proxy.Cancel(context.Background(), &operationpb.CancelOperationRequest{OperationId: "rm_cancel1"})
	if err == nil {
		t.Fatal("ожидали ошибку для удаленного rm_ legacy-prefix")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("ожидали INVALID_ARGUMENT, получили %s", st.Code())
	}
}

// principalCapturingServer — mock backend, который захватывает x-kacho-principal-*
// headers из incoming metadata своего gRPC-вызова. Это имитирует поведение
// production IAM/VPC backend, который читает principal-headers из своей incoming
// gRPC-ctx (через ту же `metadata.FromIncomingContext`).
//
// Проверяет, что opsproxy конвертирует incoming-md
// (set restmux-WithMetadata) → outgoing-md перед вызовом backend.Get/Cancel.
type principalCapturingServer struct {
	operationpb.UnimplementedOperationServiceServer
	ops              map[string]*operationpb.Operation
	receivedID       string
	receivedType     string
	receivedDispName string
}

func (m *principalCapturingServer) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-kacho-principal-id"); len(v) > 0 {
			m.receivedID = v[0]
		}
		if v := md.Get("x-kacho-principal-type"); len(v) > 0 {
			m.receivedType = v[0]
		}
		if v := md.Get("x-kacho-principal-display-name"); len(v) > 0 {
			m.receivedDispName = v[0]
		}
	}
	op, ok := m.ops[req.OperationId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.OperationId)
	}
	return op, nil
}

func (m *principalCapturingServer) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-kacho-principal-id"); len(v) > 0 {
			m.receivedID = v[0]
		}
		if v := md.Get("x-kacho-principal-type"); len(v) > 0 {
			m.receivedType = v[0]
		}
	}
	op, ok := m.ops[req.OperationId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "operation %q not found", req.OperationId)
	}
	return op, nil
}

// setupCapturingBackend — analog setupMockBackend для principalCapturingServer.
// Возвращает (conn, server) — server-handle нужен, чтобы тесты могли проверить
// захваченные headers после вызова.
func setupCapturingBackend(t *testing.T, ops map[string]*operationpb.Operation) (*grpc.ClientConn, *principalCapturingServer) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &principalCapturingServer{ops: ops}
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

// TestOpsProxy_Get_PropagatesPrincipalMetadata — проверяет проброс principal.
//
// restmux/mux.go ставит x-kacho-principal-* в INCOMING gRPC metadata через
// WithMetadata callback. Если opsproxy.Get вызовет `client.Get(ctx, req)` без
// конверсии incoming→outgoing, backend (IAM) получит анонимный principal в своей
// incoming metadata, IsSelf-check провалится и вернет NotFound тому же user'у,
// кто create-нул операцию.
//
// Тот же проброс incoming→outgoing metadata реализован в
// internal/proxy/server.go (Resolver) и shimproxy.go — opsproxy повторяет этот
// подход. Backend обязан увидеть проброшенный principal (receivedID == "usr_owner1").
func TestOpsProxy_Get_PropagatesPrincipalMetadata(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner1",
	}
	iamConn, backend := setupCapturingBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("usr_owner1", "user")
	_, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if backend.receivedID != "usr_owner1" {
		t.Errorf("backend должен был получить principal-id %q, получил %q (opsproxy не пробросил incoming metadata в outgoing)", "usr_owner1", backend.receivedID)
	}
	if backend.receivedType != "user" {
		t.Errorf("backend должен был получить principal-type %q, получил %q", "user", backend.receivedType)
	}
}

// TestOpsProxy_Cancel_PropagatesPrincipalMetadata — аналог
// TestOpsProxy_Get_PropagatesPrincipalMetadata для Cancel-пути.
func TestOpsProxy_Cancel_PropagatesPrincipalMetadata(t *testing.T) {
	id := "enp0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner2",
	}
	vpcConn, backend := setupCapturingBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	ctx := withPrincipalMD("usr_owner2", "user")
	_, err := proxy.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if backend.receivedID != "usr_owner2" {
		t.Errorf("backend должен был получить principal-id %q, получил %q (opsproxy не пробросил incoming metadata в outgoing)", "usr_owner2", backend.receivedID)
	}
}

// TestOpsProxy_Get_PropagatesDisplayName — полный набор principal-headers.
// restmux ставит 3 заголовка: principal-type, principal-id, principal-display-name.
// Все три должны доходить до backend.
func TestOpsProxy_Get_PropagatesDisplayName(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "usr_owner1",
	}
	iamConn, backend := setupCapturingBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	// ctx с display-name (имитирует full WithMetadata output)
	md := metadata.New(map[string]string{
		"x-kacho-principal-id":           "usr_owner1",
		"x-kacho-principal-type":         "user",
		"x-kacho-principal-display-name": "Alice Owner",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if backend.receivedDispName != "Alice Owner" {
		t.Errorf("backend должен был получить display-name %q, получил %q", "Alice Owner", backend.receivedDispName)
	}
}
