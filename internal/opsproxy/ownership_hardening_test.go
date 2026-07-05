// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package opsproxy_test

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// TestOpsProxy_Get_OwnershipCheck_DeniesTenantReadingSystemOwnedOp — an operation
// whose recorded owner is system/bootstrap (a backend that did NOT mount the
// principal-extract interceptor stamps every Operation with the system principal)
// must NOT be world-readable on the public surface. A tenant caller reading such
// an operation is a cross-tenant BOLA (CWE-639); it must fail closed. Only an
// internal system/bootstrap caller may read a system-owned operation.
func TestOpsProxy_Get_OwnershipCheck_DeniesTenantReadingSystemOwnedOp(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "system",
		PrincipalId:   "bootstrap",
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("usr_tenant", "user")
	_, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err == nil {
		t.Fatal("expected PermissionDenied for tenant reading a system-owned operation")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %s", st.Code())
	}
}

// TestOpsProxy_Cancel_OwnershipCheck_DeniesTenantCancelingSystemOwnedOp — same
// fail-closed rule for Cancel.
func TestOpsProxy_Cancel_OwnershipCheck_DeniesTenantCancelingSystemOwnedOp(t *testing.T) {
	id := "enp0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "system",
		PrincipalId:   "bootstrap",
	}
	vpcConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"vpc": vpcConn})

	ctx := withPrincipalMD("usr_tenant", "user")
	_, err := proxy.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: id})
	if err == nil {
		t.Fatal("expected PermissionDenied for tenant canceling a system-owned operation")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %s", st.Code())
	}
}

// TestOpsProxy_Get_OwnershipCheck_AllowsSystemCallerReadingSystemOwnedOp — an
// internal system/bootstrap caller (worker) may still read a system-owned
// operation; the hardening only closes the tenant path.
func TestOpsProxy_Get_OwnershipCheck_AllowsSystemCallerReadingSystemOwnedOp(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "system",
		PrincipalId:   "bootstrap",
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("bootstrap", "system")
	resp, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("system caller must read a system-owned op: %v", err)
	}
	if resp.Id != id {
		t.Errorf("expected %q, got %q", id, resp.Id)
	}
}

// TestOpsProxy_Get_OwnershipCheck_DeniesTypeMismatch — the ownership guard must
// compare principal_type as well as principal_id (defense-in-depth against an id
// collision across principal types). A service_account whose id equals a user's
// id must NOT be able to read that user's operation.
func TestOpsProxy_Get_OwnershipCheck_DeniesTypeMismatch(t *testing.T) {
	id := "iop0123456789abcdefg"
	op := &operationpb.Operation{
		Id:            id,
		PrincipalType: "user",
		PrincipalId:   "collide_id",
	}
	iamConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})
	proxy := opsproxy.New(map[string]*grpc.ClientConn{"iam": iamConn})

	ctx := withPrincipalMD("collide_id", "service_account")
	_, err := proxy.Get(ctx, &operationpb.GetOperationRequest{OperationId: id})
	if err == nil {
		t.Fatal("expected PermissionDenied for principal_type mismatch on colliding id")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %s", st.Code())
	}
}
