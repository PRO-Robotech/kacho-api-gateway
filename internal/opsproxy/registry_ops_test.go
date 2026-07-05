// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package opsproxy_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
)

// TestOpsProxy_Get_NewFormatRegistry проверяет роутинг 20-char id с 3-char
// prefix rop (registry — все операции домена делят этот prefix,
// PrefixOperationReg == "rop" в kacho-corelib/ids). Operation.Get/Cancel для
// registry-операций должны маршрутизироваться в registry backend.
func TestOpsProxy_Get_NewFormatRegistry(t *testing.T) {
	id := "rop0123456789abcdefg" // 20 chars, rop prefix
	op := &operationpb.Operation{Id: id, Description: "create registry"}
	registryConn := setupMockBackend(t, map[string]*operationpb.Operation{id: op})

	proxy := opsproxy.New(map[string]*grpc.ClientConn{"registry": registryConn})

	resp, err := proxy.Get(context.Background(), &operationpb.GetOperationRequest{OperationId: id})
	if err != nil {
		t.Fatalf("Get rop…: %v", err)
	}
	if resp.Id != id {
		t.Errorf("ожидали %q, получили %q", id, resp.Id)
	}

	// Cancel должен ходить туда же.
	if _, err := proxy.Cancel(context.Background(), &operationpb.CancelOperationRequest{OperationId: id}); err != nil {
		t.Fatalf("Cancel rop…: %v", err)
	}
}
