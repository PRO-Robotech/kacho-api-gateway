// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package opsproxy

import (
	"testing"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestPrefixToBackend_BoundToCorelibConstants pins the Operation-id routing
// table to the exported kacho-corelib constants (single source of truth). If a
// backend/corelib changes an op-prefix, this fails instead of silently routing
// every new-prefix Operation.Get/Cancel to InvalidArgument.
func TestPrefixToBackend_BoundToCorelibConstants(t *testing.T) {
	want := map[string]string{
		ids.PrefixOperationVPC:     "vpc",          // enp
		prefixOperationVPCSubnet:   "vpc",          // e9b (no corelib const yet)
		ids.PrefixOperationCompute: "compute",      // epd
		prefixOperationIAM:         "iam",          // iop (kacho-iam domain, not importable)
		ids.PrefixOperationNLB:     "loadbalancer", // nlb
		ids.PrefixOperationReg:     "registry",     // rop
		ids.PrefixOperationStorage: "storage",      // sop
	}
	if len(prefixToBackend) != len(want) {
		t.Fatalf("prefixToBackend has %d entries, want %d — a prefix was added/removed without updating the guard", len(prefixToBackend), len(want))
	}
	for k, v := range want {
		got, ok := prefixToBackend[k]
		if !ok {
			t.Errorf("prefix %q missing from prefixToBackend (corelib/gateway drift)", k)
			continue
		}
		if got != v {
			t.Errorf("prefix %q routes to %q, want %q", k, got, v)
		}
	}
	// Every key must be exactly 3 chars (the id-prefix contract).
	for k := range prefixToBackend {
		if len(k) != 3 {
			t.Errorf("prefix key %q is not 3 chars", k)
		}
	}
}

// TestResolveBackend_RoutesEveryKnownPrefix — a fabricated 20-char id for each
// known prefix resolves to the connected backend (no error), and an unknown
// prefix yields InvalidArgument.
func TestResolveBackend_RoutesEveryKnownPrefix(t *testing.T) {
	backends := map[string]operationpb.OperationServiceClient{}
	for _, backend := range prefixToBackend {
		backends[backend] = operationpb.NewOperationServiceClient(nil) //nolint:staticcheck // sentinel non-nil client; never dialled in this test
	}
	p := &OpsProxy{backends: backends}

	for prefix := range prefixToBackend {
		id := ids.NewID(prefix) // "<prefix><17 crockford>" = 20 chars
		if _, err := p.resolveBackend(id); err != nil {
			t.Errorf("resolveBackend(%q) prefix %q: unexpected error %v", id, prefix, err)
		}
	}

	// Unknown 3-char prefix → InvalidArgument.
	if _, err := p.resolveBackend(ids.NewID("zzz")); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown-prefix id: got %v, want InvalidArgument", err)
	}
}
