// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A server-streaming RPC is gated ONCE before the stream runs, at which point
// the client request message has not been read — the authz middleware sees a
// nil ProtoReq. For an entry whose scope is a CONCRETE per-resource id
// (from_request_field names a real resource-id field), the scope id therefore
// cannot be resolved. Defaulting such an entry to the wildcard scope "*" would
// collapse the FGA Check to `<type>:*` and authorize the caller for EVERY
// resource of that type. The stream interceptor must instead FAIL CLOSED
// (deny) so a concrete-scope streaming RPC can never be authorized against an
// over-broad wildcard scope; the FGA Check must not even run.
//
// streamWildcardEntry is a NON-concrete (wildcard) scope entry — the shape all
// real streaming RPCs use today (Subscribe/Watch). It has no concrete id to
// resolve, so it is legitimately gated at the type/singleton scope and the
// checker decides.
const streamWildcardEntry = `{"fqn":"kacho.cloud.compute.v1.InternalWatchService/Watch","permission":"compute.watch","required_relation":"viewer","scope_extractor":{"object_type":"cluster","from_request_field":"*"},"required_acr_min":"2"}`

// TestAuthz_Stream_ConcreteScope_FailClosed — a concrete per-resource-scope
// entry reached on the (unmaterialised) stream path must be DENIED, and the FGA
// Check must NOT run, even when the checker would allow. This pins the
// wildcard-collapse fix: without it the Check runs against `vpc_network:*` and
// a caller authorized on any network of that type could stream one they should
// not be scoped to.
func TestAuthz_Stream_ConcreteScope_FailClosed(t *testing.T) {
	checker := &fakeChecker{allowed: true} // would allow if the Check ran
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker)
	ss := &fakeServerStream{ctx: withTokenMD("usr_x", "user")}
	err := mw.Stream()(nil, ss,
		&grpc.StreamServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"},
		func(srv any, ss grpc.ServerStream) error {
			t.Fatal("handler must not run: concrete-scope stream must fail closed")
			return nil
		})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"concrete-scope streaming RPC with an unresolvable scope must be denied, not wildcard-allowed")
	assert.Zero(t, checker.calls.Load(),
		"FGA Check must NOT run when the concrete stream scope cannot be resolved (no wildcard collapse)")
}

// TestAuthz_Stream_WildcardScope_CheckerDecides — a wildcard/non-concrete scope
// entry (the shape real streaming RPCs use) has no concrete id to resolve, so it
// is gated at the type/singleton scope and the checker's decision stands.
func TestAuthz_Stream_WildcardScope_CheckerDecides(t *testing.T) {
	// Allow branch.
	allowChecker := &fakeChecker{allowed: true}
	allowMW := buildAuthzMiddleware(t, buildCatalog(t, streamWildcardEntry), allowChecker)
	called := false
	err := allowMW.Stream()(nil, &fakeServerStream{ctx: withTokenMD("usr_x", "user")},
		&grpc.StreamServerInfo{FullMethod: "/kacho.cloud.compute.v1.InternalWatchService/Watch"},
		func(srv any, ss grpc.ServerStream) error { called = true; return nil })
	require.NoError(t, err)
	assert.True(t, called, "wildcard-scope stream allowed by checker must run the handler")
	assert.Equal(t, int64(1), allowChecker.calls.Load(), "checker must be consulted for a wildcard-scope stream")

	// Deny branch.
	denyChecker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	denyMW := buildAuthzMiddleware(t, buildCatalog(t, streamWildcardEntry), denyChecker)
	err = denyMW.Stream()(nil, &fakeServerStream{ctx: withTokenMD("usr_x", "user")},
		&grpc.StreamServerInfo{FullMethod: "/kacho.cloud.compute.v1.InternalWatchService/Watch"},
		func(srv any, ss grpc.ServerStream) error { t.Fatal("handler must not run on deny"); return nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Equal(t, int64(1), denyChecker.calls.Load(), "checker must be consulted for a wildcard-scope stream")
}
