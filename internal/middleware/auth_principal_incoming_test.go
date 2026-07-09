// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// The gateway's proxy hops (opsproxy.Get/Cancel, shimproxy.Handler) forward the
// backend call with principalmeta.OutgoingFromIncoming, which rebuilds the
// backend's outgoing metadata from the INCOMING metadata — and
// opsproxy.checkOperationOwnership reads the caller principal from INCOMING too.
// So the auth interceptor MUST place the trusted principal into the INCOMING
// metadata on the gRPC-direct path, not only into outgoing. Otherwise the
// advertised external gRPC listener authenticates the caller but the proxy hop
// drops the principal → the backend/ownership-check sees an anonymous caller
// (REST/gRPC asymmetry: the REST path works because restmux sets these as
// incoming).
func TestAuthUnary_InjectsPrincipalIntoIncomingForProxyHops(t *testing.T) {
	const secret = "dev-secret-test"
	lookup := &fakeLookup{subj: middleware.Subject{
		Type: "user", ID: "usr-alice", DisplayName: "Alice",
	}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, secret, lookup, authTestLogger())

	tok := makeDevJWT(t, secret, "zit-12345")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+tok))

	handler := func(hctx context.Context, _ any) (any, error) {
		// What opsproxy.principalFromContext reads: the caller principal from
		// INCOMING metadata.
		inMD, ok := metadata.FromIncomingContext(hctx)
		require.True(t, ok, "incoming metadata must be present for proxy hops")
		assert.Equal(t, []string{"user"}, inMD.Get(principalmeta.MetaPrincipalType),
			"principal type must be in INCOMING metadata (opsproxy reads it there)")
		assert.Equal(t, []string{"usr-alice"}, inMD.Get(principalmeta.MetaPrincipalID),
			"principal id must be in INCOMING metadata (opsproxy reads it there)")

		// What the proxy hops forward to the backend: OutgoingFromIncoming
		// rebuilds outgoing from incoming, so the backend must see the principal.
		fwd := principalmeta.OutgoingFromIncoming(hctx)
		outMD, ok := metadata.FromOutgoingContext(fwd)
		require.True(t, ok, "proxy hop must forward outgoing metadata")
		assert.Equal(t, []string{"user"}, outMD.Get(principalmeta.MetaPrincipalType),
			"backend must receive principal type after OutgoingFromIncoming")
		assert.Equal(t, []string{"usr-alice"}, outMD.Get(principalmeta.MetaPrincipalID),
			"backend must receive principal id after OutgoingFromIncoming")
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.operation.v1.OperationService/Get"}, handler)
	require.NoError(t, err)
}
