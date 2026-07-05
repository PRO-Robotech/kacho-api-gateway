// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package principalmeta

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// OutgoingFromIncoming copies the incoming gRPC metadata of ctx into a new
// outgoing context so a cross-process gRPC hop in the gateway forwards the
// principal / request-id / … headers to the backend. Every cross-process gRPC
// hop in the gateway (opsproxy, the unknown-service shim proxy, …) must perform
// exactly this step, otherwise the trusted principal headers are dropped and the
// backend sees an anonymous caller.
//
// When ctx carries no incoming metadata it is returned unchanged, so downstream
// interceptors observe "no metadata" rather than an empty MD. The metadata is
// always .Copy()'d — the incoming map is never shared with the outgoing context,
// so a later mutation on one side cannot leak into the other.
func OutgoingFromIncoming(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, md.Copy())
}
