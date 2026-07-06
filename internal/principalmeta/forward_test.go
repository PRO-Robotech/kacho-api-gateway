// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package principalmeta_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// OutgoingFromIncoming is on the trusted-identity propagation path: every
// cross-process gateway hop (opsproxy, shim proxy) relies on it to forward the
// principal / request-id headers, otherwise the backend authorizes an anonymous
// caller. These tests pin that copy so a refactor that drops or mangles it fails
// loudly instead of silently changing the authorized identity.

// Incoming metadata present → the returned ctx's OUTGOING metadata carries the
// trusted principal + request-id headers (this is what the backend authorizes
// against).
func TestOutgoingFromIncoming_ForwardsPrincipalHeaders(t *testing.T) {
	in := metadata.New(map[string]string{
		principalmeta.MetaPrincipalType: "user",
		principalmeta.MetaPrincipalID:   "usr_abc",
		principalmeta.MetaTokenACR:      "urn:acr:mfa",
		"x-request-id":                  "req-42",
	})
	ctx := metadata.NewIncomingContext(context.Background(), in)

	out, ok := metadata.FromOutgoingContext(principalmeta.OutgoingFromIncoming(ctx))
	require.True(t, ok, "outgoing metadata must be present")
	assert.Equal(t, []string{"user"}, out.Get(principalmeta.MetaPrincipalType))
	assert.Equal(t, []string{"usr_abc"}, out.Get(principalmeta.MetaPrincipalID))
	assert.Equal(t, []string{"urn:acr:mfa"}, out.Get(principalmeta.MetaTokenACR))
	assert.Equal(t, []string{"req-42"}, out.Get("x-request-id"))
}

// The forwarded metadata is a .Copy() — a later mutation of the source incoming
// MD must not leak into the already-derived outgoing context (no shared map).
func TestOutgoingFromIncoming_CopiesNotAliases(t *testing.T) {
	in := metadata.New(map[string]string{principalmeta.MetaPrincipalID: "usr_abc"})
	ctx := metadata.NewIncomingContext(context.Background(), in)

	derived := principalmeta.OutgoingFromIncoming(ctx)
	// Mutate the source AFTER deriving the outgoing context.
	in.Set(principalmeta.MetaPrincipalID, "usr_evil")
	in.Set("x-injected", "nope")

	out, ok := metadata.FromOutgoingContext(derived)
	require.True(t, ok)
	assert.Equal(t, []string{"usr_abc"}, out.Get(principalmeta.MetaPrincipalID),
		"post-hoc source mutation must not rewrite the forwarded principal")
	assert.Empty(t, out.Get("x-injected"),
		"post-hoc source key must not appear in the already-forwarded copy")
}

// No incoming metadata → ctx is returned UNCHANGED: downstream interceptors must
// observe "no metadata" rather than an injected empty outgoing MD (which would
// mask the absence of a real principal).
func TestOutgoingFromIncoming_NoIncoming_PassThrough(t *testing.T) {
	ctx := context.Background()
	got := principalmeta.OutgoingFromIncoming(ctx)
	assert.Equal(t, ctx, got, "ctx must be returned unchanged when no incoming MD")
	_, ok := metadata.FromOutgoingContext(got)
	assert.False(t, ok, "no empty outgoing MD may be injected")
}
