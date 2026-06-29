// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_authz_cache_listener_isolation_test.go — verifies that
// InternalAuthzCacheService is NOT reachable on the external TLS listener
// (Internal* methods stay off the external endpoint).
//
// The registration helper takes both the internal-only gRPC server AND the
// external (TLS-facing) gRPC server, registers InternalAuthzCacheService ONLY
// on the internal one, and panics when wrongly registered on the external one.
// This test pins the contract: the external server must NOT have the service.
package handler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
)

// TestW1_2_14_InternalAuthzCacheService_RegisteredOnlyOnInternalServer —
// the canonical wiring helper `handler.RegisterInternalAuthzCacheService`
// must register the gRPC service ONLY on the internal-only server passed
// in, never on the external (TLS-facing) server.
//
// Test pattern: construct two grpc.Server instances (real, but not Serve'd —
// we only inspect GetServiceInfo()), call the registration helper, and
// assert the InternalAuthzCacheService FQN is present on one and absent
// on the other.
//
// An external client gRPC connection to
// `kacho.cloud.apigateway.v1.InternalAuthzCacheService/InvalidateSubject`
// must hit codes.Unimplemented (route not registered).
func TestW1_2_14_InternalAuthzCacheService_RegisteredOnlyOnInternalServer(t *testing.T) {
	internalSrv := grpc.NewServer()
	externalSrv := grpc.NewServer()

	inv := &noopInvalidator{}
	handler.RegisterInternalAuthzCacheService(internalSrv, externalSrv, inv, nil)

	const fqn = "kacho.cloud.apigateway.v1.InternalAuthzCacheService"

	internalSvcs := internalSrv.GetServiceInfo()
	_, internalHas := internalSvcs[fqn]
	assert.True(t, internalHas,
		"InternalAuthzCacheService MUST be registered on the internal server")

	externalSvcs := externalSrv.GetServiceInfo()
	_, externalHas := externalSvcs[fqn]
	assert.False(t, externalHas,
		"InternalAuthzCacheService MUST NOT be registered on the external (TLS-facing) server (internal-only)")
}

// TestW1_2_14b_RegisterInternalAuthzCacheService_NilInternalSrv_Panics —
// guard against accidental swap of args (the most likely bug for the
// "external = forbidden" invariant). Calling with nil internal server is
// a programmer error: panic loud.
func TestW1_2_14b_RegisterInternalAuthzCacheService_NilInternalSrv_Panics(t *testing.T) {
	externalSrv := grpc.NewServer()
	inv := &noopInvalidator{}
	require.Panics(t, func() {
		handler.RegisterInternalAuthzCacheService(nil, externalSrv, inv, nil)
	}, "must panic on nil internal server (programmer error)")
}

// noopInvalidator — minimal Invalidator stub used only to satisfy the
// RegisterInternalAuthzCacheService signature in these tests; behaviour
// is not exercised here.
type noopInvalidator struct{}

func (n *noopInvalidator) InvalidateSubject(_ string) int { return 0 }
func (n *noopInvalidator) Invalidate()                    {}
