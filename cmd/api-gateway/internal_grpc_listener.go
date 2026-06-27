// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_grpc_listener.go — dedicated internal-only gRPC listener for
// InternalAuthzCacheService (port 9091 by default). Internal/admin-only RPCs
// MUST NOT be exposed on the external TLS endpoint.
//
// The kacho-iam push-drainer dials KACHO_IAM_GATEWAY_INTERNAL_ADDR (e.g.
// "kacho-api-gateway-internal:9091") and invokes
// apigateway.v1.InternalAuthzCacheService.InvalidateSubject on the listener
// built here, so a revoke lands as push-invalidation within <1s. A background
// subject-change poll-loop converges sibling replicas as a fallback.
package main

import (
	"fmt"
	"log/slog"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
)

// startInternalGRPCListener builds the internal-only gRPC server, listens on
// addr (host:port; ":0" for ephemeral in tests), registers
// InternalAuthzCacheService on it (and NOT on externalSrv — internal-only
// invariant), and returns the wired server + listener so the caller drives
// Serve() and GracefulStop() under its existing signal-shutdown flow.
//
// The internal server uses the same conservative keepalive policy as the
// external server but carries NO authn/authz interceptors — it is reachable
// only from cluster-internal pods (NetworkPolicy + Service of type ClusterIP).
// The caller MUST ensure the listener is not exposed via Ingress / LoadBalancer.
//
// addr=":0" → kernel picks port; the caller can read it via lis.Addr() (used
// by the unit test for ephemeral-port lifecycle).
func startInternalGRPCListener(
	addr string, inv handler.Invalidator,
	externalSrv *grpc.Server, logger *slog.Logger,
) (*grpc.Server, net.Listener, error) {
	if addr == "" {
		return nil, nil, fmt.Errorf("internal grpc listener: addr required")
	}
	if externalSrv == nil {
		// Defensive: RegisterInternalAuthzCacheService panics on nil
		// externalSrv to enforce the internal-only invariant. Surface the
		// same error at construction time so wiring bugs are caught before
		// Serve().
		return nil, nil, fmt.Errorf("internal grpc listener: externalSrv required (pass both servers to make the internal-only invariant explicit)")
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen internal grpc %s: %w", addr, err)
	}

	srv := grpc.NewServer(
		// Match external-server keepalives so long-lived drainer streams stay
		// healthy across NAT / kube-proxy idle timeouts.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 0, // never close idle conns (drainer is long-lived)
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10, // ns is meaningless; left as zero-default below
			PermitWithoutStream: true,
		}),
	)

	handler.RegisterInternalAuthzCacheService(srv, externalSrv, inv, logger)

	// gRPC reflection — useful for `grpcurl` against the internal listener
	// during incident response. Safe because the listener is cluster-internal
	// (internal-only invariant enforced by NetworkPolicy + Service type).
	reflection.Register(srv)

	if logger != nil {
		logger.Info("api-gateway internal gRPC listener ready",
			slog.String("addr", lis.Addr().String()),
			slog.String("services", "kacho.cloud.apigateway.v1.InternalAuthzCacheService"),
			slog.String("invariant", "internal-only — never on external TLS"))
	}
	return srv, lis, nil
}
