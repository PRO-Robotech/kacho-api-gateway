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
	"time"

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
// SECURITY (security.md invariant #1/#4): the internal perimeter is NOT trusted.
// When sec.mtlsEnabled the listener mounts mTLS transport credentials
// (RequireAndVerifyClientCert against the internal CA) PLUS a per-RPC SPIFFE
// allow-list interceptor chain (authN+authZ), so only the allow-listed iam
// push-drainer identity can flush the authz cache. When mTLS is disabled it is
// the dev/local insecure listener (opt-in) — the production guard in main.go
// refuses that posture in a production-class env. Reflection is gated behind the
// debug flag (sec.reflection): it enumerates the internal admin surface.
//
// addr=":0" → kernel picks port; the caller can read it via lis.Addr() (used
// by the unit test for ephemeral-port lifecycle).
func startInternalGRPCListener(
	addr string, inv handler.Invalidator,
	externalSrv *grpc.Server, sec internalListenerSecurity, logger *slog.Logger,
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
	if sec.mtlsEnabled && sec.serverCreds == nil {
		// Defensive: buildInternalListenerSecurity never returns this shape, but a
		// hand-rolled posture with mtlsEnabled and no creds would silently downgrade
		// to plaintext — fail loudly instead.
		return nil, nil, fmt.Errorf("internal grpc listener: mTLS enabled but server credentials are nil")
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen internal grpc %s: %w", addr, err)
	}

	opts := []grpc.ServerOption{
		// Match external-server keepalives so long-lived drainer streams stay
		// healthy across NAT / kube-proxy idle timeouts.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 0, // never close idle conns (drainer is long-lived)
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// Permit the long-lived push-drainer to send frequent keepalive
			// pings: an explicit small MinTime (well under any drainer ping
			// interval — its client keepalive Time is 10s) keeps the server
			// from counting the pings as too-frequent and issuing a GOAWAY,
			// which the gRPC server default (5m MinTime) would do. Without an
			// explicit KeepaliveEnforcementPolicy the field would NOT be the
			// permissive posture — it is precisely this value that permits it.
			MinTime:             time.Second,
			PermitWithoutStream: true,
		}),
	}
	// mTLS transport creds + SPIFFE allow-list authN/authZ interceptors (empty
	// when the listener is the dev/local insecure opt-in).
	opts = append(opts, sec.serverOptions(logger)...)

	srv := grpc.NewServer(opts...)

	handler.RegisterInternalAuthzCacheService(srv, externalSrv, inv, logger)

	// gRPC reflection — useful for `grpcurl` against the internal listener during
	// incident response, but it enumerates the internal admin surface, so it is
	// gated behind an explicit debug flag (default OFF).
	if sec.reflection {
		reflection.Register(srv)
	}

	if logger != nil {
		logger.Info("api-gateway internal gRPC listener ready",
			slog.String("addr", lis.Addr().String()),
			slog.String("services", "kacho.cloud.apigateway.v1.InternalAuthzCacheService"),
			slog.Bool("mtls", sec.mtlsEnabled),
			slog.Bool("reflection", sec.reflection),
			slog.String("invariant", "internal-only — never on external TLS"))
	}
	return srv, lis, nil
}
