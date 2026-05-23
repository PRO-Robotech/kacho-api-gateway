// internal_grpc_listener.go — KAC-138 W1.2 fix-up: dedicated internal gRPC
// listener for InternalAuthzCacheService (port 9091 by default — workspace
// CLAUDE.md §запрет #6 — admin/internal-only RPCs MUST NOT be exposed on the
// external TLS endpoint).
//
// Symmetric to kacho-iam/cmd/kacho-iam/w1_2_wiring.go: the iam push-drainer
// dials KACHO_IAM_GATEWAY_INTERNAL_ADDR (e.g. "kacho-api-gateway-internal:9091")
// and invokes apigateway.v1.InternalAuthzCacheService.InvalidateSubject on the
// listener built here.
//
// Before this fix-up the wiring helper (handler.RegisterInternalAuthzCacheService)
// existed and was unit-tested but main.go never called it — iam's drainer hit
// Unavailable forever and the WS-2.3 30s poll-loop was the only convergence
// path. With this listener wired, push-invalidation lands within <1s of revoke.
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
// InternalAuthzCacheService on it (and NOT on externalSrv — §запрет #6), and
// returns the wired server + listener so the caller drives Serve() and
// GracefulStop() under its existing signal-shutdown flow.
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
		// externalSrv to enforce §запрет #6 invariant. Surface the same
		// error at construction time so wiring bugs are caught before
		// Serve().
		return nil, nil, fmt.Errorf("internal grpc listener: externalSrv required (pass both servers to make §запрет #6 invariant explicit)")
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
	// (§запрет #6 enforced by NetworkPolicy + Service type).
	reflection.Register(srv)

	if logger != nil {
		logger.Info("api-gateway internal gRPC listener ready",
			slog.String("addr", lis.Addr().String()),
			slog.String("services", "kacho.cloud.apigateway.v1.InternalAuthzCacheService"),
			slog.String("invariant", "§запрет #6 — internal-only, never on external TLS"))
	}
	return srv, lis, nil
}
