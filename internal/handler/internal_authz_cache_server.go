// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_authz_cache_server.go — gRPC handler that drops api-gateway's
// per-subject authz decision-cache entries on revoke events pushed from
// kacho-iam's subject_change_outbox drainer.
//
// Registered ONLY on api-gateway's internal mTLS listener (port 9091) — see
// RegisterInternalAuthzCacheService below. NEVER exposed on the external
// TLS REST mux: Internal.* methods do not appear on the external endpoint.
package handler

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	apigatewayv1 "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/apigateway/v1"
)

// Invalidator — minimal port the InternalAuthzCacheServer depends on.
// Implemented by AuthzMiddleware.AsInvalidator() (see
// internal/middleware/authz.go). Lives here so the handler is unit-testable
// without importing middleware (also avoids circular dependency that would
// arise if Invalidator lived in middleware/ and handler/ imported middleware/).
type Invalidator interface {
	// InvalidateSubject drops cache entries scoped to the given subject
	// (FGA-prefixed, e.g. "user:usr_abc"). Returns count of entries dropped.
	InvalidateSubject(subject string) int

	// Invalidate flushes the whole decision cache (safety-net fallback).
	// Not invoked by InternalAuthzCacheService.InvalidateSubject path but
	// part of the contract for the broader caller (the cache watcher etc.).
	Invalidate()
}

// InternalAuthzCacheServer implements
// apigatewayv1.InternalAuthzCacheServiceServer.
type InternalAuthzCacheServer struct {
	apigatewayv1.UnimplementedInternalAuthzCacheServiceServer
	inv    Invalidator
	logger *slog.Logger
}

// NewInternalAuthzCacheServer constructs the handler. logger may be nil
// (silent operation — used in unit tests).
func NewInternalAuthzCacheServer(inv Invalidator, logger *slog.Logger) *InternalAuthzCacheServer {
	return &InternalAuthzCacheServer{inv: inv, logger: logger}
}

// InvalidateSubject — see apigatewayv1.InternalAuthzCacheServiceServer.
//
// Contract:
//   - empty Subject       → codes.InvalidArgument
//   - 0 entries dropped   → codes.NotFound (idempotent; drainer maps to
//     drainer.ErrAlreadyApplied and marks sent_at)
//   - >0 entries dropped  → OK + Empty{}
//
// ResourceType / ResourceID are ignored — per-subject invalidate is the
// safe upper bound. EventType — diagnostic only (logged).
func (s *InternalAuthzCacheServer) InvalidateSubject(
	_ context.Context, req *apigatewayv1.InvalidateSubjectRequest,
) (*emptypb.Empty, error) {
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject required")
	}
	dropped := s.inv.InvalidateSubject(req.GetSubject())
	if s.logger != nil {
		s.logger.Info("authz cache invalidate (per-subject)",
			slog.String("subject", req.GetSubject()),
			slog.String("event_type", req.GetEventType()),
			slog.String("resource_type", req.GetResourceType()),
			slog.String("resource_id", req.GetResourceId()),
			slog.Int("dropped", dropped),
		)
	}
	if dropped == 0 {
		// Idempotent miss — gateway has no cache entries for this subject.
		// Drainer (kacho-iam side) maps NotFound → drainer.ErrAlreadyApplied
		// and marks sent_at; row is not retried.
		return nil, status.Error(codes.NotFound, "no cache entries for subject")
	}
	return &emptypb.Empty{}, nil
}

// RegisterInternalAuthzCacheService registers the service ONLY on the
// internal mTLS gRPC server (port 9091) — NEVER on the external TLS-facing
// server (Internal.* methods do not appear on the external endpoint).
//
// Both internalSrv and externalSrv arguments are required so the test suite
// can assert that the FQN appears on internal and is absent from external in
// one call. The externalSrv is intentionally not used to register — that is
// the invariant. Both args are panic-guarded against nil to catch arg-swap
// programmer bugs (the most likely way to accidentally expose this on the
// external endpoint).
func RegisterInternalAuthzCacheService(
	internalSrv, externalSrv *grpc.Server, inv Invalidator, logger *slog.Logger,
) {
	if internalSrv == nil {
		panic("RegisterInternalAuthzCacheService: internalSrv is nil (programmer error)")
	}
	if externalSrv == nil {
		panic("RegisterInternalAuthzCacheService: externalSrv is nil (programmer error — pass both servers to make the internal-only invariant explicit)")
	}
	srv := NewInternalAuthzCacheServer(inv, logger)
	apigatewayv1.RegisterInternalAuthzCacheServiceServer(internalSrv, srv)
	// externalSrv intentionally NOT registered — see comment above.
}
