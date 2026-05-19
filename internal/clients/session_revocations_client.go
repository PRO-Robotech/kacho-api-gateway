// Package clients — KAC-127 Phase 2 adapter: wraps the generated
// `InternalSessionRevocationsServiceClient` so the handler/logout package can
// depend on a narrow port-interface (`handler.SessionRevocationsClient`)
// instead of the full proto stub. Clean Architecture: adapter is the only
// place that talks gRPC.
package clients

import (
	"context"

	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

// SessionRevocationsAdapter wraps the generated gRPC client to satisfy
// handler.SessionRevocationsClient. The Operation result is discarded —
// callers care only about success/failure of the synchronous DB write.
type SessionRevocationsAdapter struct {
	client iamv1.InternalSessionRevocationsServiceClient
}

// NewSessionRevocationsAdapter wires the adapter onto an existing gRPC
// connection to kacho-iam:9091.
func NewSessionRevocationsAdapter(cc grpc.ClientConnInterface) *SessionRevocationsAdapter {
	return &SessionRevocationsAdapter{
		client: iamv1.NewInternalSessionRevocationsServiceClient(cc),
	}
}

// Revoke invokes InternalSessionRevocationsService.Revoke and discards the
// Operation envelope. Returns the underlying gRPC error verbatim — the
// handler caller is responsible for mapping it to a user-visible warning.
func (a *SessionRevocationsAdapter) Revoke(ctx context.Context, in *iamv1.RevokeRequest) error {
	_, err := a.client.Revoke(ctx, in)
	return err
}
