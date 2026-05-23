// Package clients — WS-2.3 adapter: wraps InternalIAMServiceClient to satisfy
// watcher.Poller. Clean Architecture: adapter is the only place that talks gRPC.
package clients

import (
	"context"
	"fmt"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
	"google.golang.org/grpc"
)

// SubjectChangePoller wraps the generated gRPC client to satisfy watcher.Poller.
type SubjectChangePoller struct {
	client iamv1.InternalIAMServiceClient
}

// NewSubjectChangePoller wires the adapter onto an existing gRPC connection to
// kacho-iam:9091 (backends["iamInternal"]). No new connection is opened.
func NewSubjectChangePoller(cc grpc.ClientConnInterface) *SubjectChangePoller {
	return &SubjectChangePoller{client: iamv1.NewInternalIAMServiceClient(cc)}
}

// PollSubjectChanges calls InternalIAMService.PollSubjectChanges with cursor
// since and limit 1000, returning the list of change ids and the head cursor.
func (p *SubjectChangePoller) PollSubjectChanges(ctx context.Context, since int64) ([]int64, int64, error) {
	resp, err := p.client.PollSubjectChanges(ctx, &iamv1.PollSubjectChangesRequest{
		SinceId: since,
		Limit:   1000,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("poll subject changes: %w", err)
	}
	ids := make([]int64, 0, len(resp.GetChanges()))
	for _, c := range resp.GetChanges() {
		ids = append(ids, c.GetId())
	}
	return ids, resp.GetHeadId(), nil
}
