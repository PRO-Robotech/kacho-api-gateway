// Package clients — gRPC-direct клиенты для cluster-internal сервисов
// (НЕ через restmux api-gateway — loop-prevention запрет #6).
//
// iam_subject_client.go: вызов `InternalIAMService.LookupSubject` на
// kacho-iam:9091.
package clients

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/cache"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

type IAMSubjectClient struct {
	conn   *grpc.ClientConn
	stub   iamv1.InternalIAMServiceClient
	cache  *cache.SubjectCache
	logger *slog.Logger
}

func NewIAMSubjectClient(addr string, logger *slog.Logger) (*IAMSubjectClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("iam internal addr empty")
	}
	kp := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kp),
	)
	if err != nil {
		return nil, fmt.Errorf("dial iam internal %s: %w", addr, err)
	}
	return &IAMSubjectClient{
		conn:   conn,
		stub:   iamv1.NewInternalIAMServiceClient(conn),
		cache:  cache.NewSubjectCache(10_000, 30*time.Second),
		logger: logger,
	}, nil
}

func (c *IAMSubjectClient) LookupByExternalID(ctx context.Context, externalID string) (middleware.Subject, error) {
	if externalID == "" {
		return middleware.Subject{}, stderrors.New("external_id empty")
	}

	if cached, ok := c.cache.Get(externalID); ok {
		return cached, nil
	}

	timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.stub.LookupSubject(timeout, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: externalID},
	})
	if err != nil {
		st, _ := status.FromError(err)
		if st.Code() == codes.NotFound {
			return middleware.Subject{}, fmt.Errorf("subject not found: %s", externalID)
		}
		c.logger.Warn("iam.LookupSubject failed",
			"external_id", externalID, "code", st.Code(), "msg", st.Message())
		return middleware.Subject{}, fmt.Errorf("iam lookup failed: %w", err)
	}

	var subj middleware.Subject
	switch s := resp.Subject.(type) {
	case *iamv1.LookupSubjectResponse_User:
		subj = middleware.Subject{
			Type:        "user",
			ID:          s.User.GetId(),
			DisplayName: pickDisplayName(s.User.GetDisplayName(), s.User.GetEmail()),
		}
	case *iamv1.LookupSubjectResponse_ServiceAccount:
		subj = middleware.Subject{
			Type:        "service_account",
			ID:          s.ServiceAccount.GetId(),
			DisplayName: s.ServiceAccount.GetName(),
		}
	default:
		return middleware.Subject{}, fmt.Errorf("unexpected subject oneof from iam")
	}
	c.cache.Set(externalID, subj)
	return subj, nil
}

func (c *IAMSubjectClient) InvalidateAll() { c.cache.InvalidateAll() }
func (c *IAMSubjectClient) Close() error  { return c.conn.Close() }

func pickDisplayName(displayName, email string) string {
	if displayName != "" {
		return displayName
	}
	return email
}
