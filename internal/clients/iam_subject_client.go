// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/cache"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// subjectLookupStub is the narrow subset of iamv1.InternalIAMServiceClient the
// subject adapter actually calls. Depending on this port (not the full generated
// client) lets unit tests substitute a deterministic fake without a network hop
// (Clean Architecture: the use-case owns the port). The real
// iamv1.NewInternalIAMServiceClient satisfies it.
type subjectLookupStub interface {
	LookupSubject(ctx context.Context, in *iamv1.LookupSubjectRequest, opts ...grpc.CallOption) (*iamv1.LookupSubjectResponse, error)
	Check(ctx context.Context, in *iamv1.CheckRequest, opts ...grpc.CallOption) (*iamv1.CheckResponse, error)
}

// userUpsertStub is the narrow subset of iamv1.InternalUserServiceClient used
// for the lazy Kratos-identity User-mirror upsert. Same rationale as
// subjectLookupStub.
type userUpsertStub interface {
	UpsertFromIdentity(ctx context.Context, in *iamv1.UpsertFromIdentityRequest, opts ...grpc.CallOption) (*operationpb.Operation, error)
}

type IAMSubjectClient struct {
	conn     *grpc.ClientConn
	stub     subjectLookupStub
	userStub userUpsertStub // для lazy-upsert User mirror от Kratos
	cache    *cache.SubjectCache
	logger   *slog.Logger

	// sleep is the retry-backoff sleeper for the lazy Kratos upsert loop.
	// Injectable so unit tests drive the eventual-consistency retry
	// deterministically instead of burning real wall-clock time (the rest of the
	// codebase — lrucache / DPoPReplayCache — uses the same clock-seam pattern).
	sleep func(time.Duration)
	// upsertRetries / upsertBackoff — retry policy for the post-upsert
	// lookup loop (async Operation may not be visible immediately).
	upsertRetries int
	upsertBackoff time.Duration
}

// NewIAMSubjectClient dials kacho-iam:9091 for InternalIAMService.LookupSubject.
//
// transportCreds is the per-edge transport-credentials dial-option for the
// gateway→iam edge (mTLS client-cert when KACHO_API_GATEWAY_MTLS_IAM_ENABLE=true,
// assembled in cmd/api-gateway). nil ⇒ insecure (dev backward-compat). The
// transport layer is orthogonal to the principal-metadata propagated on each RPC.
func NewIAMSubjectClient(addr string, logger *slog.Logger, transportCreds grpc.DialOption) (*IAMSubjectClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("iam internal addr empty")
	}
	if transportCreds == nil {
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	// Time=10s — держим idle subject-lookup conn теплым.
	kp := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}
	conn, err := grpc.NewClient(addr,
		transportCreds,
		grpc.WithKeepaliveParams(kp),
	)
	if err != nil {
		return nil, fmt.Errorf("dial iam internal %s: %w", addr, err)
	}
	return &IAMSubjectClient{
		conn:          conn,
		stub:          iamv1.NewInternalIAMServiceClient(conn),
		userStub:      iamv1.NewInternalUserServiceClient(conn),
		cache:         cache.NewSubjectCache(10_000, 30*time.Second),
		logger:        logger,
		sleep:         time.Sleep,
		upsertRetries: 5,
		upsertBackoff: 200 * time.Millisecond,
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
			// Wrap the sentinel (%w) so errors.Is(err, errSubjectNotFound)
			// matches regardless of the human-readable text — the classifier
			// LookupOrUpsertFromKratos relies on must not be coupled to wording.
			return middleware.Subject{}, fmt.Errorf("%w: %s", errSubjectNotFound, externalID)
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

// LookupOrUpsertFromKratos — для Kratos session-flow. Если User mirror
// еще не существует (NotFound), создает его через InternalUserService.UpsertFromIdentity
// и retry'ит lookup. email обязателен.
func (c *IAMSubjectClient) LookupOrUpsertFromKratos(ctx context.Context, identityID, email, displayName string) (middleware.Subject, error) {
	subj, err := c.LookupByExternalID(ctx, identityID)
	if err == nil {
		return subj, nil
	}
	// Если ошибка — НЕ NotFound (network / other), не пытаемся upsert.
	if !isErrSubjectNotFound(err) {
		return middleware.Subject{}, err
	}
	if email == "" {
		return middleware.Subject{}, fmt.Errorf("lazy-upsert: email is required (identity=%s)", identityID)
	}
	// Upsert (async — возвращает Operation, но операция выполняется быстро;
	// для simplest path просто ждем короткий retry-loop).
	upsertCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, uErr := c.userStub.UpsertFromIdentity(upsertCtx, &iamv1.UpsertFromIdentityRequest{
		ExternalId:  identityID,
		Email:       email,
		DisplayName: displayName,
	})
	if uErr != nil {
		c.logger.Warn("kratos lazy-upsert failed", "identity_id", identityID, "err", uErr.Error())
		return middleware.Subject{}, fmt.Errorf("lazy-upsert: %w", uErr)
	}
	// Operation выполняется async; SubjectLookup может еще не видеть. Retry с
	// инъектируемым sleeper'ом (детерминированно в тестах).
	c.cache.InvalidateAll() // отбросить negative-cache, чтобы повтор не вернул то же NotFound
	for i := 0; i < c.upsertRetries; i++ {
		c.sleep(c.upsertBackoff)
		if subj, err := c.LookupByExternalID(ctx, identityID); err == nil {
			c.logger.Info("kratos lazy-upsert succeeded", "identity_id", identityID, "user_id", subj.ID, "retries", i+1)
			return subj, nil
		}
	}
	return middleware.Subject{}, fmt.Errorf("lazy-upsert: subject still not found after upsert (identity=%s)", identityID)
}

// errSubjectNotFound — sentinel, отличает «не найден» (приемлемо для upsert)
// от других ошибок (network, panic, и т.п.). LookupByExternalID оборачивает его
// через %w, поэтому классификация — чистый errors.Is (без text-matching).
var errSubjectNotFound = stderrors.New("subject not found")

func isErrSubjectNotFound(err error) bool {
	return stderrors.Is(err, errSubjectNotFound)
}

// IsSystemAdmin — проверка system-admin tuple через
// InternalIAMService.Check(kacho_system:root#admin). Subject = "user:<id>" |
// "service_account:<id>". Возвращает (allowed, error).
func (c *IAMSubjectClient) IsSystemAdmin(ctx context.Context, subject string) (bool, error) {
	if subject == "" {
		return false, nil
	}
	timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := c.stub.Check(timeout, &iamv1.CheckRequest{
		SubjectId: subject,
		Relation:  "admin",
		Object:    "kacho_system:root",
	})
	if err != nil {
		st, _ := status.FromError(err)
		if st.Code() == codes.Unimplemented || st.Code() == codes.PermissionDenied {
			return false, nil
		}
		return false, err
	}
	return resp.GetAllowed(), nil
}

func (c *IAMSubjectClient) InvalidateAll() { c.cache.InvalidateAll() }
func (c *IAMSubjectClient) Close() error   { return c.conn.Close() }

func pickDisplayName(displayName, email string) string {
	if displayName != "" {
		return displayName
	}
	return email
}
