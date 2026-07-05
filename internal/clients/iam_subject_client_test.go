// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	stderrors "errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/cache"
)

// fakeSubjectStub is a deterministic subjectLookupStub. lookupFn is invoked per
// call so a test can vary the response across the upsert retry loop.
type fakeSubjectStub struct {
	calls    atomic.Int32
	lookupFn func(n int32, in *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error)
}

func (f *fakeSubjectStub) LookupSubject(_ context.Context, in *iamv1.LookupSubjectRequest, _ ...grpc.CallOption) (*iamv1.LookupSubjectResponse, error) {
	n := f.calls.Add(1)
	return f.lookupFn(n, in)
}

func (f *fakeSubjectStub) Check(context.Context, *iamv1.CheckRequest, ...grpc.CallOption) (*iamv1.CheckResponse, error) {
	return &iamv1.CheckResponse{}, nil
}

// fakeUserStub counts UpsertFromIdentity calls.
type fakeUserStub struct {
	calls    atomic.Int32
	upsertFn func(in *iamv1.UpsertFromIdentityRequest) (*operationpb.Operation, error)
}

func (f *fakeUserStub) UpsertFromIdentity(_ context.Context, in *iamv1.UpsertFromIdentityRequest, _ ...grpc.CallOption) (*operationpb.Operation, error) {
	f.calls.Add(1)
	if f.upsertFn != nil {
		return f.upsertFn(in)
	}
	return &operationpb.Operation{}, nil
}

// newTestClient builds an IAMSubjectClient wired to the given fakes with a
// no-op sleeper (deterministic, no wall-clock burn).
func newTestClient(stub subjectLookupStub, user userUpsertStub) *IAMSubjectClient {
	return &IAMSubjectClient{
		stub:          stub,
		userStub:      user,
		cache:         cache.NewSubjectCache(1000, 30*time.Second, nil),
		logger:        slog.Default(),
		sleep:         func(time.Duration) {}, // deterministic: no real sleep
		upsertRetries: 5,
		upsertBackoff: 0,
	}
}

func userResp(id, email, display string) *iamv1.LookupSubjectResponse {
	return &iamv1.LookupSubjectResponse{
		Subject: &iamv1.LookupSubjectResponse_User{
			User: &iamv1.User{Id: id, Email: email, DisplayName: display},
		},
	}
}

// TestLookupByExternalID_UserOneof — a User oneof maps to a user Subject with a
// display-name falling back to email.
func TestLookupByExternalID_UserOneof(t *testing.T) {
	c := newTestClient(&fakeSubjectStub{lookupFn: func(int32, *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		return userResp("usr_1", "a@b.co", ""), nil
	}}, &fakeUserStub{})

	subj, err := c.LookupByExternalID(context.Background(), "ext-1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if subj.Type != "user" || subj.ID != "usr_1" || subj.DisplayName != "a@b.co" {
		t.Fatalf("got %+v, want user/usr_1/a@b.co (display falls back to email)", subj)
	}
}

// TestLookupByExternalID_ServiceAccountOneof — a ServiceAccount oneof maps to a
// service_account Subject.
func TestLookupByExternalID_ServiceAccountOneof(t *testing.T) {
	c := newTestClient(&fakeSubjectStub{lookupFn: func(int32, *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		return &iamv1.LookupSubjectResponse{Subject: &iamv1.LookupSubjectResponse_ServiceAccount{
			ServiceAccount: &iamv1.ServiceAccount{Id: "sva_1", Name: "ci-bot"},
		}}, nil
	}}, &fakeUserStub{})

	subj, err := c.LookupByExternalID(context.Background(), "ext-2")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if subj.Type != "service_account" || subj.ID != "sva_1" || subj.DisplayName != "ci-bot" {
		t.Fatalf("got %+v, want service_account/sva_1/ci-bot", subj)
	}
}

// TestLookupByExternalID_UnexpectedOneof — an empty oneof is a hard error (no
// silent anonymous downgrade).
func TestLookupByExternalID_UnexpectedOneof(t *testing.T) {
	c := newTestClient(&fakeSubjectStub{lookupFn: func(int32, *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		return &iamv1.LookupSubjectResponse{}, nil // nil Subject oneof
	}}, &fakeUserStub{})

	_, err := c.LookupByExternalID(context.Background(), "ext-3")
	if err == nil {
		t.Fatal("empty subject oneof must error")
	}
}

// TestLookupByExternalID_NotFound_WrapsSentinel — a NotFound from iam must be a
// wrapped errSubjectNotFound so errors.Is matches (the reword-safe classifier
// used by LookupOrUpsertFromKratos). This FAILS before the %w fix.
func TestLookupByExternalID_NotFound_WrapsSentinel(t *testing.T) {
	c := newTestClient(&fakeSubjectStub{lookupFn: func(int32, *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		return nil, status.Error(codes.NotFound, "no such subject")
	}}, &fakeUserStub{})

	_, err := c.LookupByExternalID(context.Background(), "ext-missing")
	if err == nil {
		t.Fatal("expected NotFound error")
	}
	if !stderrors.Is(err, errSubjectNotFound) {
		t.Fatalf("NotFound error must wrap errSubjectNotFound (errors.Is), got %v", err)
	}
	// isErrSubjectNotFound must agree (it is the classifier the upsert path uses).
	if !isErrSubjectNotFound(err) {
		t.Fatalf("isErrSubjectNotFound must classify a genuine NotFound, got %v", err)
	}
}

// TestLookupOrUpsertFromKratos_UpsertThenRetrySucceeds — first lookup is
// NotFound → the adapter MUST enter the upsert branch, then a retry lookup
// succeeds. Guards the sentinel-classification control flow.
func TestLookupOrUpsertFromKratos_UpsertThenRetrySucceeds(t *testing.T) {
	stub := &fakeSubjectStub{lookupFn: func(n int32, _ *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		if n == 1 {
			return nil, status.Error(codes.NotFound, "not yet mirrored")
		}
		return userResp("usr_new", "new@b.co", "New User"), nil
	}}
	user := &fakeUserStub{}
	c := newTestClient(stub, user)

	subj, err := c.LookupOrUpsertFromKratos(context.Background(), "kratos-id", "new@b.co", "New User")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if user.calls.Load() != 1 {
		t.Fatalf("upsert branch must run exactly once, got %d calls", user.calls.Load())
	}
	if subj.Type != "user" || subj.ID != "usr_new" {
		t.Fatalf("got %+v, want user/usr_new", subj)
	}
}

// TestLookupOrUpsertFromKratos_NotFoundEmptyEmail — NotFound with no email must
// error WITHOUT attempting an upsert (email is required to mirror).
func TestLookupOrUpsertFromKratos_NotFoundEmptyEmail(t *testing.T) {
	stub := &fakeSubjectStub{lookupFn: func(int32, *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		return nil, status.Error(codes.NotFound, "missing")
	}}
	user := &fakeUserStub{}
	c := newTestClient(stub, user)

	_, err := c.LookupOrUpsertFromKratos(context.Background(), "kratos-id", "", "no email")
	if err == nil {
		t.Fatal("empty email must error")
	}
	if user.calls.Load() != 0 {
		t.Fatalf("must NOT attempt upsert with empty email, got %d calls", user.calls.Load())
	}
}

// TestLookupOrUpsertFromKratos_NonNotFound_NoUpsert — a non-NotFound lookup
// error (e.g. Unavailable) must NOT trigger an upsert; it propagates.
func TestLookupOrUpsertFromKratos_NonNotFound_NoUpsert(t *testing.T) {
	stub := &fakeSubjectStub{lookupFn: func(int32, *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		return nil, status.Error(codes.Unavailable, "iam down")
	}}
	user := &fakeUserStub{}
	c := newTestClient(stub, user)

	_, err := c.LookupOrUpsertFromKratos(context.Background(), "kratos-id", "e@b.co", "d")
	if err == nil {
		t.Fatal("Unavailable lookup must propagate")
	}
	if user.calls.Load() != 0 {
		t.Fatalf("non-NotFound must NOT attempt upsert, got %d calls", user.calls.Load())
	}
}
