// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestLookupOrUpsertFromKratos_DoesNotFlushOtherEntries pins that a first-time
// Kratos lazy-upsert must NOT wipe unrelated cached subject resolutions. The
// SubjectCache never stores negative entries, so there is no "negative-cache" to
// drop; a blanket InvalidateAll() only causes a cache-miss storm for every other
// user on the hot path. Pre-populate an unrelated subject, run the upsert path,
// and assert the unrelated entry survives.
func TestLookupOrUpsertFromKratos_DoesNotFlushOtherEntries(t *testing.T) {
	stub := &fakeSubjectStub{lookupFn: func(n int32, _ *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
		if n == 1 {
			return nil, status.Error(codes.NotFound, "not yet mirrored")
		}
		return userResp("usr_new", "new@b.co", "New User"), nil
	}}
	user := &fakeUserStub{}
	c := newTestClient(stub, user)

	// An unrelated user's resolution is already cached.
	c.cache.Set("other-identity", middleware.Subject{Type: "user", ID: "usr_other", DisplayName: "Other"})

	if _, err := c.LookupOrUpsertFromKratos(context.Background(), "kratos-id", "new@b.co", "New User"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if _, ok := c.cache.Get("other-identity"); !ok {
		t.Fatal("first-time Kratos upsert flushed an unrelated cached subject (blanket InvalidateAll)")
	}
}
