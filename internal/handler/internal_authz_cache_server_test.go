// internal_authz_cache_server_test.go — RED tests for the W1.2
// InternalAuthzCacheService server implementation on api-gateway.
//
// W1.2 (KAC-138 of KAC-136 / KAC-134 epic). Acceptance:
// docs/specs/sub-phase-W1.2-subject-change-cache-invalidation-acceptance.md §4.4 §6.3.
//
// At RED time the following symbols DO NOT exist (will not compile):
//
//	handler.InternalAuthzCacheServer
//	handler.NewInternalAuthzCacheServer
//	handler.Invalidator         (the small adapter port the handler depends on)
//
// Tests intentionally fail to compile with "undefined: handler.*" until
// GREEN lands per acceptance §4.4.
//
// Scenario IDs map 1:1 to acceptance §6.3:
//
//	W1.2-11 — Handler InvalidateSubject drops per-subject entries (OK reply)
//	W1.2-12 — Empty cache (0 dropped) → codes.NotFound (idempotent contract)
//	W1.2-13 — Empty subject → codes.InvalidArgument
//
// Listener-isolation (W1.2-14) is asserted in internal_authz_cache_listener_isolation_test.go
// (the listener wiring lives in cmd/api-gateway/main.go, not in this handler).
package handler_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apigatewayv1 "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/apigateway/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
)

// fakeInvalidator implements handler.Invalidator (the small port the
// handler depends on — typically wired to AuthzMiddleware.AsInvalidator()
// which exposes decisionCache.InvalidateSubject + InvalidateCache).
type fakeInvalidator struct {
	mu                sync.Mutex
	invalidateSubject map[string]int // configured per-subject return value
	subjectCalls      []string
	cacheFlushes      int
}

func (f *fakeInvalidator) InvalidateSubject(subject string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subjectCalls = append(f.subjectCalls, subject)
	return f.invalidateSubject[subject] // 0 if absent
}

func (f *fakeInvalidator) Invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheFlushes++
}

func (f *fakeInvalidator) callsFor(subject string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.subjectCalls {
		if s == subject {
			n++
		}
	}
	return n
}

// TestW1_2_11_HandlerInvalidateSubject_HappyPath_OKReply — per acceptance §6.3.1:
// 3 cache entries dropped → server returns OK + Empty{} (NOT NotFound).
func TestW1_2_11_HandlerInvalidateSubject_HappyPath_OKReply(t *testing.T) {
	inv := &fakeInvalidator{
		invalidateSubject: map[string]int{"user:usr_a": 3},
	}
	srv := handler.NewInternalAuthzCacheServer(inv, nil)

	resp, err := srv.InvalidateSubject(context.Background(),
		&apigatewayv1.InvalidateSubjectRequest{
			Subject:   "user:usr_a",
			EventType: "binding_revoke",
		})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 1, inv.callsFor("user:usr_a"),
		"handler must invoke Invalidator.InvalidateSubject exactly once")
}

// TestW1_2_12_HandlerInvalidateSubject_EmptyCache_ReturnsNotFound —
// acceptance §6.3.2: 0 entries dropped → codes.NotFound so the drainer
// maps to drainer.ErrAlreadyApplied and marks sent_at.
func TestW1_2_12_HandlerInvalidateSubject_EmptyCache_ReturnsNotFound(t *testing.T) {
	inv := &fakeInvalidator{
		invalidateSubject: map[string]int{}, // 0 for any subject
	}
	srv := handler.NewInternalAuthzCacheServer(inv, nil)

	_, err := srv.InvalidateSubject(context.Background(),
		&apigatewayv1.InvalidateSubjectRequest{
			Subject:   "user:usr_no_cache",
			EventType: "binding_revoke",
		})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "must be gRPC status error")
	assert.Equal(t, codes.NotFound, st.Code(),
		"0 dropped → NotFound (acceptance §6.3.2; drainer maps to ErrAlreadyApplied)")
	assert.Contains(t, strings.ToLower(st.Message()), "no cache",
		"message must indicate empty-cache miss")
}

// TestW1_2_13_HandlerInvalidateSubject_EmptySubject_ReturnsInvalidArgument
// — acceptance §6.3.3: empty subject → codes.InvalidArgument; cache
// untouched (Invalidator never called).
func TestW1_2_13_HandlerInvalidateSubject_EmptySubject_ReturnsInvalidArgument(t *testing.T) {
	inv := &fakeInvalidator{}
	srv := handler.NewInternalAuthzCacheServer(inv, nil)

	_, err := srv.InvalidateSubject(context.Background(),
		&apigatewayv1.InvalidateSubjectRequest{
			Subject:   "",
			EventType: "binding_revoke",
		})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"empty subject → InvalidArgument (acceptance §6.3.3)")

	inv.mu.Lock()
	assert.Empty(t, inv.subjectCalls,
		"Invalidator must NOT be called on empty subject")
	inv.mu.Unlock()
}

// TestW1_2_11b_HandlerLogsEventTypeAndResourceFields — handler MUST log
// (or forward to metric labels) event_type / resource_type / resource_id
// from the request. We can't easily assert log content in a unit test, so
// this test asserts that the handler accepts the optional fields without
// failing — full observability assertion lives in a metrics integration
// test (out of scope for RED handler-unit; covered by GREEN observability DoD).
func TestW1_2_11b_HandlerAcceptsOptionalScopeFields(t *testing.T) {
	inv := &fakeInvalidator{
		invalidateSubject: map[string]int{"user:usr_a": 2},
	}
	srv := handler.NewInternalAuthzCacheServer(inv, nil)

	_, err := srv.InvalidateSubject(context.Background(),
		&apigatewayv1.InvalidateSubjectRequest{
			Subject:      "user:usr_a",
			EventType:    "jit_revoke",
			ResourceType: "project",
			ResourceId:   "prj_a",
		})
	require.NoError(t, err,
		"optional scope fields must not cause handler error (MVP ignores them)")
	assert.Equal(t, 1, inv.callsFor("user:usr_a"))
}
