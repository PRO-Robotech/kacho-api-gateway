// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// driveBody sends a POST with a request body through the idempotency middleware
// and reports the response plus downstream-visible body.
func driveBody(h http.Handler, principal, path, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	if principal != "" {
		r.Header.Set("X-Kacho-Principal-Id", principal)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// TestIdempotency_DifferentBodySameKeyNotReplayed proves that reusing an
// Idempotency-Key with a materially different request payload is a cache MISS
// (the second write executes downstream) rather than silently replaying the
// first response — a masked lost-update otherwise (CWE-694). Also proves the
// downstream still sees the full request body after the key-fingerprint read.
func TestIdempotency_DifferentBodySameKeyNotReplayed(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)
	var calls int
	var lastSeen string
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		lastSeen = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("echo:" + lastSeen))
	}))

	// First body → downstream executes, response cached.
	rr1 := driveBody(h, "u", "/compute/v1/instances", "K", "bodyA")
	if calls != 1 || lastSeen != "bodyA" || rr1.Body.String() != "echo:bodyA" {
		t.Fatalf("first: calls=%d seen=%q resp=%q", calls, lastSeen, rr1.Body.String())
	}
	// SAME key, DIFFERENT body → must be a miss (downstream runs again, sees bodyB),
	// not a replay of bodyA's cached response.
	rr2 := driveBody(h, "u", "/compute/v1/instances", "K", "bodyB")
	if calls != 2 {
		t.Fatalf("different body under reused key was replayed: calls=%d want 2", calls)
	}
	if lastSeen != "bodyB" || rr2.Body.String() != "echo:bodyB" {
		t.Fatalf("second: seen=%q resp=%q (downstream must see bodyB in full)", lastSeen, rr2.Body.String())
	}
	if rr2.Header().Get("X-Idempotent-Replayed") == "true" {
		t.Fatalf("different-body request must not be marked as a replay")
	}
	// SAME key, SAME body as the first → genuine replay of the cached response.
	rr3 := driveBody(h, "u", "/compute/v1/instances", "K", "bodyA")
	if calls != 2 {
		t.Fatalf("identical body+key must replay, not re-execute: calls=%d want 2", calls)
	}
	if rr3.Body.String() != "echo:bodyA" || rr3.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Fatalf("replay: resp=%q replayed=%q", rr3.Body.String(), rr3.Header().Get("X-Idempotent-Replayed"))
	}
}

// drive sends a POST through the idempotency middleware with the given
// principal id, request path and Idempotency-Key, and reports the response plus
// whether downstream was invoked.
func drive(h http.Handler, principal, path, key string) (*httptest.ResponseRecorder, string) {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	if principal != "" {
		r.Header.Set("X-Kacho-Principal-Id", principal)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr, rr.Body.String()
}

// TestIdempotency_ScopedByPrincipal proves a replay is confined to the same
// authenticated principal — a different principal presenting the same key gets
// its own downstream call, not the first caller's cached body.
func TestIdempotency_ScopedByPrincipal(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)
	var calls int
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body-for-" + r.Header.Get("X-Kacho-Principal-Id")))
	}))

	if _, b := drive(h, "user-A", "/iam/v1/projects", "K"); b != "body-for-user-A" || calls != 1 {
		t.Fatalf("first A: body=%q calls=%d", b, calls)
	}
	rr, b := drive(h, "user-A", "/iam/v1/projects", "K")
	if b != "body-for-user-A" || calls != 1 || rr.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Fatalf("replay A: body=%q calls=%d replayed=%q", b, calls, rr.Header().Get("X-Idempotent-Replayed"))
	}
	// Same key, DIFFERENT principal must NOT collide with user-A's entry.
	_, b = drive(h, "user-B", "/iam/v1/projects", "K")
	if b != "body-for-user-B" || calls != 2 {
		t.Fatalf("user-B same key leaked A's body: body=%q calls=%d", b, calls)
	}
}

// TestIdempotency_ScopedByPathMethod proves the same key on a different path is
// not a replay (a request fingerprint, not a bare key).
func TestIdempotency_ScopedByPathMethod(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)
	var calls int
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	_, _ = drive(h, "u", "/iam/v1/projects", "K")
	_, _ = drive(h, "u", "/vpc/v1/networks", "K") // same key, different path
	if calls != 2 {
		t.Fatalf("same key on different path replayed: calls=%d want 2", calls)
	}
}

// TestIdempotency_5xxNotCached_Retried proves a failed mutation (5xx) is NOT
// cached long-term, so a retry with the same key re-executes downstream instead
// of replaying a fabricated failure/success. This pins the `statusCode < 500`
// caching predicate (retry-safety, idempotency.go).
func TestIdempotency_5xxNotCached_Retried(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)
	var calls int
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable) // 503
		_, _ = w.Write([]byte("upstream down"))
	}))

	rr1, _ := drive(h, "u", "/iam/v1/projects", "K")
	if rr1.Code != http.StatusServiceUnavailable || calls != 1 {
		t.Fatalf("first: code=%d calls=%d", rr1.Code, calls)
	}
	if rr1.Header().Get("X-Idempotent-Replayed") != "" {
		t.Fatalf("first request must not be a replay")
	}
	// Retry same key: 5xx was not cached → downstream runs again, not replayed.
	rr2, _ := drive(h, "u", "/iam/v1/projects", "K")
	if calls != 2 {
		t.Fatalf("5xx was cached and replayed: calls=%d want 2", calls)
	}
	if rr2.Header().Get("X-Idempotent-Replayed") != "" {
		t.Fatalf("5xx retry must not carry X-Idempotent-Replayed")
	}
}

// TestIdempotency_StatusBoundary_499Cached_500NotCached pins the exact `< 500`
// boundary: 499 is cached (replayed), 500 is not (re-executed).
func TestIdempotency_StatusBoundary_499Cached_500NotCached(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		wantCalls    int
		wantReplayed bool
	}{
		{"499_cached", 499, 1, true},
		{"500_not_cached", 500, 2, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := NewIdempotencyStore(time.Minute)
			var calls int
			h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("b"))
			}))
			_, _ = drive(h, "u", "/iam/v1/projects", "K")
			rr2, _ := drive(h, "u", "/iam/v1/projects", "K")
			if calls != tc.wantCalls {
				t.Fatalf("status %d: calls=%d want %d", tc.status, calls, tc.wantCalls)
			}
			replayed := rr2.Header().Get("X-Idempotent-Replayed") == "true"
			if replayed != tc.wantReplayed {
				t.Fatalf("status %d: replayed=%v want %v", tc.status, replayed, tc.wantReplayed)
			}
		})
	}
}

// TestIdempotency_Bounded proves the store never grows past its capacity.
func TestIdempotency_Bounded(t *testing.T) {
	store := newIdempotencyStoreWithCap(time.Hour, 8)
	for i := 0; i < 200; i++ {
		store.put("k"+strconv.Itoa(i), idempotencyEntry{expiresAt: time.Now().Add(time.Hour)})
	}
	if got := store.Len(); got > 8 {
		t.Fatalf("store grew to %d, cap 8", got)
	}
	// The most recent key must survive eviction.
	if _, ok := store.get("k199"); !ok {
		t.Fatal("most-recent key was evicted")
	}
}

// TestIdempotency_LargeBodyNotCached proves an oversized response is not cached,
// so it cannot pin large buffers in memory.
func TestIdempotency_LargeBodyNotCached(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)
	var calls int
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), idempotencyMaxBodyBytes+1))
	}))
	_, _ = drive(h, "u", "/iam/v1/projects", "K")
	_, _ = drive(h, "u", "/iam/v1/projects", "K") // not cached → downstream again
	if calls != 2 {
		t.Fatalf("oversized response was cached: calls=%d want 2", calls)
	}
}
