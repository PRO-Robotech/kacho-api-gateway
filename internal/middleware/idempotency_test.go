// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

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
