// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// idempotency_race_test.go — contested-path race test for HTTPIdempotency.
//
// The idempotency contract is "same Idempotency-Key -> same Operation.id".
// A naive check-then-act (get-miss -> downstream -> put) lets two concurrent
// double-submits both miss the cache and both execute the mutating downstream,
// creating two resources / two Operations (CWE-362 / TOCTOU).
// This test asserts exactly-one-winner under concurrency; it fails without the
// single-flight reservation.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIdempotency_ConcurrentSameKey_SingleDownstream fires N parallel POSTs with
// the same (principal, path, key) and asserts the mutating downstream runs
// exactly once while every caller observes the same response body.
func TestIdempotency_ConcurrentSameKey_SingleDownstream(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)

	var calls int64
	release := make(chan struct{})
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until all goroutines are in-flight so a check-then-act
		// implementation is guaranteed to double-execute.
		<-release
		n := atomic.AddInt64(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"op":"` + http.StatusText(int(n)) + `"}`))
	}))

	const n = 16
	var wg sync.WaitGroup
	bodies := make([]string, n)
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/compute/v1/instances", nil)
			r.Header.Set("Idempotency-Key", "same-key")
			r.Header.Set("X-Kacho-Principal-Id", "user-A")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			bodies[idx] = rr.Body.String()
			statuses[idx] = rr.Code
		}(i)
	}
	// Give goroutines time to reach the reservation point, then release.
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("downstream executed %d times, want exactly 1 (single-flight broken)", got)
	}
	for i := 0; i < n; i++ {
		if statuses[i] != http.StatusOK {
			t.Fatalf("caller %d got status %d, want 200", i, statuses[i])
		}
		if bodies[i] != bodies[0] {
			t.Fatalf("caller %d body %q != leader body %q (results diverged)", i, bodies[i], bodies[0])
		}
	}
}

// TestIdempotency_LeaderPanic_FollowersWakeAndReservationReleased proves the
// single-flight liveness contract: when the leader's downstream panics, the
// deferred abortLeader releases the in-flight reservation and wakes every
// follower (they fall through to execute downstream themselves) — no follower
// blocks forever, and the reservation map is cleared so a subsequent same-key
// request proceeds. A regression that drops the deferred abort would deadlock
// all followers; this test (with a timeout) catches it.
func TestIdempotency_LeaderPanic_FollowersWakeAndReservationReleased(t *testing.T) {
	store := NewIdempotencyStore(time.Minute)

	var panicMode atomic.Bool
	panicMode.Store(true)
	release := make(chan struct{})
	h := HTTPIdempotency(store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if panicMode.Load() {
			<-release // hold the leader until all followers are parked on the flight
			panic("downstream boom")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The leader (and any follower that falls through) re-panics; each
			// goroutine recovers its own, mimicking net/http's per-request recover.
			defer func() { _ = recover() }()
			r := httptest.NewRequest(http.MethodPost, "/compute/v1/instances", nil)
			r.Header.Set("Idempotency-Key", "panic-key")
			r.Header.Set("X-Kacho-Principal-Id", "user-A")
			h.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}

	// Let all followers park on the leader's flight, then release the leader to panic.
	time.Sleep(30 * time.Millisecond)
	close(release)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("followers blocked forever after leader panic (abortLeader liveness broken)")
	}

	// Reservation released: a fresh same-key request must execute downstream and
	// succeed (not block, not replay a dead flight).
	panicMode.Store(false)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/compute/v1/instances", nil)
	r.Header.Set("Idempotency-Key", "panic-key")
	r.Header.Set("X-Kacho-Principal-Id", "user-A")
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("post-panic same-key request got %d, want 200 (reservation leaked)", rr.Code)
	}
}
