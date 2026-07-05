// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// idempotency_race_test.go — contested-path race test for HTTPIdempotency.
//
// The idempotency contract is "same Idempotency-Key -> same Operation.id".
// A naive check-then-act (get-miss -> downstream -> put) lets two concurrent
// double-submits both miss the cache and both execute the mutating downstream,
// creating two resources / two Operations (CWE-362 / TOCTOU; project-rule #10).
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
