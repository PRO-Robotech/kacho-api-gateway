// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestKratosClient_Whoami drives the session-cookie authN path against a stub
// Kratos /sessions/whoami. It locks down the fail-closed contract: any non-200,
// decode error, or inactive session yields Active=false (never fail-open), and
// results are cached in the correct (positive/negative) class so a second call
// does not re-hit Kratos.
func TestKratosClient_Whoami(t *testing.T) {
	const cookie = "ory_kratos_session=abc"
	activeBody := `{"active":true,"identity":{"id":"id-123","traits":{"email":"a@b.com","name":{"first":"Ann","last":"Lee"}}}}`
	inactiveBody := `{"active":false,"identity":{"id":"id-9","traits":{"email":"x@y.com"}}}`

	cases := []struct {
		name         string
		status       int
		body         string
		wantActive   bool
		wantIdentity string
		wantEmail    string
		wantDN       string
	}{
		{"active session → positive cache", http.StatusOK, activeBody, true, "id-123", "a@b.com", "Ann Lee"},
		// Inactive-but-200: identity fields are parsed from the body, but Active
		// is false and the result is negatively cached — callers gate on Active.
		{"inactive session → fail-closed negative", http.StatusOK, inactiveBody, false, "id-9", "x@y.com", "x@y.com"},
		{"401 unauthorized → fail-closed negative", http.StatusUnauthorized, `{"error":"no session"}`, false, "", "", ""},
		{"500 server error → fail-closed negative", http.StatusInternalServerError, `boom`, false, "", "", ""},
		{"decode error → fail-closed negative", http.StatusOK, `{not-json`, false, "", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				if r.URL.Path != "/sessions/whoami" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				if r.Header.Get("Cookie") != cookie {
					t.Errorf("cookie not forwarded: %q", r.Header.Get("Cookie"))
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			c := NewKratosClient(srv.URL)
			res := c.Whoami(context.Background(), cookie)

			if res.Active != tc.wantActive {
				t.Fatalf("Active = %v, want %v", res.Active, tc.wantActive)
			}
			if res.IdentityID != tc.wantIdentity {
				t.Errorf("IdentityID = %q, want %q", res.IdentityID, tc.wantIdentity)
			}
			if res.Email != tc.wantEmail {
				t.Errorf("Email = %q, want %q", res.Email, tc.wantEmail)
			}
			if res.DisplayName != tc.wantDN {
				t.Errorf("DisplayName = %q, want %q", res.DisplayName, tc.wantDN)
			}

			// Second call must be served from cache — no extra HTTP round-trip.
			_ = c.Whoami(context.Background(), cookie)
			if got := atomic.LoadInt32(&hits); got != 1 {
				t.Errorf("expected exactly 1 HTTP call (result cached), got %d", got)
			}

			// The result must land in the correct cache class: positive entries
			// carry active=true, negative (fail-closed) entries active=false.
			// Peek does not disturb LRU recency.
			e, cached := c.cache.Peek(cookie)
			if !cached {
				t.Fatal("result not cached after whoami")
			}
			if e.active != tc.wantActive {
				t.Errorf("cache entry active=%v, want %v (wrong positive/negative class)", e.active, tc.wantActive)
			}
		})
	}
}

// TestKratosClient_Whoami_NoHTTPWhenNoInput proves the guard clauses short-circuit
// without any network call (fail-closed, no Kratos load) when the cookie or the
// configured BaseURL is empty.
func TestKratosClient_Whoami_NoHTTPWhenNoInput(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	// Empty cookie → inactive, no HTTP call.
	c := NewKratosClient(srv.URL)
	if res := c.Whoami(context.Background(), ""); res.Active {
		t.Error("empty cookie must yield inactive result")
	}

	// Empty BaseURL → inactive, no HTTP call.
	c2 := NewKratosClient("")
	if res := c2.Whoami(context.Background(), "ory_kratos_session=abc"); res.Active {
		t.Error("empty BaseURL must yield inactive result")
	}

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected 0 HTTP calls for empty cookie/BaseURL, got %d", got)
	}
}
