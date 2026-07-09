// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestJWKSCache_RefreshDoesNotBlockReadersDuringFetch pins the concurrency
// contract: a slow JWKS endpoint must NOT stall concurrent token verifications.
// refresh() must fetch OUTSIDE the RWMutex (fetch-outside-lock, publish-under-
// lock) so RLock-only readers stay unblocked while a fetch is in flight. In the
// buggy version refresh holds c.mu.Lock() across the blocking HTTP round-trip,
// so a concurrent FetchedAt() (RLock) blocks for the whole fetch → this fails.
func TestJWKSCache_RefreshDoesNotBlockReadersDuringFetch(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(started) })
		<-release // hold the response open — simulate a slow JWKS endpoint
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}`)
	}))
	defer srv.Close()

	c := NewJWKSCache(srv.URL, time.Minute, &http.Client{Timeout: 5 * time.Second})

	// Trigger a refresh; it blocks inside the HTTP fetch until we release.
	go func() { _, _ = c.Resolve(context.Background(), "k1") }()

	<-started // fetch is now in flight (buggy code holds the write lock here)

	// An RLock-only read must return promptly, not wait for the whole fetch.
	done := make(chan struct{})
	go func() { _ = c.FetchedAt(); close(done) }()

	select {
	case <-done:
		// good — reader was not blocked by the in-flight fetch
	case <-time.After(500 * time.Millisecond):
		t.Error("FetchedAt() blocked during an in-flight JWKS fetch — refresh() holds the write lock across network I/O")
	}
	close(release)
}
