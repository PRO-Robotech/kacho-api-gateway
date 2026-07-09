// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCallbackMalformedIssuerNoPanic locks Finding 2: a malformed Issuer must not
// panic the handler. http.NewRequestWithContext returns (nil, err) for a control-char
// URL; the discarded error previously left req==nil and the following req.Header.Set /
// h.http.Do dereferenced nil → panic (opaque 500 via outer recovery). The handler must
// instead detect the build error and return a clean 502 Bad Gateway.
func TestCallbackMalformedIssuerNoPanic(t *testing.T) {
	cfg := OIDCConfig{
		// A DEL (0x7f) control byte in the Issuer makes url.Parse (inside
		// NewRequestWithContext) fail, so req comes back nil.
		Issuer:      "http://kacho-zitadel\x7f:8080",
		ClientID:    "test-client",
		RedirectURI: "http://api.kacho.local/iam/v1/auth/callback",
	}
	h := NewOIDCHandler(cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	req := httptest.NewRequest(http.MethodGet, "http://api.kacho.local/iam/v1/auth/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "xyz"})
	rec := httptest.NewRecorder()

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("Callback panicked on malformed Issuer: %v", p)
		}
	}()
	h.Callback(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("malformed Issuer: got status %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// TestCallbackNon200BodyBounded locks Finding 1: a non-200 token-exchange response
// body must be read through a bounded io.LimitReader (matching the sibling readers in
// introspection_cache.go / logout_handler.go), so a misbehaving/compromised IdP cannot
// force a multi-MB one-shot allocation + log amplification on the unauthenticated
// pre-session path. We assert the logged "body" is capped at 1024 bytes even though the
// server returns far more.
func TestCallbackNon200BodyBounded(t *testing.T) {
	const oversized = 8192
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(bytes.Repeat([]byte("A"), oversized))
	}))
	defer srv.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	cfg := OIDCConfig{
		Issuer:      srv.URL,
		ClientID:    "test-client",
		RedirectURI: "http://api.kacho.local/iam/v1/auth/callback",
	}
	h := NewOIDCHandler(cfg, logger)

	req := httptest.NewRequest(http.MethodGet, "http://api.kacho.local/iam/v1/auth/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "xyz"})
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("non-200 exchange: got status %d, want %d", rec.Code, http.StatusBadGateway)
	}

	// Find the logged body attribute and assert it is bounded to 1024 bytes.
	var found bool
	for _, line := range bytes.Split(bytes.TrimSpace(logBuf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		b, ok := entry["body"].(string)
		if !ok {
			continue
		}
		found = true
		if len(b) > 1024 {
			t.Fatalf("logged body not bounded: got %d bytes, want <= 1024", len(b))
		}
		if strings.Count(b, "A") == oversized {
			t.Fatalf("full oversized body reached the log (%d bytes)", oversized)
		}
	}
	if !found {
		t.Fatal("expected a log entry carrying a bounded body attribute")
	}
}
