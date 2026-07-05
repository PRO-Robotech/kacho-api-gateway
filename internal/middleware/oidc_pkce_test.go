// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

// oidc_pkce_test.go — PKCE (RFC 7636) on the OAuth authorization-code flow. A
// public client (no client_secret) must protect the code exchange with a
// per-request code_verifier bound via S256 code_challenge, so an intercepted
// authorization code is not redeemable without the verifier cookie.

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestOIDCHandler(issuer string) *OIDCHandler {
	return NewOIDCHandler(OIDCConfig{
		Issuer:      issuer,
		ClientID:    "test-client",
		RedirectURI: "https://api.kacho.local/iam/v1/auth/callback",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func pkceCookieFrom(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == pkceCookieName {
			return c
		}
	}
	return nil
}

// Login must emit code_challenge (S256) and persist the matching verifier in an
// HttpOnly cookie so the callback can complete the PKCE exchange.
func TestLogin_EmitsPKCEChallenge(t *testing.T) {
	h := newTestOIDCHandler("https://idp.example")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://api.kacho.local/iam/v1/auth/login", nil)
	h.Login(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", res.StatusCode)
	}
	loc, _ := res.Location()
	if loc == nil {
		t.Fatal("no Location header")
	}
	q := loc.Query()
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("code_challenge missing from authorize redirect")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}

	pk := pkceCookieFrom(res)
	if pk == nil || pk.Value == "" {
		t.Fatal("pkce verifier cookie not set")
	}
	if !pk.HttpOnly {
		t.Error("pkce verifier cookie must be HttpOnly")
	}
	// challenge == base64url(sha256(verifier))
	sum := sha256.Sum256([]byte(pk.Value))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("code_challenge %q does not match S256(verifier) %q", challenge, want)
	}
}

// Callback must forward the code_verifier (from the pkce cookie) on the token
// exchange so the IdP can validate the PKCE binding.
func TestCallback_SendsCodeVerifier(t *testing.T) {
	var gotVerifier string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotVerifier = r.Form.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","id_token":"it","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	h := newTestOIDCHandler(tokenSrv.URL)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"https://api.kacho.local/iam/v1/auth/callback?code=abc&state=xyz", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "xyz"})
	req.AddCookie(&http.Cookie{Name: pkceCookieName, Value: "the-verifier-value"})
	h.Callback(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		body, _ := io.ReadAll(rr.Result().Body)
		t.Fatalf("callback want 302, got %d (%s)", rr.Result().StatusCode, string(body))
	}
	if gotVerifier != "the-verifier-value" {
		t.Fatalf("token exchange code_verifier = %q, want %q", gotVerifier, "the-verifier-value")
	}
}
