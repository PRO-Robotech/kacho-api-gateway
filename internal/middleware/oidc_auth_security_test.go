// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSafeRelativePath verifies that the post-login redirect target is constrained
// to a same-origin relative path — a protocol-relative ("//evil.com") or
// backslash-tricked target must collapse to "/", closing the open-redirect class.
func TestSafeRelativePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/iam/v1/projects?x=1", "/iam/v1/projects?x=1"},
		{"//evil.com", "/"},                    // protocol-relative → absolute in browsers
		{"//evil.com/path", "/"},               // protocol-relative with path
		{"/\\evil.com", "/"},                   // backslash variant (some browsers normalise)
		{"https://evil.com", "/"},              // absolute URL
		{"http://evil.com", "/"},               // absolute URL
		{"evil.com", "/"},                      // not rooted
		{"\\\\evil.com", "/"},                  // UNC-style
		{"/%2F%2Fevil.com", "/%2F%2Fevil.com"}, // encoded — stays a local path, not decoded by Location
		{"/\t/evil.com", "/"},                  // TAB at [1] — browsers strip it → //evil.com
		{"/\r\n//evil.com", "/"},               // CR/LF strip → //evil.com
		{"/a\\b", "/"},                         // backslash mid-path → may normalise to /
		{"/path\x00x", "/"},                    // NUL byte
	}
	for _, tc := range cases {
		if got := safeRelativePath(tc.in); got != tc.want {
			t.Errorf("safeRelativePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRequestIsHTTPS covers the cookie-Secure decision: a request seen over TLS,
// or one forwarded as https by a trusted L7 ingress, is treated as secure.
func TestRequestIsHTTPS(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "http://api.kacho.local/iam/v1/auth/login", nil)
	if requestIsHTTPS(plain) {
		t.Error("plain HTTP request must not be treated as HTTPS")
	}

	fwd := httptest.NewRequest(http.MethodGet, "http://api.kacho.local/iam/v1/auth/login", nil)
	fwd.Header.Set("X-Forwarded-Proto", "https")
	if !requestIsHTTPS(fwd) {
		t.Error("X-Forwarded-Proto: https must be treated as HTTPS (behind TLS-terminating ingress)")
	}
}
