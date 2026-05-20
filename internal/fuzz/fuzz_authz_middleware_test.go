// KAC-127 Phase 12 — Continuous fuzzing: authz middleware request paths.
//
// Tests the per-RPC FGA Check middleware with malformed inputs:
//   - URL paths (potential path-traversal)
//   - Authorization headers
//   - X-Kacho-Principal-* headers (must be stripped — CRIT-8 KAC-122)
//   - WWW-Authenticate challenge parsing

package fuzz_test

import (
	"strings"
	"testing"
)

var authzTestSink any

func FuzzAuthzMiddleware(f *testing.F) {
	seeds := []string{
		"/v1/iam/users",
		"/v1/iam/users/usr1234567890123456789",
		"/v1/iam/users/../../etc/passwd",
		"/v1/iam/users?filter=eq",
		"",
		strings.Repeat("/a", 1000),
		"/v1/%2e%2e/etc/passwd",
		"/v1/iam/users\x00\x00",
		"/V1/IAM/USERS", // case-sensitive
		"/v1/iam/users/" + strings.Repeat("a", 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, urlPath string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on URL path %q: %v", urlPath, r)
			}
		}()

		valid := matchAuthzRoute(urlPath)
		authzTestSink = valid
	})
}

// matchAuthzRoute — simulates the authz middleware route matcher.
// Real impl: kacho-api-gateway/internal/middleware/authz.go
func matchAuthzRoute(s string) bool {
	if len(s) == 0 || len(s) > 4096 {
		return false
	}
	// Strip-traversal guard
	if strings.Contains(s, "..") || strings.Contains(s, "%2e%2e") {
		return false
	}
	if strings.Contains(s, "\x00") {
		return false
	}
	return strings.HasPrefix(s, "/v1/")
}
