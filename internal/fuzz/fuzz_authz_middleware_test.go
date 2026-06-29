// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Continuous fuzzing — authz REST route matcher.
//
// The authz middleware resolves an incoming REST method+path to a gRPC FQN
// (and its permission-catalog entry) before the FGA Check. Malformed paths
// (traversal, null bytes, oversized, encoded) must never panic and must fail
// closed (unresolved → denied). This target drives the REAL resolver
// (middleware.RestRouter.Resolve), not a local reimplementation.

package fuzz_test

import (
	"strings"
	"testing"

	mw "github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func FuzzAuthzMiddleware(f *testing.F) {
	router := mw.NewRestRouter()

	seeds := []string{
		"/iam/v1/users",
		"/iam/v1/users/usr1234567890123456789",
		"/iam/v1/users/../../etc/passwd",
		"/vpc/v1/networks?filter=eq",
		"",
		strings.Repeat("/a", 1000),
		"/iam/v1/%2e%2e/etc/passwd",
		"/iam/v1/users\x00\x00",
		"/IAM/V1/USERS",
		"/iam/v1/users/" + strings.Repeat("a", 1024),
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
		// Resolve must be panic-free for any method/path combination; an
		// unresolved path returns ok=false (the middleware then fails closed).
		_, _ = router.Resolve("GET", urlPath)
		_, _ = router.Resolve("POST", urlPath)
		_, _ = router.Resolve("DELETE", urlPath)
	})
}
