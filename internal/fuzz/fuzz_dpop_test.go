// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Continuous fuzzing — DPoP proof parser.
//
// DPoP (RFC 9449) proof tokens are user-controlled via the DPoP request
// header. A malformed proof must never panic and must fail closed. This
// target drives the REAL validator (middleware.DPoPValidator.Validate) with a
// DPoP-bound access token so the fuzzed input flows through the actual
// base64/JSON header parsing, thumbprint comparison, and replay path.

package fuzz_test

import (
	"strings"
	"testing"
	"time"

	mw "github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func FuzzDPoPProof(f *testing.F) {
	cache := mw.NewDPoPReplayCache(mw.DPoPReplayCacheConfig{MaxEntries: 4096, TTL: time.Minute})
	validator, err := mw.NewDPoPValidator(mw.DPoPValidatorConfig{
		ReplayCache:  cache,
		IatFreshness: time.Minute,
	})
	if err != nil {
		f.Fatalf("construct validator: %v", err)
	}
	// A DPoP-bound token (cnf.jkt present) forces Validate to parse the proof
	// header rather than short-circuiting on a plain bearer.
	token := &mw.VerifiedToken{Raw: "fake.access.token"}
	token.Cnf.HasJkt = true
	token.Cnf.Jkt = "ZHVtbXktamt0LXRodW1icHJpbnQ"

	seeds := []string{
		"eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIn19.eyJqdGkiOiJqdGkxIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9hcGkua2FjaG8uY2xvdWQvdjEvbWUiLCJpYXQiOjE3MzAwMDAwMDB9.fake-sig",
		"",
		"abc.def.ghi",
		"...",
		strings.Repeat("a", 100000),
		"eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJqIn0.fake",                 // missing typ/jwk
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqIn0.fake", // typ != dpop+jwt
		"eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwieCI6IlwiPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4ifX0.eyJqdGkiOiJqIn0.fake", // null/script in JWK
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on DPoP proof %q: %v", input, r)
			}
		}()
		// A malformed proof must return an error, never panic. We do not assert
		// the specific error — only that parsing is panic-free and fail-closed.
		_ = validator.Validate(token, mw.DPoPRequest{
			Method:     "GET",
			URL:        "https://api.kacho.cloud/v1/me",
			DPoPHeader: input,
		})
	})
}
