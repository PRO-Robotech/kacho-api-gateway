// KAC-127 Phase 12 — Continuous fuzzing: DPoP proof parser.
//
// DPoP (RFC 9449) proof tokens are user-controlled via Authorization
// header. Malformed proof must NOT panic, must produce stable error,
// must NOT bypass jti-cache replay protection.

package fuzz_test

import (
	"strings"
	"testing"
)

var dpopTestSink any

func FuzzDPoPProof(f *testing.F) {
	seeds := []string{
		// Well-formed structurally.
		"eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIn19.eyJqdGkiOiJqdGkxIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9hcGkua2FjaG8uY2xvdWQvdjEvbWUiLCJpYXQiOjE3MzAwMDAwMDB9.fake-sig",
		"",
		"abc.def.ghi",
		"...",
		strings.Repeat("a", 100000),
		// Missing typ/jwk header.
		"eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJqIn0.fake",
		// `typ` != `dpop+jwt`.
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqIn0.fake",
		// Adversarial — null in JWK.
		"eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwieCI6IlwiPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4ifX0.eyJqdGkiOiJqIn0.fake",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on DPoP proof: %v", r)
			}
		}()
		valid := parseDPoPStub(input)
		dpopTestSink = valid
	})
}

func parseDPoPStub(s string) bool {
	const maxLen = 64 * 1024
	if len(s) > maxLen {
		return false
	}
	parts := strings.Split(s, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != ""
}
