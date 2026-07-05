// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// dpop_principal_id_test.go — the DPoP header-injection path must derive the
// principal id with the SAME precedence as the legacy auth.HTTP Hydra path
// (principalFromVerifiedToken): prefer the kacho_principal_id claim over the
// raw OIDC `sub`. Otherwise DPoP.Wrap (inner handler) overwrites the principal
// headers auth.HTTP set, and the downstream FGA subject becomes user:<oidc-sub>
// instead of user:<kacho-id> — a lockout / inconsistent-subject bug
// (CWE-287 / OWASP A07).
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInjectVerifiedTokenHeaders_PrefersKachoPrincipalIDOverSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/users/x", nil)
	vt := &VerifiedToken{
		Subject: "zitadel-uuid-999", // raw OIDC sub — must NOT win
		ACR:     "1",
		ExtClaims: map[string]any{
			"kacho_principal_type": "user",
			"kacho_principal_id":   "usr_abc123", // canonical kacho id — must win
		},
	}
	injectVerifiedTokenHeaders(r, vt)

	if got := r.Header.Get("X-Kacho-Principal-Id"); got != "usr_abc123" {
		t.Fatalf("X-Kacho-Principal-Id = %q, want kacho id usr_abc123 (not raw sub)", got)
	}
	if got := r.Header.Get("Grpc-Metadata-X-Kacho-Principal-Id"); got != "usr_abc123" {
		t.Fatalf("Grpc-Metadata-X-Kacho-Principal-Id = %q, want usr_abc123", got)
	}
	if got := r.Header.Get("X-Kacho-Principal-Type"); got != "user" {
		t.Fatalf("X-Kacho-Principal-Type = %q, want user", got)
	}
}

// TestInjectVerifiedTokenHeaders_TopLevelClaimWins — kacho_principal_id promoted
// to the top-level claim set (Hydra allowed_top_level_claims) is also honored.
func TestInjectVerifiedTokenHeaders_TopLevelClaimWins(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/users/x", nil)
	vt := &VerifiedToken{
		Subject: "sub-raw",
		Claims: map[string]any{
			"kacho_principal_type": "service_account",
			"kacho_principal_id":   "sa_xyz",
		},
	}
	injectVerifiedTokenHeaders(r, vt)
	if got := r.Header.Get("X-Kacho-Principal-Id"); got != "sa_xyz" {
		t.Fatalf("X-Kacho-Principal-Id = %q, want sa_xyz", got)
	}
	if got := r.Header.Get("X-Kacho-Principal-Type"); got != "service_account" {
		t.Fatalf("X-Kacho-Principal-Type = %q, want service_account", got)
	}
}

// TestInjectVerifiedTokenHeaders_FallsBackToSub — when no kacho_principal_id
// claim exists, the raw sub is still used (backward compatible).
func TestInjectVerifiedTokenHeaders_FallsBackToSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/users/x", nil)
	vt := &VerifiedToken{Subject: "sub-only", ACR: "2"}
	injectVerifiedTokenHeaders(r, vt)
	if got := r.Header.Get("X-Kacho-Principal-Id"); got != "sub-only" {
		t.Fatalf("X-Kacho-Principal-Id = %q, want fallback sub-only", got)
	}
}
