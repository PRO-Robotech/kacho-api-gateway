// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import "testing"

// TestBuildCacheKey_DeviceAttestationAffectsKey locks the round-5 audit fix:
// device_attestation feeds the FGA device_compliant() condition, so a cached
// ALLOW computed with device_attestation="compliant" must NOT be replayed for
// an otherwise-identical request whose device_attestation differs (e.g.
// "noncompliant") — that request's Check may legitimately DENY. If the cache
// key ignores device_attestation, both contexts collide onto the same key and
// the cache would incorrectly serve the first decision to the second request.
func TestBuildCacheKey_DeviceAttestationAffectsKey(t *testing.T) {
	base := map[string]any{
		"acr_value": "2",
		"mfa_at":    int64(1000),
		"client_ip": "10.0.0.1",
	}

	ctxCompliant := cloneCtx(base)
	ctxCompliant["device_attestation"] = "compliant"

	ctxNonCompliant := cloneCtx(base)
	ctxNonCompliant["device_attestation"] = "noncompliant"

	keyCompliant := buildCacheKey("user:usr_abc", "vpc.subnet.get", "subnet", "sub_123", ctxCompliant)
	keyNonCompliant := buildCacheKey("user:usr_abc", "vpc.subnet.get", "subnet", "sub_123", ctxNonCompliant)

	if keyCompliant == keyNonCompliant {
		t.Fatalf("buildCacheKey must differ when device_attestation differs (compliant vs noncompliant), got identical key %q for both — a cached ALLOW for a compliant device would be replayed for a noncompliant one", keyCompliant)
	}
}

// TestBuildCacheKey_AMRClaimsAffectKey locks the round-5 audit fix: amr_claims
// feeds the FGA mfa_fresh() condition (mfa freshness depends on the
// authentication method used), so two requests differing only in amr_claims
// (e.g. password-only vs password+otp) must produce distinct cache keys.
func TestBuildCacheKey_AMRClaimsAffectKey(t *testing.T) {
	base := map[string]any{
		"acr_value": "2",
		"mfa_at":    int64(1000),
	}

	ctxPasswordOnly := cloneCtx(base)
	ctxPasswordOnly["amr_claims"] = []string{"pwd"}

	ctxWithOTP := cloneCtx(base)
	ctxWithOTP["amr_claims"] = []string{"pwd", "otp"}

	keyPasswordOnly := buildCacheKey("user:usr_abc", "vpc.subnet.get", "subnet", "sub_123", ctxPasswordOnly)
	keyWithOTP := buildCacheKey("user:usr_abc", "vpc.subnet.get", "subnet", "sub_123", ctxWithOTP)

	if keyPasswordOnly == keyWithOTP {
		t.Fatalf("buildCacheKey must differ when amr_claims differs, got identical key %q for both", keyPasswordOnly)
	}
}

func cloneCtx(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
