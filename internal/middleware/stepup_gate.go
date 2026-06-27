// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// stepup_gate.go — RFC 9470 (OAuth 2.0 Step-up Authentication Challenge) +
// OpenID Connect Core 1.0 §3.1.2.1 ACR enforcement.
//
// Given a permission catalog (`<rpc-fqn> → required_acr_min` + optional
// `mfa_max_age`), the gate decides whether to allow a verified token through.
// On failure it emits an RFC 6750-style challenge that signals the UI to run
// a re-authentication ceremony with elevated `acr_values`.
//
// ACR ordering:
//
//	"0" (anonymous) < "1" (password-only) < "2" (Passkey/UV-preferred) <
//	"3" (Passkey/UV-required, hardware-bound)
//
// `mfa_max_age` enforces a sliding freshness window on `auth_time` — a token
// older than the window is rejected even if its `acr` is high enough,
// forcing a re-auth.
package middleware

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors — mapped to WWW-Authenticate by the HTTP handler.
var (
	ErrStepUpRequired = errors.New("insufficient_user_authentication: higher ACR required")
	ErrMFAStale       = errors.New("insufficient_user_authentication: MFA assertion is stale")
)

// PermissionRequirement — per-RPC authentication policy. Resolved by the
// permission catalog; a missing entry implies the default
// requirement (ACR=2, no max-age).
type PermissionRequirement struct {
	RequiredACRMin string        // "" → no requirement (effectively "0")
	MFAMaxAge      time.Duration // 0 → no requirement
}

// StepUpGate — stateless evaluator.
type StepUpGate struct {
	now func() time.Time
}

// NewStepUpGate constructs an evaluator with the given clock (defaults to
// time.Now). Inject a synthetic clock for tests.
func NewStepUpGate(now func() time.Time) *StepUpGate {
	if now == nil {
		now = time.Now
	}
	return &StepUpGate{now: now}
}

// Check enforces both `acr` floor and `auth_time` freshness. Returns nil on
// pass, a sentinel + descriptive error on fail.
func (g *StepUpGate) Check(token *VerifiedToken, req PermissionRequirement) error {
	if token == nil {
		return errors.New("stepup: token required")
	}

	if req.RequiredACRMin != "" {
		gotRank := acrRank(token.ACR)
		wantRank := acrRank(req.RequiredACRMin)
		if gotRank < wantRank {
			return fmt.Errorf("%w: presented=%q required=%q", ErrStepUpRequired, token.ACR, req.RequiredACRMin)
		}
	}

	if req.MFAMaxAge > 0 {
		if token.AuthTime.IsZero() {
			return fmt.Errorf("%w: auth_time missing in token", ErrMFAStale)
		}
		age := g.now().Sub(token.AuthTime)
		if age > req.MFAMaxAge {
			return fmt.Errorf("%w: age=%s max=%s", ErrMFAStale, age, req.MFAMaxAge)
		}
	}
	return nil
}

// acrRank maps ACR strings to a comparable integer. Unknown values resolve
// to 0 (anonymous) — fail-closed when policy expects ≥ 1.
func acrRank(acr string) int {
	switch acr {
	case "3":
		return 3
	case "2":
		return 2
	case "1":
		return 1
	case "0", "":
		return 0
	default:
		return 0
	}
}

// BuildStepUpChallenge produces an RFC 9470 §3 / RFC 6750 challenge header
// value for the given requirement. Returned string is suitable for direct
// use as the value of `WWW-Authenticate`.
//
// Examples:
//
//	BuildStepUpChallenge(PermissionRequirement{RequiredACRMin: "3"})
//	  → `Bearer error="insufficient_user_authentication",
//	     error_description="Required ACR 3 for this resource; presented ACR 2",
//	     acr_values="3"`
//
// `presentedACR` may be empty (anonymous / no token).
func BuildStepUpChallenge(req PermissionRequirement, presentedACR string) string {
	desc := fmt.Sprintf("Required ACR %s for this resource; presented ACR %s",
		req.RequiredACRMin, defaultIfEmpty(presentedACR, "0"))
	out := `Bearer error="insufficient_user_authentication", error_description="` + desc + `"`
	if req.RequiredACRMin != "" {
		out += `, acr_values="` + req.RequiredACRMin + `"`
	}
	if req.MFAMaxAge > 0 {
		out += fmt.Sprintf(`, max_age="%d"`, int(req.MFAMaxAge.Seconds()))
	}
	return out
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
