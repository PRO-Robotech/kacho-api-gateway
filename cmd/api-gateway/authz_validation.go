// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package main — startup-validation for the per-RPC AuthZ middleware
// configuration. Lives at the composition root so the gateway refuses to
// boot in production with a fail-open or disabled middleware.
package main

import (
	"fmt"
	"strings"
)

// AuthzMiddlewareConfig is the minimal cross-section of the middleware
// configuration that the startup-validator cares about: the master toggle
// (`Enabled`) and the legacy override (`FailOpen`).
//
// Defined as a small value-type at the composition root (not the middleware
// package) so the validator can be tested without pulling the whole
// middleware/clients dependency graph into a `package main` test binary.
// At wire-time, main() populates it from `cfg.AuthZEnabled` / `cfg.AuthZFailOpen`.
type AuthzMiddlewareConfig struct {
	Enabled   bool
	FailOpen  bool
	AuthNMode string // "dev" | "production" | "production-strict"
	// DevSecretSet reports whether KACHO_API_GATEWAY_AUTHN_DEV_SECRET is non-empty.
	// A dev secret in a production-class env is a fatal misconfig: the symmetric
	// HMAC-dev token path yields a real principal / forges a service_account with
	// no IAM lookup (CWE-347). populated from `cfg.AuthNDevSecret != ""`.
	DevSecretSet bool
}

// validateProductionAuthzConfig refuses to start when the deploy environment is
// production-class AND the security posture is relaxed: authz disabled, authz
// fail-open, or an anonymous (dev) authN mode. Only the explicit dev-class
// labels ("dev" / "local" / "test") tolerate a relaxed config (the caller emits
// a WARN line). Every OTHER env value — an empty/unset label, or a typo like
// "prd" / "live" — is treated as production-class and validated (secure-by-
// default): a deploy that forgets to set KACHO_APP_ENV still fails closed rather
// than silently skipping the guard (CWE-1188; security.md "any deploy =
// production-mode, anonymous fail-closed").
//
// Root cause it guards against: helm overlay drift that leaves the gateway with
// authz disabled / fail-open / anonymous authN in a deployed environment (the
// middleware would otherwise mount as a silent pass-through).
func validateProductionAuthzConfig(env string, cfg AuthzMiddlewareConfig) error {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "dev", "local", "test":
		// Dev-class — tolerate any combination (warn-only path lives in main).
		// NOTE: an empty/unset env is intentionally NOT here — it is production-
		// class (fail-closed) so a forgotten KACHO_APP_ENV cannot skip the guard.
		return nil
	}

	var problems []string
	if !cfg.Enabled {
		problems = append(problems, "authz.enabled=false (must be true in prod)")
	}
	if cfg.FailOpen {
		problems = append(problems, "authz.failOpen=true (must be false in prod)")
	}
	switch cfg.AuthNMode {
	case "production", "production-strict":
		// ok — authenticated callers required.
	default:
		problems = append(problems, fmt.Sprintf(
			"authn.mode=%q (must be production or production-strict in prod)", cfg.AuthNMode))
	}
	if cfg.DevSecretSet {
		// SEC (sec-hardening-r8): the HMAC-dev symmetric token path is a dev/e2e
		// affordance. A dev secret in a production-class env lets a validly-
		// HS256-signed token forge a principal (a service_account with NO IAM
		// lookup) — symmetric-key principal forgery (CWE-347). Refuse to boot.
		problems = append(problems,
			"authn.devSecret set (KACHO_API_GATEWAY_AUTHN_DEV_SECRET must be empty in prod — symmetric-key principal forgery)")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf(
		"authz/authn config invalid in %q env: %s (refuse to start)",
		env, strings.Join(problems, "; "),
	)
}
