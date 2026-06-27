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
}

// validateProductionAuthzConfig refuses to start when the deploy environment is
// production-class AND the security posture is relaxed: authz disabled, authz
// fail-open, or an anonymous (dev) authN mode. Only the explicit dev-class
// labels ("" / dev / local / test) tolerate a relaxed config (the caller emits a
// WARN line). Every OTHER env value — including a typo like "prd" or "live" — is
// treated as production-class and validated, so a mistyped overlay fails closed
// rather than silently skipping the guard.
//
// Root cause it guards against: helm overlay drift that leaves the gateway with
// authz disabled / fail-open / anonymous authN in a deployed environment (the
// middleware would otherwise mount as a silent pass-through).
func validateProductionAuthzConfig(env string, cfg AuthzMiddlewareConfig) error {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "", "dev", "local", "test":
		// Dev-class — tolerate any combination (warn-only path lives in main).
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
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf(
		"authz/authn config invalid in %q env: %s (refuse to start)",
		env, strings.Join(problems, "; "),
	)
}
