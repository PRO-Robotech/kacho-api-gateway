// Package main — startup-validation for the per-RPC AuthZ middleware
// configuration. Lives at the composition root so the gateway refuses to
// boot in production with a fail-open or disabled middleware.
//
// KAC-139 (W1.3 — gateway authz-middleware fail-closed enable).
// Spec: docs/specs/sub-phase-W1.3-gateway-authz-failclosed-acceptance.md §2.3.
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
	Enabled  bool
	FailOpen bool
}

// validateProductionAuthzConfig refuses to start when the deploy environment
// is production-class (prod / production / staging) AND the authz middleware
// is either disabled or running fail-open. Non-production envs (dev / local /
// empty) pass through unconditionally — the caller emits a WARN log line in
// those cases (see main.go wiring for KAC-139).
//
// Root cause it guards against: helm overlay drift that leaves
// `KACHO_API_GATEWAY_AUTHZ_ENABLED=false` or `..._FAIL_OPEN=true` shipped to
// prod (the exact regression W1.3 was raised to plug — values.prod.yaml had
// no `authz:` block, so middleware mounted as silent pass-through).
func validateProductionAuthzConfig(env string, cfg AuthzMiddlewareConfig) error {
	switch strings.ToLower(env) {
	case "prod", "production", "staging":
		// fall through to validation below
	default:
		// dev, local, "" → tolerate any combination (warn-only path lives in main).
		return nil
	}

	var problems []string
	if !cfg.Enabled {
		problems = append(problems, "authz.enabled=false (must be true in prod)")
	}
	if cfg.FailOpen {
		problems = append(problems, "authz.failOpen=true (must be false in prod)")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf(
		"authz config invalid in %s env: %s (KAC-139 W1.3 — refuse to start)",
		strings.ToLower(env), strings.Join(problems, "; "),
	)
}
