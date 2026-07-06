// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Startup-validation tests for the production authz config implemented in
// authz_validation.go: a production-class deployment must refuse a relaxed
// (disabled / fail-open / dev-authN) configuration.
package main

import (
	"strings"
	"testing"
)

// Production env with authz disabled MUST be rejected.
func TestW1_3_08_ProdRefusesAuthzDisabled(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: false, FailOpen: false})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "authz.enabled=false") {
		t.Fatalf("expected 'authz.enabled=false' in error, got: %v", err)
	}
}

// Production env with FailOpen=true MUST be rejected.
func TestW1_3_08b_ProdRefusesFailOpen(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: true, FailOpen: true})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "authz.failOpen=true") {
		t.Fatalf("expected 'authz.failOpen=true' in error, got: %v", err)
	}
}

// Staging is also production-class — refuses misconfig.
func TestW1_3_08c_StagingRefusesFailOpen(t *testing.T) {
	err := validateProductionAuthzConfig("staging", AuthzMiddlewareConfig{Enabled: true, FailOpen: true})
	if err == nil {
		t.Fatalf("expected error in staging, got nil")
	}
}

// Production env with correct config (enabled + fail-closed +
// production-strict authN) accepts.
func TestW1_3_09_ProdAcceptsCorrectConfig(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: true, FailOpen: false, AuthNMode: "production-strict"})
	if err != nil {
		t.Fatalf("expected nil for prod+enabled+fail-closed+strict, got: %v", err)
	}
}

// Prod with anonymous (dev) authN mode MUST be rejected — a production gateway
// must not accept unauthenticated callers even if authz is enabled.
func TestProdRefusesDevAuthNMode(t *testing.T) {
	err := validateProductionAuthzConfig("production", AuthzMiddlewareConfig{Enabled: true, FailOpen: false, AuthNMode: "dev"})
	if err == nil {
		t.Fatalf("expected error for prod + authn dev, got nil")
	}
	if !strings.Contains(err.Error(), "authn.mode") {
		t.Fatalf("expected authn.mode problem, got: %v", err)
	}
}

// An unrecognised / mistyped env (e.g. "prd", "live") is treated as
// production-class and fails closed when authz is misconfigured — a typo in the
// env overlay must not silently skip the production guard.
func TestUnknownEnvFailsClosed(t *testing.T) {
	for _, env := range []string{"prd", "live", "production-eu"} {
		err := validateProductionAuthzConfig(env, AuthzMiddlewareConfig{Enabled: false, FailOpen: false, AuthNMode: "dev"})
		if err == nil {
			t.Fatalf("unknown env %q with disabled authz must fail closed, got nil", env)
		}
	}
}

// "test" env joins dev/local as dev-class — tolerates relaxed config.
func TestTestEnvAllowsRelaxed(t *testing.T) {
	if err := validateProductionAuthzConfig("test", AuthzMiddlewareConfig{Enabled: false, FailOpen: true, AuthNMode: "dev"}); err != nil {
		t.Fatalf("test env must allow relaxed config, got: %v", err)
	}
}

// Empty/unset KACHO_APP_ENV MUST be treated as production-class (fail-closed):
// a deploy that forgets to set the env label must still hard-fail when authz is
// disabled / anonymous authN, instead of silently booting with a full bypass at
// the edge (security.md: any deploy = production-mode, anonymous fail-closed).
func TestEmptyEnvFailsClosed(t *testing.T) {
	err := validateProductionAuthzConfig("", AuthzMiddlewareConfig{Enabled: false, FailOpen: false, AuthNMode: "dev"})
	if err == nil {
		t.Fatalf("empty env with disabled authz must fail closed, got nil")
	}
	if !strings.Contains(err.Error(), "authz.enabled=false") {
		t.Fatalf("expected 'authz.enabled=false' in error, got: %v", err)
	}
}

// Empty env with a correct (secure) posture still boots — only a RELAXED posture
// under an unset env is fatal, not the empty env by itself.
func TestEmptyEnvAcceptsSecureConfig(t *testing.T) {
	if err := validateProductionAuthzConfig("", AuthzMiddlewareConfig{Enabled: true, FailOpen: false, AuthNMode: "production-strict"}); err != nil {
		t.Fatalf("empty env with secure posture must boot, got: %v", err)
	}
}

// dev/local env tolerates relaxed config (WARN-only path). Empty env is NO LONGER
// dev-class (see TestEmptyEnvFailsClosed) — only the explicit dev/local/test
// labels opt out of the fail-closed guard.
func TestW1_3_09b_DevAllowsRelaxedConfig(t *testing.T) {
	if err := validateProductionAuthzConfig("dev", AuthzMiddlewareConfig{Enabled: false, FailOpen: true}); err != nil {
		t.Fatalf("dev must allow relaxed config, got: %v", err)
	}
	if err := validateProductionAuthzConfig("local", AuthzMiddlewareConfig{Enabled: false, FailOpen: true}); err != nil {
		t.Fatalf("local must allow relaxed config, got: %v", err)
	}
}

// Combined problems reported together.
func TestW1_3_09c_ProdReportsBothProblems(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: false, FailOpen: true})
	if err == nil {
		t.Fatalf("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "authz.enabled=false") || !strings.Contains(msg, "authz.failOpen=true") {
		t.Fatalf("expected both problems in error, got: %v", err)
	}
}

// SEC (sec-hardening-r8): a non-empty KACHO_API_GATEWAY_AUTHN_DEV_SECRET in a
// production-class env is a FATAL misconfig — the symmetric HMAC-dev token path
// (a validly-HS256-signed token) yields a real principal / forges a
// service_account with no IAM lookup. A production deploy must never carry a dev
// secret; the gateway must refuse to boot (defense-in-depth alongside the
// runtime refusal in the middleware).
func TestProdRefusesDevSecretSet(t *testing.T) {
	err := validateProductionAuthzConfig("production", AuthzMiddlewareConfig{
		Enabled: true, FailOpen: false, AuthNMode: "production-strict", DevSecretSet: true,
	})
	if err == nil {
		t.Fatalf("expected error for prod + dev secret set, got nil")
	}
	if !strings.Contains(err.Error(), "devSecret") {
		t.Fatalf("expected 'devSecret' problem in error, got: %v", err)
	}
}

// Empty/unset env is production-class (secure-by-default), so a dev secret under
// an unset env must also hard-fail — a forgotten KACHO_APP_ENV cannot smuggle the
// HMAC-dev path into a deployed environment.
func TestEmptyEnvRefusesDevSecretSet(t *testing.T) {
	err := validateProductionAuthzConfig("", AuthzMiddlewareConfig{
		Enabled: true, FailOpen: false, AuthNMode: "production-strict", DevSecretSet: true,
	})
	if err == nil {
		t.Fatalf("expected error for empty env + dev secret set, got nil")
	}
	if !strings.Contains(err.Error(), "devSecret") {
		t.Fatalf("expected 'devSecret' problem in error, got: %v", err)
	}
}

// Dev-class envs tolerate a dev secret (the HMAC-dev path is a dev/e2e affordance
// and the middleware only accepts it under mode==dev anyway).
func TestDevEnvAllowsDevSecretSet(t *testing.T) {
	if err := validateProductionAuthzConfig("dev", AuthzMiddlewareConfig{
		Enabled: true, FailOpen: false, AuthNMode: "dev", DevSecretSet: true,
	}); err != nil {
		t.Fatalf("dev env must allow a dev secret, got: %v", err)
	}
}

// A secure prod posture with NO dev secret still boots — only the dev secret is
// the fatal factor here, not the prod env by itself.
func TestProdAcceptsNoDevSecret(t *testing.T) {
	if err := validateProductionAuthzConfig("production", AuthzMiddlewareConfig{
		Enabled: true, FailOpen: false, AuthNMode: "production-strict", DevSecretSet: false,
	}); err != nil {
		t.Fatalf("prod with no dev secret + secure posture must boot, got: %v", err)
	}
}
