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

// "test" env joins dev/local/"" as dev-class — tolerates relaxed config.
func TestTestEnvAllowsRelaxed(t *testing.T) {
	if err := validateProductionAuthzConfig("test", AuthzMiddlewareConfig{Enabled: false, FailOpen: true, AuthNMode: "dev"}); err != nil {
		t.Fatalf("test env must allow relaxed config, got: %v", err)
	}
}

// dev/local env tolerates relaxed config (WARN-only path).
func TestW1_3_09b_DevAllowsRelaxedConfig(t *testing.T) {
	if err := validateProductionAuthzConfig("dev", AuthzMiddlewareConfig{Enabled: false, FailOpen: true}); err != nil {
		t.Fatalf("dev must allow relaxed config, got: %v", err)
	}
	if err := validateProductionAuthzConfig("", AuthzMiddlewareConfig{Enabled: false, FailOpen: true}); err != nil {
		t.Fatalf("empty env must allow relaxed config, got: %v", err)
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
