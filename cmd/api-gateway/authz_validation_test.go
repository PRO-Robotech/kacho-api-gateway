// KAC-139 (W1.3): startup-validation tests for the production authz config.
// These tests are RED-first per superpowers:test-driven-development — they fail
// (compile error) before the GREEN code in authz_validation.go is added, then
// pass once it's wired.
package main

import (
	"strings"
	"testing"
)

// W1.3-08 — production env with authz disabled MUST be rejected.
func TestW1_3_08_ProdRefusesAuthzDisabled(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: false, FailOpen: false})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "authz.enabled=false") {
		t.Fatalf("expected 'authz.enabled=false' in error, got: %v", err)
	}
}

// W1.3-08b — production env with FailOpen=true MUST be rejected.
func TestW1_3_08b_ProdRefusesFailOpen(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: true, FailOpen: true})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "authz.failOpen=true") {
		t.Fatalf("expected 'authz.failOpen=true' in error, got: %v", err)
	}
}

// W1.3-08c — staging also production-class — refuses misconfig.
func TestW1_3_08c_StagingRefusesFailOpen(t *testing.T) {
	err := validateProductionAuthzConfig("staging", AuthzMiddlewareConfig{Enabled: true, FailOpen: true})
	if err == nil {
		t.Fatalf("expected error in staging, got nil")
	}
}

// W1.3-09 — production env with correct config (enabled + fail-closed) accepts.
func TestW1_3_09_ProdAcceptsCorrectConfig(t *testing.T) {
	err := validateProductionAuthzConfig("prod", AuthzMiddlewareConfig{Enabled: true, FailOpen: false})
	if err != nil {
		t.Fatalf("expected nil for prod+enabled+fail-closed, got: %v", err)
	}
}

// W1.3-09b — dev/local env tolerates relaxed config (WARN-only path).
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

// W1.3-09c — combined problems reported together.
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
