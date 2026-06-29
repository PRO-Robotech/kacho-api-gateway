// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_overrides.go — File-based per-route override registry for the authz
// middleware.
//
// Overrides bypass the IAM AuthorizeService check entirely — useful for
// emergency lockdown (force-deny everything except a small allowlist) or
// for staged rollouts (force-allow a new RPC before its catalog entry has
// shipped to all clusters).
//
// File format (YAML, hot-reloadable via SIGHUP):
//
//	# /etc/kacho/api-gateway/authz_overrides.yaml
//	version: 1
//	overrides:
//	  - fqn: "kacho.cloud.iam.v1.AccessBindingService/Upsert"
//	    decision: "deny"   # emergency lock — no one can mutate role grants
//	    reason: "incident response: freeze role-grant mutations"
//	  - fqn: "kacho.cloud.vpc.v1.NetworkService/Get"
//	    decision: "allow"  # temporarily public during catalog migration
//	    reason: "catalog drift: shipping fix in v2.3"
//
// Decisions:
//
//	"allow" — pass through without Check (subject still injected; just no FGA call).
//	"deny"  — return PermissionDenied with the supplied reason.
//
// Invalid YAML / unknown FQN / unknown decision → load fails, previous map
// preserved. Reload is atomic.
package middleware

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// OverrideDecision — possible per-route overrides.
type OverrideDecision int

const (
	// OverrideNone — no override applies (default).
	OverrideNone OverrideDecision = iota
	// OverrideAllow — bypass IAM Check, pass-through.
	OverrideAllow
	// OverrideDeny — return PermissionDenied unconditionally.
	OverrideDeny
)

// String renders an OverrideDecision for logs.
func (d OverrideDecision) String() string {
	switch d {
	case OverrideAllow:
		return "allow"
	case OverrideDeny:
		return "deny"
	default:
		return "none"
	}
}

// AuthzOverrides — atomic-swappable map of FQN → OverrideDecision.
type AuthzOverrides struct {
	current atomic.Pointer[map[string]overrideEntry]
	path    atomic.Pointer[string]
	mu      sync.Mutex
}

type overrideEntry struct {
	decision OverrideDecision
	reason   string
}

// NewAuthzOverrides constructs an empty registry; LoadFromFile / Reload
// populate it.
func NewAuthzOverrides() *AuthzOverrides {
	o := &AuthzOverrides{}
	empty := map[string]overrideEntry{}
	o.current.Store(&empty)
	return o
}

// authzOverrideFile — YAML root structure.
type authzOverrideFile struct {
	Version   int                      `yaml:"version"`
	Overrides []authzOverrideFileEntry `yaml:"overrides"`
}

type authzOverrideFileEntry struct {
	FQN      string `yaml:"fqn"`
	Decision string `yaml:"decision"`
	Reason   string `yaml:"reason"`
}

// LoadFromBytes parses a YAML document and atomically replaces the map.
// Returns a hard error on syntax problems / unknown decision strings.
func (o *AuthzOverrides) LoadFromBytes(buf []byte) error {
	if len(buf) == 0 {
		// Treat empty input as "clear all overrides".
		empty := map[string]overrideEntry{}
		o.current.Store(&empty)
		return nil
	}
	var doc authzOverrideFile
	if err := yaml.Unmarshal(buf, &doc); err != nil {
		return fmt.Errorf("authz overrides: yaml unmarshal: %w", err)
	}
	if doc.Version != 0 && doc.Version != 1 {
		return fmt.Errorf("authz overrides: unsupported version %d (expected 1)", doc.Version)
	}
	next := make(map[string]overrideEntry, len(doc.Overrides))
	for i, e := range doc.Overrides {
		fqn := strings.TrimSpace(e.FQN)
		if fqn == "" {
			return fmt.Errorf("authz overrides: entry #%d has empty fqn", i)
		}
		if _, dup := next[fqn]; dup {
			return fmt.Errorf("authz overrides: duplicate fqn %q", fqn)
		}
		dec, err := parseOverrideDecision(e.Decision)
		if err != nil {
			return fmt.Errorf("authz overrides: entry %q: %w", fqn, err)
		}
		next[fqn] = overrideEntry{decision: dec, reason: e.Reason}
	}
	o.current.Store(&next)
	return nil
}

// LoadFromReader convenience wrapper.
func (o *AuthzOverrides) LoadFromReader(r io.Reader) error {
	buf, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return fmt.Errorf("authz overrides: read: %w", err)
	}
	return o.LoadFromBytes(buf)
}

// LoadFromFile reads + parses; remembers the path for Reload.
func (o *AuthzOverrides) LoadFromFile(path string) error {
	if path == "" {
		return errors.New("authz overrides: empty path")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	f, err := os.Open(path) // #nosec G304 — operator-controlled path
	if err != nil {
		return fmt.Errorf("authz overrides: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if lerr := o.LoadFromReader(f); lerr != nil {
		return lerr
	}
	p := path
	o.path.Store(&p)
	return nil
}

// Reload re-reads from the previously-stored path; no-op when never loaded
// from a file.
func (o *AuthzOverrides) Reload() error {
	p := o.path.Load()
	if p == nil || *p == "" {
		return errors.New("authz overrides: no path stored for reload")
	}
	return o.LoadFromFile(*p)
}

// Lookup returns (decision, true) when an override applies. (OverrideNone,
// false) means the request continues through normal flow.
func (o *AuthzOverrides) Lookup(fqn string) (OverrideDecision, bool) {
	m := o.current.Load()
	if m == nil {
		return OverrideNone, false
	}
	e, ok := (*m)[fqn]
	if !ok {
		return OverrideNone, false
	}
	return e.decision, true
}

// Reason returns the operator-supplied reason for the override; empty when
// none configured or no override matches.
func (o *AuthzOverrides) Reason(fqn string) string {
	m := o.current.Load()
	if m == nil {
		return ""
	}
	e, ok := (*m)[fqn]
	if !ok {
		return ""
	}
	return e.reason
}

// Size returns the number of active overrides.
func (o *AuthzOverrides) Size() int {
	m := o.current.Load()
	if m == nil {
		return 0
	}
	return len(*m)
}

func parseOverrideDecision(s string) (OverrideDecision, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow", "permit":
		return OverrideAllow, nil
	case "deny", "forbid":
		return OverrideDeny, nil
	default:
		return OverrideNone, fmt.Errorf("unknown decision %q (expected 'allow' or 'deny')", s)
	}
}
