// Package middleware — permission_catalog.go: in-memory permission registry
// loaded from kacho-proto/gen/permission_catalog.json (KAC-127 Phase 3).
//
// The catalog is emitted by `protoc-gen-kacho-permissions` and embedded into
// the api-gateway binary via `//go:embed` from a sibling-replicated copy in
// `internal/middleware/embed/permission_catalog.json` (kept in sync with
// kacho-proto via the `make sync-permission-catalog` Makefile target, mirroring
// the `make sync-migrations` pattern from corelib).
//
// Loaded shape:
//
//	(service-FQN, method-name) → CatalogEntry{permission, required_relation,
//	   required_acr_min, risk_level, requires_mfa_fresh, scope_extractor, …}
//
// The map is read-only after Load; replacement (SIGHUP hot-reload, FS path
// override) swaps the entire map atomically under sync.RWMutex.
//
// Lookup keys are gRPC FQN ("kacho.cloud.vpc.v1.NetworkService/Create") which
// matches the format produced by Phase 1 (acceptance §5 spec):
//
//	"<proto-package>.<Service>/<Method>"
//
// Method-not-found returns ok=false; callers default to "no requirement"
// (anonymous-allowed) which the AuthZ middleware then treats either as
// allowed-through (public allowlist) or denied (fail-closed default) per its
// own policy configuration.
package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
)

// CatalogEntry — Phase 3 catalog row mirrored from
// `kacho.cloud.iam.v1.PermissionCatalogEntry`. Decoded from JSON without
// pulling the proto descriptor (the catalog is intentionally self-contained;
// see permissions_catalog.proto comment).
type CatalogEntry struct {
	// FQN — fully-qualified gRPC method id
	// ("kacho.cloud.vpc.v1.NetworkService/Create"). Map key.
	FQN string `json:"fqn"`

	// Permission — canonical `<domain>.<resource>.<verb>` string
	// ("vpc.networks.create"). Literal "<exempt>" marks public RPCs that
	// bypass per-RPC authz (Login / Register / Recovery / Health).
	Permission string `json:"permission"`

	// RequiredRelation — OpenFGA relation (`viewer` / `editor` / `admin` /
	// domain-specific) checked against the scope.
	RequiredRelation string `json:"required_relation"`

	// ScopeExtractor — how to obtain the scope id from the incoming request.
	ScopeExtractor ScopeExtractor `json:"scope_extractor"`

	// RequiredACRMin — ACR floor as string ("1" / "2" / "3"). Default "2".
	RequiredACRMin string `json:"required_acr_min"`

	// Domain — `<domain>` part of `Permission` ("vpc"). Filled by plugin
	// during emission.
	Domain string `json:"domain"`

	// ResourceType — `<resource>` part of `Permission` ("networks").
	ResourceType string `json:"resource_type"`

	// Action — `<verb>` part of `Permission` ("create").
	Action string `json:"action"`

	// RequiresMFAFresh — true when this RPC requires `mfa_fresh` overlay
	// regardless of the underlying role's conditions. Defaults follow
	// `RiskLevel`: LOW/MEDIUM → false, HIGH/CRITICAL → true.
	RequiresMFAFresh bool `json:"requires_mfa_fresh"`

	// RiskLevel — operator-classification of the permission's blast radius.
	// Values: "RISK_LEVEL_UNSPECIFIED" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL".
	RiskLevel string `json:"risk_level"`

	// Description — admin-UI-surfaced human description (≤ 512 chars).
	Description string `json:"description"`

	// EmittedBuildSHA — git-SHA at catalog emission time; used by audit to
	// detect catalog-vs-binary drift.
	EmittedBuildSHA string `json:"emitted_build_sha"`
}

// ScopeExtractor — mirrored from `kacho.cloud.iam.v1.PermissionScopeExtractor`.
type ScopeExtractor struct {
	// ObjectType — OpenFGA object type ("project" / "vpc_network" / ...).
	ObjectType string `json:"object_type"`

	// FromRequestField — top-level proto request field name from which the
	// scope id is taken. Empty for `<exempt>` and for unparseable methods;
	// the middleware then falls back to the gateway-wide default scope
	// (configured via env).
	FromRequestField string `json:"from_request_field"`
}

// IsExempt reports whether this entry is the wildcard public-allowlist marker.
// Catalog convention: `Permission == "<exempt>"` (also matches when permission
// is empty AND the FQN is on the hard-coded login/health/recovery allowlist).
func (e CatalogEntry) IsExempt() bool {
	return e.Permission == "<exempt>"
}

// PermissionCatalog — in-memory immutable lookup map. Reload via
// `Reload(io.Reader)` swaps the entire entries map atomically.
type PermissionCatalog struct {
	// entries pointer is swapped atomically on reload; readers grab the
	// current snapshot via Load() under RLock.
	entries atomic.Pointer[map[string]CatalogEntry]

	// path remembers where the catalog was originally loaded from so a
	// SIGHUP hot-reload can re-read the same path without extra wiring.
	path atomic.Pointer[string]

	// reload mutex guards path / re-entrant reload calls (entries is
	// already atomic; this protects the read-then-decode sequence).
	reload sync.Mutex
}

// NewPermissionCatalog constructs an empty catalog; callers wire it up via
// LoadFromReader / LoadFromFile / LoadFromBytes.
func NewPermissionCatalog() *PermissionCatalog {
	pc := &PermissionCatalog{}
	empty := map[string]CatalogEntry{}
	pc.entries.Store(&empty)
	return pc
}

// LoadFromBytes parses a JSON document (legacy bare-array OR object with
// `entries` field, per Phase 3 catalog finalization) and replaces the
// in-memory map atomically. Duplicate FQNs return a hard error — the plugin
// guarantees uniqueness; a duplicate indicates a tampered catalog.
func (c *PermissionCatalog) LoadFromBytes(buf []byte) error {
	if len(buf) == 0 {
		return errors.New("permission catalog: empty input")
	}
	// Try Phase 3 object shape first: {"entries": [...], "critical": {...}}.
	var asObject struct {
		Entries []CatalogEntry `json:"entries"`
		// Critical is parsed but currently unused at this layer; the audit
		// pipeline reads it directly from the catalog. Kept here for
		// forward-compat with admin-UI surfaces.
		Critical struct {
			Permissions []string `json:"permissions"`
		} `json:"critical"`
	}
	var entries []CatalogEntry
	if jerr := json.Unmarshal(buf, &asObject); jerr == nil && len(asObject.Entries) > 0 {
		entries = asObject.Entries
	} else {
		// Fallback to Phase 1 bare-array shape: [{...}, {...}].
		if aerr := json.Unmarshal(buf, &entries); aerr != nil {
			return fmt.Errorf("permission catalog: decode (object: %v; array: %w)", jerr, aerr)
		}
	}
	if len(entries) == 0 {
		return errors.New("permission catalog: zero entries decoded")
	}

	next := make(map[string]CatalogEntry, len(entries))
	for i := range entries {
		e := entries[i]
		if e.FQN == "" {
			return fmt.Errorf("permission catalog: entry #%d has empty fqn", i)
		}
		if _, dup := next[e.FQN]; dup {
			return fmt.Errorf("permission catalog: duplicate fqn %q", e.FQN)
		}
		next[e.FQN] = e
	}
	c.entries.Store(&next)
	return nil
}

// LoadFromReader is a thin convenience wrapper over LoadFromBytes.
func (c *PermissionCatalog) LoadFromReader(r io.Reader) error {
	// Cap input at 8 MiB to prevent runaway allocations from a malicious
	// catalog source (file or HTTP). Phase 3 catalog is ~30 KB for 303
	// entries; 8 MiB is ~3 orders of magnitude headroom.
	buf, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return fmt.Errorf("permission catalog: read: %w", err)
	}
	return c.LoadFromBytes(buf)
}

// LoadFromFile reads + decodes from the given filesystem path and remembers
// the path for subsequent SIGHUP reloads.
func (c *PermissionCatalog) LoadFromFile(path string) error {
	if path == "" {
		return errors.New("permission catalog: empty path")
	}
	c.reload.Lock()
	defer c.reload.Unlock()

	f, err := os.Open(path) // #nosec G304 — operator-controlled path
	if err != nil {
		return fmt.Errorf("permission catalog: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if lerr := c.LoadFromReader(f); lerr != nil {
		return lerr
	}
	// Remember path AFTER successful parse — preserve previous path on
	// reload failure so subsequent Reload() doesn't switch to the bad file.
	p := path
	c.path.Store(&p)
	return nil
}

// Reload re-reads the catalog from the path remembered by the last successful
// LoadFromFile. No-op if no path was ever set. Returns the prior LoadFromFile
// error semantics.
func (c *PermissionCatalog) Reload() error {
	p := c.path.Load()
	if p == nil || *p == "" {
		return errors.New("permission catalog: no path stored for reload")
	}
	return c.LoadFromFile(*p)
}

// Lookup returns the catalog entry for the given gRPC FQN, e.g.
// "kacho.cloud.vpc.v1.NetworkService/Create".
//
// Returns ok=false when the FQN is unknown; callers handle this per their
// policy (typically deny-by-default in production, allow-pass in dev).
func (c *PermissionCatalog) Lookup(fqn string) (CatalogEntry, bool) {
	m := c.entries.Load()
	if m == nil {
		return CatalogEntry{}, false
	}
	e, ok := (*m)[fqn]
	return e, ok
}

// Size returns the number of entries currently loaded.
func (c *PermissionCatalog) Size() int {
	m := c.entries.Load()
	if m == nil {
		return 0
	}
	return len(*m)
}

// FQNs returns a sorted slice of all known FQNs. Useful for diagnostics and
// audit-side verification of catalog-vs-tree drift.
func (c *PermissionCatalog) FQNs() []string {
	m := c.entries.Load()
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(*m))
	for k := range *m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
