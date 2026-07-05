// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// dpop_replay_cache.go — LRU+TTL store for seen DPoP `jti` values.
//
// RFC 9449 §11.1 requires the resource server to reject a DPoP proof whose
// `jti` has been seen in a window comparable to `iat`-freshness. We implement
// a per-pod LRU (default capacity 100k, entry TTL 120s = 2× iat-freshness
// window) over the shared internal/lrucache primitive. Multi-pod distributed
// replay is mitigated by the 60s `iat` freshness check; the in-process cache is
// sufficient and no shared external store is introduced.
//
// Set semantics: the jti is the key, the value is empty. Replay detection uses
// Peek (NOT Get) so a repeated jti is NOT kept warm in the LRU — an attacker
// replaying a proof must not extend its own entry's lifetime.
package middleware

import (
	"errors"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/lrucache"
)

// ErrDPoPReplay — sentinel; DPoP jti was already used within the freshness
// window. Mapped to `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
var ErrDPoPReplay = errors.New("dpop jti already used (replay detected)")

// DPoPReplayCache — bounded LRU with per-entry TTL, backed by lrucache.
type DPoPReplayCache struct {
	c *lrucache.Cache[string, struct{}]
}

// DPoPReplayCacheConfig — construction parameters.
type DPoPReplayCacheConfig struct {
	MaxEntries int
	TTL        time.Duration
	Now        func() time.Time // tests override
}

// NewDPoPReplayCache constructs a replay cache. Non-positive sizes fall back to
// safe defaults (never silently disable replay protection).
func NewDPoPReplayCache(cfg DPoPReplayCacheConfig) *DPoPReplayCache {
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	return &DPoPReplayCache{c: lrucache.New[string, struct{}](maxEntries, ttl, cfg.Now)}
}

// Add registers a new jti. Returns ErrDPoPReplay if the jti is already present
// (within TTL); otherwise stores it and returns nil. TTL and capacity eviction
// are handled by the underlying cache (capacity eviction is the DoS guard — an
// attacker cannot flood the cache to age out a real jti any faster than the LRU
// bound allows).
//
// Thread-safe under concurrent goroutines.
func (c *DPoPReplayCache) Add(jti string) error {
	if jti == "" {
		return errors.New("empty jti")
	}
	// Peek (no LRU touch) — a replayed jti must not keep itself warm.
	if _, seen := c.c.Peek(jti); seen {
		return ErrDPoPReplay
	}
	c.c.Put(jti, struct{}{})
	return nil
}

// Len returns the current number of entries. Used by tests / observability.
func (c *DPoPReplayCache) Len() int { return c.c.Len() }

// Purge removes all entries. Used by tests and SIGHUP-driven reset (future).
func (c *DPoPReplayCache) Purge() { c.c.Invalidate() }
