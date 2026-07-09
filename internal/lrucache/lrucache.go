// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package lrucache is the single bounded TTL+LRU cache primitive for the
// api-gateway. It replaces the several hand-rolled mutex+linked-list+map caches
// that previously each re-implemented the same eviction/expiry logic
// (decision cache, subject cache, introspection cache, replay cache, …), so the
// eviction path exists and is tested exactly once.
//
// Divergent per-caller invalidation semantics are expressed as options ON this
// primitive rather than as forks of it:
//
//   - Invalidate()             — whole-cache flush (session-revocation safety net)
//   - InvalidateKey(k)         — drop a single key
//   - InvalidateWhere(pred)    — drop all keys matching a predicate
//     (e.g. subject-prefix revocation)
//   - Generation()/PutIfGen()  — write-after-invalidate epoch guard: a caller
//     snapshots Generation() at get()-miss time and PutIfGen drops the write if
//     an intervening Invalidate*/ moved the generation, so a value computed
//     against pre-revocation state can never re-populate a just-flushed entry.
//
// The zero value is not usable; construct with New. Safe for concurrent use.
package lrucache

import (
	"container/list"
	"sync"
	"time"
)

// Cache is a bounded, TTL-expiring, LRU-evicting cache keyed by K with values V.
type Cache[K comparable, V any] struct {
	mu      sync.Mutex
	items   map[K]*list.Element
	order   *list.List // front = most-recently-used, back = least-recently-used
	maxSize int
	ttl     time.Duration
	now     func() time.Time
	gen     uint64
}

type entry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt time.Time
}

// New constructs a cache with the given capacity and TTL. A non-positive
// maxSize/ttl falls back to sane defaults; a nil clock falls back to time.Now.
func New[K comparable, V any](maxSize int, ttl time.Duration, now func() time.Time) *Cache[K, V] {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &Cache[K, V]{
		items:   make(map[K]*list.Element, maxSize),
		order:   list.New(),
		maxSize: maxSize,
		ttl:     ttl,
		now:     now,
	}
}

// Get returns the live value for key, refreshing its LRU recency. A missing or
// TTL-expired entry returns the zero value and false (and is evicted).
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	e := el.Value.(*entry[K, V])
	if c.now().After(e.expiresAt) {
		c.order.Remove(el)
		delete(c.items, key)
		var zero V
		return zero, false
	}
	c.order.MoveToFront(el)
	return e.value, true
}

// Peek returns the live value for key WITHOUT refreshing its LRU recency. Used
// by set-membership callers (e.g. DPoP replay detection) that deliberately must
// not keep a repeated key warm. Still honours TTL (an expired entry is evicted
// and reported absent).
func (c *Cache[K, V]) Peek(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	e := el.Value.(*entry[K, V])
	if c.now().After(e.expiresAt) {
		c.order.Remove(el)
		delete(c.items, key)
		var zero V
		return zero, false
	}
	return e.value, true
}

// Put stores value under key with a fresh default TTL, evicting the
// least-recently-used entry when over capacity.
func (c *Cache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(key, value, c.ttl)
}

// AddIfAbsent atomically checks presence (honouring TTL eviction) and inserts
// value under key only if no live entry exists, all under a single lock hold.
// It returns true when it inserted (key was absent/expired) and false when a
// live entry already existed. This is the atomic set-membership primitive for
// callers enforcing a uniqueness invariant (e.g. DPoP jti replay detection):
// unlike a separate Peek-then-Put pair it has no check-then-act window, so
// concurrent adds of the same key resolve to exactly one winner.
//
// Presence is checked WITHOUT refreshing LRU recency (an already-present key is
// not kept warm by a losing add); insertion uses the default TTL.
func (c *Cache[K, V]) AddIfAbsent(key K, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry[K, V])
		if !c.now().After(e.expiresAt) {
			return false // live entry present — do not touch recency, do not insert
		}
		// Expired: evict, then fall through to insert as fresh.
		c.order.Remove(el)
		delete(c.items, key)
	}
	c.putLocked(key, value, c.ttl)
	return true
}

// PutWithTTL stores value under key with a caller-supplied TTL (for callers
// whose per-entry expiry is bounded by an external deadline, e.g. an OAuth
// token `exp`). A non-positive ttl falls back to the cache default.
func (c *Cache[K, V]) PutWithTTL(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.putLocked(key, value, ttl)
}

// Generation returns the current invalidation generation. Snapshot it at
// get()-miss time and hand it to PutIfGen.
func (c *Cache[K, V]) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// PutIfGen stores value only when the generation still equals the caller's
// snapshot. If an Invalidate*/ ran in between, the write is dropped — closing the
// write-after-invalidate race (recomputing on the next request is always safe;
// re-caching a revoked decision is not).
func (c *Cache[K, V]) PutIfGen(key K, value V, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	c.putLocked(key, value, c.ttl)
}

// PutIfGenWithTTL stores value under key with a caller-supplied TTL, but only
// when the generation still equals the caller's snapshot (see PutIfGen). It is
// the TTL-bounded variant used by callers whose per-entry expiry is clamped by
// an external deadline (e.g. an OAuth token `exp`) AND who must honour the
// write-after-invalidate epoch guard. A non-positive ttl falls back to the
// cache default.
func (c *Cache[K, V]) PutIfGenWithTTL(key K, value V, ttl time.Duration, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.putLocked(key, value, ttl)
}

func (c *Cache[K, V]) putLocked(key K, value V, ttl time.Duration) {
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry[K, V])
		e.value = value
		e.expiresAt = c.now().Add(ttl)
		c.order.MoveToFront(el)
		return
	}
	e := &entry[K, V]{key: key, value: value, expiresAt: c.now().Add(ttl)}
	c.items[key] = c.order.PushFront(e)
	if len(c.items) > c.maxSize {
		if back := c.order.Back(); back != nil {
			c.order.Remove(back)
			delete(c.items, back.Value.(*entry[K, V]).key)
		}
	}
}

// Invalidate flushes every entry and bumps the generation.
func (c *Cache[K, V]) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]*list.Element, c.maxSize)
	c.order.Init()
	c.gen++
}

// InvalidateKey drops a single key. It does NOT bump the generation (it targets
// one entry, not a class of in-flight writes).
func (c *Cache[K, V]) InvalidateKey(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// InvalidateWhere drops every entry whose key satisfies pred and bumps the
// generation (even when nothing matched — an in-flight write for the targeted
// class must still be dropped by PutIfGen). Returns the number removed.
func (c *Cache[K, V]) InvalidateWhere(pred func(K) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	removed := 0
	for k, el := range c.items {
		if pred(k) {
			c.order.Remove(el)
			delete(c.items, k)
			removed++
		}
	}
	return removed
}

// Len returns the current number of live entries. Entries whose TTL has
// elapsed but which have not yet been lazily evicted (this cache has no
// background GC — eviction happens on Get/Peek/AddIfAbsent of that key or under
// capacity pressure) are NOT counted, so Len()==0 truthfully means "no live
// entry" for the leak-detection / observability callers that read it.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	n := 0
	for _, el := range c.items {
		if !now.After(el.Value.(*entry[K, V]).expiresAt) {
			n++
		}
	}
	return n
}
