// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package lrucache

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCache_PutGet(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	c.Put("a", 1)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("Get(a)=%d,%v want 1,true", v, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Fatal("Get(missing) should miss")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	adv := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	c := New[string, int](10, 50*time.Millisecond, clock)
	c.Put("a", 1)
	adv(49 * time.Millisecond)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("entry must survive within TTL")
	}
	adv(2 * time.Millisecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("entry must expire past TTL")
	}
}

func TestCache_Len_ExcludesExpired(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	adv := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	c := New[string, int](10, 50*time.Millisecond, clock)
	c.Put("a", 1)
	c.Put("b", 2)
	if got := c.Len(); got != 2 {
		t.Fatalf("Len()=%d, want 2 live", got)
	}
	// Both TTLs elapse but no Get/Peek touches them, so nothing is lazily
	// evicted. Len() documents itself as reporting LIVE entries, so it must
	// exclude the now-expired (but still-mapped) entries.
	adv(51 * time.Millisecond)
	if got := c.Len(); got != 0 {
		t.Fatalf("Len()=%d after TTL, want 0 live", got)
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := New[string, int](2, time.Minute, nil)
	c.Put("a", 1)
	c.Put("b", 2)
	// Touch a so b becomes least-recently-used.
	c.Get("a")
	c.Put("c", 3)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted as LRU")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should survive (recently used)")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("c should be present")
	}
}

func TestCache_InvalidateKey(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	c.Put("a", 1)
	c.InvalidateKey("a")
	if _, ok := c.Get("a"); ok {
		t.Fatal("a should be gone")
	}
}

func TestCache_InvalidateWhere_Prefix(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	c.Put("user:x|1", 1)
	c.Put("user:x|2", 2)
	c.Put("user:y|1", 3)
	n := c.InvalidateWhere(func(k string) bool { return strings.HasPrefix(k, "user:x|") })
	if n != 2 {
		t.Fatalf("removed %d, want 2", n)
	}
	if c.Len() != 1 {
		t.Fatalf("len %d, want 1", c.Len())
	}
}

func TestCache_EpochGuard_DropsStaleWrite(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	gen := c.Generation()
	if _, ok := c.Get("k"); ok {
		t.Fatal("cold miss expected")
	}
	c.InvalidateWhere(func(string) bool { return false }) // bumps gen, removes nothing
	c.PutIfGen("k", 1, gen)
	if _, ok := c.Get("k"); ok {
		t.Fatal("stale PutIfGen after invalidation must be dropped")
	}
}

func TestCache_PutIfGenWithTTL_DropsStaleWrite(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	gen := c.Generation()
	if _, ok := c.Get("k"); ok {
		t.Fatal("cold miss expected")
	}
	c.InvalidateWhere(func(string) bool { return false }) // bumps gen, removes nothing
	c.PutIfGenWithTTL("k", 1, time.Minute, gen)
	if _, ok := c.Get("k"); ok {
		t.Fatal("stale PutIfGenWithTTL after invalidation must be dropped")
	}
}

func TestCache_PutIfGenWithTTL_KeepsFreshWrite(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	gen := c.Generation()
	c.PutIfGenWithTTL("k", 7, time.Minute, gen)
	if v, ok := c.Get("k"); !ok || v != 7 {
		t.Fatalf("fresh PutIfGenWithTTL must persist: %d,%v", v, ok)
	}
}

func TestCache_EpochGuard_KeepsFreshWrite(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	gen := c.Generation()
	c.PutIfGen("k", 7, gen)
	if v, ok := c.Get("k"); !ok || v != 7 {
		t.Fatalf("fresh PutIfGen must persist: %d,%v", v, ok)
	}
}

func TestCache_Invalidate_BumpsGeneration(t *testing.T) {
	c := New[string, int](10, time.Minute, nil)
	g0 := c.Generation()
	c.Invalidate()
	if c.Generation() == g0 {
		t.Fatal("Invalidate must bump generation")
	}
}

func TestCache_Peek_NoLRUTouch(t *testing.T) {
	c := New[string, int](2, time.Minute, nil)
	c.Put("a", 1)
	c.Put("b", 2)
	// Peek a — must NOT refresh its recency, so a stays LRU.
	if v, ok := c.Peek("a"); !ok || v != 1 {
		t.Fatalf("Peek(a)=%d,%v want 1,true", v, ok)
	}
	c.Put("c", 3) // evicts LRU
	if _, ok := c.Peek("a"); ok {
		t.Fatal("a should have been evicted (Peek must not keep it warm)")
	}
	if _, ok := c.Peek("b"); !ok {
		t.Fatal("b should survive")
	}
}

func TestCache_Peek_RespectsTTL(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	adv := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	c := New[string, int](10, 50*time.Millisecond, clock)
	c.Put("a", 1)
	adv(60 * time.Millisecond)
	if _, ok := c.Peek("a"); ok {
		t.Fatal("Peek must report expired entry as absent")
	}
}

func TestCache_PutWithTTL(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	adv := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	c := New[string, int](10, time.Hour, clock) // long default TTL
	c.PutWithTTL("a", 1, 100*time.Millisecond)  // short override
	adv(90 * time.Millisecond)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("entry must survive within per-entry TTL")
	}
	adv(20 * time.Millisecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("entry must expire at per-entry TTL, not the long default")
	}
}

func TestCache_AddIfAbsent_Basic(t *testing.T) {
	c := New[string, struct{}](10, time.Minute, nil)
	if !c.AddIfAbsent("a", struct{}{}) {
		t.Fatal("first AddIfAbsent(a) must insert and return true")
	}
	if c.AddIfAbsent("a", struct{}{}) {
		t.Fatal("second AddIfAbsent(a) must observe present entry and return false")
	}
}

func TestCache_AddIfAbsent_RespectsTTL(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	adv := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	c := New[string, struct{}](10, 50*time.Millisecond, clock)
	if !c.AddIfAbsent("a", struct{}{}) {
		t.Fatal("first insert must succeed")
	}
	adv(60 * time.Millisecond) // expire
	if !c.AddIfAbsent("a", struct{}{}) {
		t.Fatal("after TTL expiry AddIfAbsent must treat key as absent and re-insert")
	}
}

func TestCache_AddIfAbsent_NoLRUTouchOnLosingAdd(t *testing.T) {
	c := New[string, struct{}](2, time.Minute, nil)
	c.AddIfAbsent("a", struct{}{})
	c.AddIfAbsent("b", struct{}{})
	// Losing AddIfAbsent on present "a" must NOT refresh its recency.
	if c.AddIfAbsent("a", struct{}{}) {
		t.Fatal("AddIfAbsent(a) should have lost (a present)")
	}
	c.AddIfAbsent("c", struct{}{}) // evicts LRU
	if _, ok := c.Peek("a"); ok {
		t.Fatal("a should have been evicted (losing AddIfAbsent must not keep it warm)")
	}
	if _, ok := c.Peek("b"); !ok {
		t.Fatal("b should survive")
	}
}

func TestCache_AddIfAbsent_ConcurrentSameKey_OneWinner(t *testing.T) {
	c := New[string, struct{}](64, time.Hour, nil)
	const N = 200
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.AddIfAbsent("contested", struct{}{}) {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("AddIfAbsent concurrent winners = %d, want exactly 1", wins)
	}
}

func TestCache_ConcurrentRace(t *testing.T) {
	c := New[string, int](1000, time.Minute, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				gen := c.Generation()
				if _, ok := c.Get("k"); !ok {
					c.PutIfGen("k", id, gen)
				}
				if j%100 == 0 {
					c.InvalidateWhere(func(string) bool { return true })
				}
			}
		}(i)
	}
	wg.Wait()
}
