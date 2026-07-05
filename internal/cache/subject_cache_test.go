// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cache_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/cache"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestSubjectCache_SetGet(t *testing.T) {
	c := cache.NewSubjectCache(10, 1*time.Second, nil)
	c.Set("zit-1", middleware.Subject{Type: "user", ID: "usr-1"})
	v, ok := c.Get("zit-1")
	assert.True(t, ok)
	assert.Equal(t, "usr-1", v.ID)
}

func TestSubjectCache_Miss(t *testing.T) {
	c := cache.NewSubjectCache(10, 1*time.Second, nil)
	_, ok := c.Get("zit-x")
	assert.False(t, ok)
}

func TestSubjectCache_TTL_Expiry(t *testing.T) {
	// Deterministic: step an injected clock past the TTL instead of sleeping.
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	c := cache.NewSubjectCache(10, 50*time.Millisecond, clock)
	c.Set("zit-1", middleware.Subject{ID: "usr-1"})

	// Just before TTL → still present.
	advance(49 * time.Millisecond)
	_, ok := c.Get("zit-1")
	assert.True(t, ok, "entry must survive within TTL")

	// Past TTL → evicted on read.
	advance(2 * time.Millisecond)
	_, ok = c.Get("zit-1")
	assert.False(t, ok, "entry must expire past TTL")
}

func TestSubjectCache_LRU_Eviction(t *testing.T) {
	c := cache.NewSubjectCache(2, 10*time.Second, nil)
	c.Set("a", middleware.Subject{ID: "1"})
	c.Set("b", middleware.Subject{ID: "2"})
	c.Set("c", middleware.Subject{ID: "3"})
	_, ok := c.Get("a")
	assert.False(t, ok)
	_, ok = c.Get("b")
	assert.True(t, ok)
	_, ok = c.Get("c")
	assert.True(t, ok)
}

func TestSubjectCache_Invalidate(t *testing.T) {
	c := cache.NewSubjectCache(10, 10*time.Second, nil)
	c.Set("zit-1", middleware.Subject{ID: "usr-1"})
	c.Invalidate("zit-1")
	_, ok := c.Get("zit-1")
	assert.False(t, ok)
}

func TestSubjectCache_InvalidateAll(t *testing.T) {
	c := cache.NewSubjectCache(10, 10*time.Second, nil)
	c.Set("a", middleware.Subject{ID: "1"})
	c.Set("b", middleware.Subject{ID: "2"})
	c.InvalidateAll()
	assert.Equal(t, 0, c.Len())
}

func TestSubjectCache_ConcurrentAccess(t *testing.T) {
	c := cache.NewSubjectCache(100, 1*time.Second, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Set("k", middleware.Subject{ID: "v"})
			_, _ = c.Get("k")
		}()
	}
	wg.Wait()
}
