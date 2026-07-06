// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// dpop_replay_cache_test.go — LRU+TTL cache invariants under concurrency.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestDPoPReplayCache_Add_Replay(t *testing.T) {
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 16,
		TTL:        time.Minute,
	})
	require.NoError(t, c.Add("jti-a"))
	require.NoError(t, c.Add("jti-b"))
	require.ErrorIs(t, c.Add("jti-a"), middleware.ErrDPoPReplay)
}

func TestDPoPReplayCache_TTLExpiration(t *testing.T) {
	// Use a mock clock to step time deterministically.
	var current atomic.Int64
	current.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, current.Load()) }

	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 16,
		TTL:        1 * time.Second,
		Now:        now,
	})
	require.NoError(t, c.Add("jti"))
	// Step time past TTL.
	current.Add(int64(2 * time.Second))
	// Adding the same jti again should now succeed — entry expired.
	require.NoError(t, c.Add("jti"))
}

func TestDPoPReplayCache_CapacityEviction(t *testing.T) {
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 3,
		TTL:        time.Hour,
	})
	require.NoError(t, c.Add("a"))
	require.NoError(t, c.Add("b"))
	require.NoError(t, c.Add("c"))
	// Capacity is 3 and full. Adding a 4th key evicts EXACTLY the
	// least-recently-inserted key (the LRU tail, "a"); "b" and "c" must remain
	// resident. Add does not refresh recency of a present key (AddIfAbsent), so
	// insertion order == recency order here.
	require.NoError(t, c.Add("d"))
	assert.Equal(t, 3, c.Len(), "capacity must stay bounded at MaxEntries")

	// The eviction victim ("a") is the ONLY key that becomes re-addable — i.e.
	// it was the one evicted. Re-adding it is the replay-relevant path: an
	// evicted jti is legitimately treated as fresh again.
	require.NoError(t, c.Add("a"), "evicted jti must be re-addable as fresh")

	// Re-adding "a" (now at capacity again) evicts the new tail ("b"). The
	// still-resident keys ("c", "d") MUST continue to be rejected as replays —
	// eviction pressure must not silently re-admit a jti that was never evicted.
	require.ErrorIs(t, c.Add("c"), middleware.ErrDPoPReplay,
		"resident jti c must stay blocked under eviction pressure")
	require.ErrorIs(t, c.Add("d"), middleware.ErrDPoPReplay,
		"resident jti d must stay blocked under eviction pressure")
	assert.Equal(t, 3, c.Len())
}

func TestDPoPReplayCache_ConcurrentAdd(t *testing.T) {
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 10000,
		TTL:        time.Hour,
	})
	var wg sync.WaitGroup
	const N = 1000
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = c.Add("uniq-" + itoa(i))
		}(i)
	}
	wg.Wait()
	assert.Equal(t, N, c.Len())
}

func TestDPoPReplayCache_ConcurrentSameJti_OnlyOneWins(t *testing.T) {
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 64,
		TTL:        time.Hour,
	})
	const N = 200
	var success, replay int32
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.Add("contested")
			if err == nil {
				atomic.AddInt32(&success, 1)
			} else {
				atomic.AddInt32(&replay, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), success)
	assert.Equal(t, int32(N-1), replay)
}

func TestDPoPReplayCache_Purge(t *testing.T) {
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 16,
		TTL:        time.Hour,
	})
	require.NoError(t, c.Add("x"))
	require.NoError(t, c.Add("y"))
	assert.Equal(t, 2, c.Len())
	c.Purge()
	assert.Equal(t, 0, c.Len())
	require.NoError(t, c.Add("x"))
}

func TestDPoPReplayCache_EmptyJtiRejected(t *testing.T) {
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
		MaxEntries: 16,
		TTL:        time.Minute,
	})
	assert.Error(t, c.Add(""))
}

func TestDPoPReplayCache_DefaultsApplied(t *testing.T) {
	// Construction with zero values must apply defaults (100k entries, 120s TTL).
	c := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{})
	require.NoError(t, c.Add("a"))
	assert.Equal(t, 1, c.Len())
}

// itoa — small helper to avoid pulling strconv in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := "0123456789"
	out := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		out = string(digits[n%10]) + out
		n /= 10
	}
	if neg {
		out = "-" + out
	}
	return out
}
