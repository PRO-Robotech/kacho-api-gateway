// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

// introspection_cache_test.go — Hydra introspection LRU+TTL cache.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func newIntrospectionServer(active bool, exp int64) (*httptest.Server, *atomic.Int32) {
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = r.ParseForm()
		body := map[string]any{
			"active": active,
			"sub":    "usr_alice",
			"scope":  "openid profile",
			"exp":    exp,
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	return srv, hits
}

func TestIntrospection_HappyPath_Caches(t *testing.T) {
	srv, hits := newIntrospectionServer(true, time.Now().Add(15*time.Minute).Unix())
	defer srv.Close()

	c, err := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
	})
	require.NoError(t, err)
	res, err := c.Introspect(context.Background(), "jti-1", "rawtoken")
	require.NoError(t, err)
	assert.True(t, res.Active)
	assert.Equal(t, "usr_alice", res.Subject)
	// Second call → cache hit, no extra network.
	_, err = c.Introspect(context.Background(), "jti-1", "rawtoken")
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load())
}

func TestIntrospection_InactiveCached_Negative(t *testing.T) {
	srv, hits := newIntrospectionServer(false, 0)
	defer srv.Close()
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
	})
	_, err := c.Introspect(context.Background(), "jti", "raw")
	assert.ErrorIs(t, err, middleware.ErrTokenInactive)
	// Negative cache: second call also rejected without re-hit.
	_, err = c.Introspect(context.Background(), "jti", "raw")
	assert.ErrorIs(t, err, middleware.ErrTokenInactive)
	assert.Equal(t, int32(1), hits.Load())
}

func TestIntrospection_ExpiredAlreadyAtFetch_TreatedAsInactive(t *testing.T) {
	// Hydra returns active=true but exp is already in the past — defence: we
	// must reject as inactive AND not cache the wrong positive result.
	srv, hits := newIntrospectionServer(true, time.Now().Add(-time.Hour).Unix())
	defer srv.Close()
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
	})
	_, err := c.Introspect(context.Background(), "jti", "raw")
	assert.ErrorIs(t, err, middleware.ErrTokenInactive)
	// Second call also hits the server (no positive caching for past-exp).
	_, err = c.Introspect(context.Background(), "jti", "raw")
	assert.ErrorIs(t, err, middleware.ErrTokenInactive)
	assert.Equal(t, int32(2), hits.Load())
}

// TestIntrospection_ShortExp_ClampsCacheTTL — deterministic (injected clock, no
// wall-clock sleep). exp is 2s ahead of the injected `now`, so the 1h configured
// TTL is clamped to the exp window. A read before exp is a cache hit; a read
// after exp both misses AND re-fetches (where the clamp now finds exp in the
// past → inactive), proving the clamp is driven by the injectable clock.
func TestIntrospection_ShortExp_ClampsCacheTTL(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	nowT := base
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return nowT }
	advance := func(d time.Duration) { mu.Lock(); nowT = nowT.Add(d); mu.Unlock() }

	srv, hits := newIntrospectionServer(true, base.Add(2*time.Second).Unix())
	defer srv.Close()
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
		Now:                   clock,
	})

	// First call at now=base → cached with TTL clamped to the ~2s exp window.
	_, err := c.Introspect(context.Background(), "jti", "raw")
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load())

	// Within the clamp window → cache hit, no re-fetch.
	advance(1 * time.Second)
	_, err = c.Introspect(context.Background(), "jti", "raw")
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load(), "read within clamp window must be a cache hit")

	// Past exp → entry expired (miss) AND the re-fetch clamp sees exp in the
	// past → ErrTokenInactive. Either way Hydra is re-hit.
	advance(2 * time.Second)
	_, err = c.Introspect(context.Background(), "jti", "raw")
	assert.ErrorIs(t, err, middleware.ErrTokenInactive)
	assert.Equal(t, int32(2), hits.Load(), "read past exp must re-hit Hydra")
}

func TestIntrospection_Invalidate(t *testing.T) {
	srv, hits := newIntrospectionServer(true, time.Now().Add(15*time.Minute).Unix())
	defer srv.Close()
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
	})
	_, _ = c.Introspect(context.Background(), "jti", "raw")
	assert.Equal(t, int32(1), hits.Load())
	c.Invalidate("jti")
	_, _ = c.Introspect(context.Background(), "jti", "raw")
	assert.Equal(t, int32(2), hits.Load())
}

func TestIntrospection_HydraError_Bubbles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
	})
	_, err := c.Introspect(context.Background(), "jti", "raw")
	require.Error(t, err)
	assert.False(t, errors.Is(err, middleware.ErrTokenInactive))
}

func TestIntrospection_Construction_RequiresURL(t *testing.T) {
	_, err := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{})
	require.Error(t, err)
}

func TestIntrospection_EmptyJTI_Rejected(t *testing.T) {
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: "http://x",
	})
	_, err := c.Introspect(context.Background(), "", "raw")
	require.Error(t, err)
}
