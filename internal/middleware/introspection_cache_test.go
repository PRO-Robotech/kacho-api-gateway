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

func TestIntrospection_ShortExp_ClampsCacheTTL(t *testing.T) {
	// exp is 50ms in the future → TTL is clamped to 50ms; second call after
	// expiry must re-hit Hydra.
	srv, hits := newIntrospectionServer(true, time.Now().Add(50*time.Millisecond).Unix()+1)
	defer srv.Close()
	c, _ := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
		HydraIntrospectionURL: srv.URL,
		TTL:                   1 * time.Hour,
	})
	_, err := c.Introspect(context.Background(), "jti", "raw")
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load())
	time.Sleep(1100 * time.Millisecond) // exceed clamp
	_, err = c.Introspect(context.Background(), "jti", "raw")
	// After short clamp + sleep, exp may already be past → ErrTokenInactive,
	// or Hydra still returns active=true depending on race; both are OK so
	// long as the server was re-hit.
	_ = err
	assert.GreaterOrEqual(t, hits.Load(), int32(2))
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
