// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// introspection_cache.go — Hydra-backed token introspection with negative-TTL
// LRU cache.
//
// Purpose: even when the access token's signature + claims pass local
// verification, the token may have been revoked server-side (admin logout,
// CAEP push, back-channel logout). Hydra's `/oauth2/introspect` is the
// authoritative answer, but calling it on every request is too expensive
// (≈ 50–100ms p95). We add a tiny LRU with TTL = min(5s, exp-now) so a fresh
// access token only round-trips Hydra at most every 5s.
//
// Negative caching: when introspection returns `active=false`, we still cache
// the result (under the same TTL) — repeated requests from a compromised
// client shouldn't hammer Hydra.
//
// Invalidation: callers (session-revocations watcher) call Invalidate(jti)
// when a Postgres LISTEN/NOTIFY arrives. This is the primary path; the TTL
// is a backstop for the case where the NOTIFY connection drops.
//
// The cache itself is a simple sync.Map + min-heap is unnecessary at this
// scale; we use the same LRU pattern as dpop_replay_cache.go but track exp
// on each entry.
package middleware

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrTokenInactive — Hydra reported `active=false`; bubble up to caller and
// terminate request with 401.
var ErrTokenInactive = errors.New("token is not active (revoked or expired upstream)")

// IntrospectionResult — minimal RFC 7662 §2.2 response shape. Hydra returns
// many more fields; we keep only what downstream needs.
type IntrospectionResult struct {
	Active   bool   `json:"active"`
	Subject  string `json:"sub,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ExpiryAt int64  `json:"exp,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	TokenUse string `json:"token_use,omitempty"`
}

// IntrospectionCache — LRU + TTL.
type IntrospectionCache struct {
	url        string
	httpClient *http.Client
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

	// HTTP basic auth for the Hydra admin /introspect endpoint (Hydra requires
	// it for any client-credentials introspection in production). Optional.
	basicUser string
	basicPass string

	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

type introspectionEntry struct {
	jti       string
	result    IntrospectionResult
	expiresAt time.Time
}

// IntrospectionCacheConfig — construction parameters.
type IntrospectionCacheConfig struct {
	HydraIntrospectionURL string
	HTTPClient            *http.Client
	MaxEntries            int
	TTL                   time.Duration
	Now                   func() time.Time
	BasicAuthUser         string
	BasicAuthPass         string
}

// NewIntrospectionCache constructs a cache. Returns error on empty URL.
func NewIntrospectionCache(cfg IntrospectionCacheConfig) (*IntrospectionCache, error) {
	if cfg.HydraIntrospectionURL == "" {
		return nil, errors.New("introspection cache: HydraIntrospectionURL is required")
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &IntrospectionCache{
		url:        cfg.HydraIntrospectionURL,
		httpClient: hc,
		maxEntries: cfg.MaxEntries,
		ttl:        cfg.TTL,
		now:        now,
		basicUser:  cfg.BasicAuthUser,
		basicPass:  cfg.BasicAuthPass,
		entries:    make(map[string]*list.Element),
		lru:        list.New(),
	}, nil
}

// Introspect returns the cached or freshly-fetched introspection result.
// Returns ErrTokenInactive when Hydra (or the cached entry) reports active=false.
//
// Key is the access-token JTI — small, opaque, never logged. We never pass
// the raw token through the cache map (defence-in-depth against memory dump
// disclosure).
func (c *IntrospectionCache) Introspect(ctx context.Context, jti, rawToken string) (IntrospectionResult, error) {
	if jti == "" {
		return IntrospectionResult{}, errors.New("introspect: jti required")
	}
	if rawToken == "" {
		return IntrospectionResult{}, errors.New("introspect: raw token required")
	}

	// 1. Cache hit?
	if r, ok := c.get(jti); ok {
		if !r.Active {
			return r, ErrTokenInactive
		}
		return r, nil
	}

	// 2. Fetch from Hydra.
	res, err := c.fetchHydra(ctx, rawToken)
	if err != nil {
		return IntrospectionResult{}, err
	}

	// 3. Store negative + positive — TTL bounded by exp.
	// If exp is already in the past we treat the token as inactive and skip
	// caching the (stale) positive result. Defense: an attacker may not race
	// past the introspection result before exp slips by; we re-introspect on
	// next call so Hydra's fresh `active=false` is reflected immediately.
	ttl := c.ttl
	if res.ExpiryAt > 0 {
		untilExp := time.Until(time.Unix(res.ExpiryAt, 0))
		if untilExp <= 0 {
			res.Active = false
			return res, ErrTokenInactive
		}
		if untilExp < ttl {
			ttl = untilExp
		}
	}
	c.put(jti, res, ttl)

	if !res.Active {
		return res, ErrTokenInactive
	}
	return res, nil
}

// Invalidate removes the cached entry for jti. Called by session_revocations
// LISTEN/NOTIFY handler to honor force-logout immediately (≤ 1s SLA).
func (c *IntrospectionCache) Invalidate(jti string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[jti]; ok {
		c.lru.Remove(el)
		delete(c.entries, jti)
	}
}

// Len returns current cache size; used by tests / observability.
func (c *IntrospectionCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

func (c *IntrospectionCache) get(jti string) (IntrospectionResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[jti]
	if !ok {
		return IntrospectionResult{}, false
	}
	entry := el.Value.(*introspectionEntry)
	if c.now().After(entry.expiresAt) {
		c.lru.Remove(el)
		delete(c.entries, jti)
		return IntrospectionResult{}, false
	}
	c.lru.MoveToFront(el)
	return entry.result, true
}

func (c *IntrospectionCache) put(jti string, res IntrospectionResult, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Bounded GC.
	for c.lru.Len() >= c.maxEntries {
		tail := c.lru.Back()
		if tail == nil {
			break
		}
		c.lru.Remove(tail)
		delete(c.entries, tail.Value.(*introspectionEntry).jti)
	}
	entry := &introspectionEntry{
		jti:       jti,
		result:    res,
		expiresAt: c.now().Add(ttl),
	}
	if el, ok := c.entries[jti]; ok {
		el.Value = entry
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(entry)
	c.entries[jti] = el
}

func (c *IntrospectionCache) fetchHydra(ctx context.Context, rawToken string) (IntrospectionResult, error) {
	form := url.Values{}
	form.Set("token", rawToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(form.Encode()))
	if err != nil {
		return IntrospectionResult{}, fmt.Errorf("introspect build req: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.basicUser != "" {
		req.SetBasicAuth(c.basicUser, c.basicPass)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return IntrospectionResult{}, fmt.Errorf("introspect do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return IntrospectionResult{}, fmt.Errorf("introspect status=%d body=%q", resp.StatusCode, string(body))
	}
	var out IntrospectionResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return IntrospectionResult{}, fmt.Errorf("introspect decode: %w", err)
	}
	return out, nil
}
