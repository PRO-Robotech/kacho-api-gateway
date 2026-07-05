// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package cache — in-process cache helpers для api-gateway.
// subject_cache.go — LRU-bounded + TTL cache для subject-резолва, поверх общего
// internal/lrucache примитива (единая протестированная eviction/TTL-логика).
package cache

import (
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/lrucache"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

type SubjectCache struct {
	c *lrucache.Cache[string, middleware.Subject]
}

// NewSubjectCache constructs the cache. `now` is the injectable time source
// (tests step a mock clock past the TTL instead of sleeping on the wall clock);
// production callers pass nil and get time.Now — mirroring lrucache.New and the
// sibling cache constructors (introspection, dpop-replay).
func NewSubjectCache(maxSize int, ttl time.Duration, now func() time.Time) *SubjectCache {
	if maxSize <= 0 {
		maxSize = 10_000
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &SubjectCache{c: lrucache.New[string, middleware.Subject](maxSize, ttl, now)}
}

func (c *SubjectCache) Get(key string) (middleware.Subject, bool) { return c.c.Get(key) }

func (c *SubjectCache) Set(key string, v middleware.Subject) { c.c.Put(key, v) }

func (c *SubjectCache) Invalidate(key string) { c.c.InvalidateKey(key) }

func (c *SubjectCache) InvalidateAll() { c.c.Invalidate() }

func (c *SubjectCache) Len() int { return c.c.Len() }
