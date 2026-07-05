// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_cache.go — the per-RPC authz decision cache and its cache-key builder.
//
// Extracted from authz.go (which had grown to a 1200+-line god-file mixing
// interceptors, the decision engine and the cache). The eviction/TTL/LRU
// mechanics now live in the shared internal/lrucache primitive; this file only
// carries the authz-specific policy: the cached decision shape, the
// subject-prefix invalidation used by session-revocation pushes, the
// write-after-invalidate epoch guard wiring, and the deterministic cache key.
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/lrucache"
)

// decisionCacheEntry — cached outcome.
type decisionCacheEntry struct {
	allowed bool
	reasons []string
}

// decisionCache — LRU-with-TTL over the shared lrucache primitive, plus the
// authz-specific subject-prefix invalidation. Safe for concurrent use.
type decisionCache struct {
	c *lrucache.Cache[string, decisionCacheEntry]
}

func newDecisionCache(maxSize int, ttl time.Duration, now func() time.Time) *decisionCache {
	return &decisionCache{c: lrucache.New[string, decisionCacheEntry](maxSize, ttl, now)}
}

func (c *decisionCache) get(key string) (decisionCacheEntry, bool) { return c.c.Get(key) }

func (c *decisionCache) put(key string, v decisionCacheEntry) { c.c.Put(key, v) }

// generation snapshots the invalidation generation for the epoch guard; see
// putIfGen.
func (c *decisionCache) generation() uint64 { return c.c.Generation() }

// putIfGen stores v only when the cache generation still equals the snapshot the
// caller captured at get()-miss time. If an Invalidate/InvalidateSubject ran in
// between, the (potentially stale, pre-revocation) write is discarded — closing
// the write-after-invalidate race where a Check computed against a pre-revocation
// grant would otherwise re-populate a just-flushed allow=true entry and survive
// for the whole TTL (CWE-362 + CWE-613; project-rule #10).
func (c *decisionCache) putIfGen(key string, v decisionCacheEntry, gen uint64) {
	c.c.PutIfGen(key, v, gen)
}

// Invalidate removes ALL cache entries — used by the LISTEN/NOTIFY
// session_revocations push safety-net. Bumps the generation.
func (c *decisionCache) Invalidate() { c.c.Invalidate() }

// InvalidateSubject removes cache entries for the given FGA subject prefix
// ("user:usr_abc"). Subject is matched verbatim against the key prefix used at
// insert time. Bumps the generation so an in-flight Check for this subject that
// snapshotted the pre-revocation generation has its putIfGen dropped even when
// zero entries currently match.
func (c *decisionCache) InvalidateSubject(subject string) int {
	if subject == "" {
		return 0
	}
	prefix := subject + "|"
	return c.c.InvalidateWhere(func(key string) bool {
		return strings.HasPrefix(key, prefix)
	})
}

// Size returns the number of live cache entries.
func (c *decisionCache) Size() int { return c.c.Len() }

// buildCacheKey — stable cache key over (subject, action, resource,
// principal-binding context). Including `acr`/`mfa_at`/`client_ip` ensures
// step-up changes invalidate naturally; excluding `current_time`/`jti`
// avoids per-request cache busts.
func buildCacheKey(subject, action, resourceType, resourceID string, contextMap map[string]any) string {
	// Use a canonical concatenation of the security-affecting context keys
	// so equivalent contexts collide cleanly. We pick a subset to keep keys
	// reasonable in length; full-context-hash would change on harmless
	// fields and obliterate the cache.
	parts := []string{subject, action, resourceType, resourceID}
	if contextMap != nil {
		keys := []string{"acr_value", "mfa_at", "client_ip", "device_id", "passkey_aaguid"}
		sort.Strings(keys) // deterministic
		for _, k := range keys {
			if v, ok := contextMap[k]; ok {
				parts = append(parts, k+"="+fmt.Sprint(v))
			}
		}
	}
	raw := strings.Join(parts, "|")
	// Compress with sha256 for stable length (the cache map handles
	// collisions naturally — sha256 collision probability is negligible).
	sum := sha256.Sum256([]byte(raw))
	// Encode prefix + subject-prefix so InvalidateSubject can match.
	// Format: "<subject>|<sha256-hex>".
	return subject + "|" + hex.EncodeToString(sum[:])
}
