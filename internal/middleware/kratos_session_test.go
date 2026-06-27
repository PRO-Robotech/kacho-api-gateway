// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"strconv"
	"testing"
	"time"
)

// TestKratosClient_CacheBounded proves the whoami cache never grows past its
// hard cap even when fed a flood of unique (attacker-controlled) cookie keys
// within the TTL window — TTL-only eviction would otherwise grow unbounded.
func TestKratosClient_CacheBounded(t *testing.T) {
	c := NewKratosClient("http://kratos.local")
	c.maxEntries = 64

	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 1000; i++ {
		c.posCache["cookie-"+strconv.Itoa(i)] = kratosCacheEntry{
			res:    KratosWhoamiResult{Active: true},
			expiry: time.Now().Add(time.Hour), // not expired → TTL sweep cannot free
		}
		c.enforceCapLocked()
	}
	if total := len(c.posCache) + len(c.negCache); total > c.maxEntries {
		t.Fatalf("kratos cache grew to %d, cap %d", total, c.maxEntries)
	}
}
