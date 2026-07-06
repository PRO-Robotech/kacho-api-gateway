// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"strconv"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/lrucache"
)

// TestKratosClient_CacheBounded proves the whoami cache never grows past its
// hard cap even when fed a flood of unique (attacker-controlled) cookie keys
// within the TTL window — TTL-only eviction would otherwise grow unbounded. The
// bound is now enforced by the shared internal/lrucache primitive the client
// wires; this test pins that the client stays bounded under a key flood.
func TestKratosClient_CacheBounded(t *testing.T) {
	const cap = 64
	c := NewKratosClient("http://kratos.local")
	c.cache = lrucache.New[string, kratosCacheEntry](cap, time.Hour, nil)

	for i := 0; i < 1000; i++ {
		c.cache.PutWithTTL(
			"cookie-"+strconv.Itoa(i),
			kratosCacheEntry{res: KratosWhoamiResult{Active: true}, active: true},
			time.Hour, // not expired → TTL sweep cannot free; only the cap can
		)
	}
	if total := c.cache.Len(); total > cap {
		t.Fatalf("kratos cache grew to %d, cap %d", total, cap)
	}
}
