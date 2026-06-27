// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_metrics.go — lightweight in-process counters & histograms for the
// authz middleware.
//
// The api-gateway already exposes a Prometheus textfile by scraping a small set
// of process-level counters. We add three families:
//
//	kacho_api_gateway_authz_check_total{result="allowed|denied|error"}
//	kacho_api_gateway_authz_check_latency_ms (histogram, fixed buckets)
//	kacho_api_gateway_authz_cache_hit_total / authz_cache_miss_total
//
// Implementation: atomic-counter-only (no Prometheus client dependency to
// stay lean — the gateway does its own /metrics rendering elsewhere; this
// type's Snapshot() returns a printable map that the textfile handler can
// fold in. Adding a real prometheus.Client wrapper is a no-op switch when
// the gateway adopts one).
package middleware

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

// AuthzMetrics — atomic counters + bucket histogram, safe for concurrent use.
type AuthzMetrics struct {
	allowedTotal atomic.Int64
	deniedTotal  atomic.Int64
	errorTotal   atomic.Int64

	cacheHitTotal  atomic.Int64
	cacheMissTotal atomic.Int64

	// Latency histogram buckets (ms). Defined once at construction time so
	// Snapshot() doesn't re-sort every call.
	latencyMu      sync.Mutex
	latencyBuckets []float64 // upper bounds, ascending
	latencyCounts  []int64   // counts per bucket (last bucket = +Inf)
	latencySum     float64   // running sum (ms) for average
	latencyCount   int64     // total observations
}

// NewAuthzMetrics constructs a metrics container with default latency
// buckets matching the spec ([1,5,10,20,50,100,200,500,1000] ms).
func NewAuthzMetrics() *AuthzMetrics {
	buckets := []float64{1, 5, 10, 20, 50, 100, 200, 500, 1000}
	return &AuthzMetrics{
		latencyBuckets: buckets,
		latencyCounts:  make([]int64, len(buckets)+1),
	}
}

// NewAuthzMetricsWithBuckets allows operators to override bucket bounds.
// Buckets must be ascending and positive; non-conforming input falls back
// to the default.
func NewAuthzMetricsWithBuckets(buckets []float64) *AuthzMetrics {
	if !ascendingPositive(buckets) {
		return NewAuthzMetrics()
	}
	cp := make([]float64, len(buckets))
	copy(cp, buckets)
	return &AuthzMetrics{
		latencyBuckets: cp,
		latencyCounts:  make([]int64, len(cp)+1),
	}
}

// RecordAllow increments the allowed counter.
func (m *AuthzMetrics) RecordAllow() { m.allowedTotal.Add(1) }

// RecordDeny increments the denied counter.
func (m *AuthzMetrics) RecordDeny() { m.deniedTotal.Add(1) }

// RecordError increments the error counter (Check call failed — Unavailable
// / Timeout / parser-failure / etc.).
func (m *AuthzMetrics) RecordError() { m.errorTotal.Add(1) }

// RecordCacheHit / RecordCacheMiss — decision cache.
func (m *AuthzMetrics) RecordCacheHit()  { m.cacheHitTotal.Add(1) }
func (m *AuthzMetrics) RecordCacheMiss() { m.cacheMissTotal.Add(1) }

// ObserveLatencyMs adds a latency sample to the histogram.
func (m *AuthzMetrics) ObserveLatencyMs(ms float64) {
	if ms < 0 {
		ms = 0
	}
	m.latencyMu.Lock()
	defer m.latencyMu.Unlock()
	// Find first bucket whose upper bound >= ms.
	idx := sort.SearchFloat64s(m.latencyBuckets, ms)
	if idx < len(m.latencyBuckets) {
		m.latencyCounts[idx]++
	} else {
		m.latencyCounts[len(m.latencyBuckets)]++
	}
	m.latencySum += ms
	m.latencyCount++
}

// Snapshot returns a copy of the current counter state suitable for direct
// emission via a /metrics handler. Keys are pre-rendered Prometheus
// metric-name+labels strings.
func (m *AuthzMetrics) Snapshot() map[string]float64 {
	allowed := m.allowedTotal.Load()
	denied := m.deniedTotal.Load()
	errors := m.errorTotal.Load()
	hits := m.cacheHitTotal.Load()
	miss := m.cacheMissTotal.Load()

	out := map[string]float64{
		`kacho_api_gateway_authz_check_total{result="allowed"}`: float64(allowed),
		`kacho_api_gateway_authz_check_total{result="denied"}`:  float64(denied),
		`kacho_api_gateway_authz_check_total{result="error"}`:   float64(errors),
		`kacho_api_gateway_authz_cache_total{result="hit"}`:     float64(hits),
		`kacho_api_gateway_authz_cache_total{result="miss"}`:    float64(miss),
	}
	if total := hits + miss; total > 0 {
		out["kacho_api_gateway_authz_cache_hit_ratio"] = float64(hits) / float64(total)
	}

	m.latencyMu.Lock()
	for i, ub := range m.latencyBuckets {
		// Cumulative bucket count (LE semantics).
		var le int64
		for j := 0; j <= i; j++ {
			le += m.latencyCounts[j]
		}
		out[`kacho_api_gateway_authz_check_latency_ms_bucket{le="`+formatBucket(ub)+`"}`] = float64(le)
	}
	// +Inf bucket.
	var infTotal int64
	for _, c := range m.latencyCounts {
		infTotal += c
	}
	out[`kacho_api_gateway_authz_check_latency_ms_bucket{le="+Inf"}`] = float64(infTotal)
	out[`kacho_api_gateway_authz_check_latency_ms_sum`] = m.latencySum
	out[`kacho_api_gateway_authz_check_latency_ms_count`] = float64(m.latencyCount)
	m.latencyMu.Unlock()

	return out
}

// CacheHitRatio returns the live hit/(hit+miss) ratio; 0 when no
// observations.
func (m *AuthzMetrics) CacheHitRatio() float64 {
	h := m.cacheHitTotal.Load()
	mm := m.cacheMissTotal.Load()
	if h+mm == 0 {
		return 0
	}
	return float64(h) / float64(h+mm)
}

// ascendingPositive returns true when buckets are strictly increasing and
// positive.
func ascendingPositive(b []float64) bool {
	if len(b) == 0 {
		return false
	}
	prev := -1.0
	for _, v := range b {
		if v <= prev || v <= 0 {
			return false
		}
		prev = v
	}
	return true
}

// formatBucket renders a float bucket bound to a canonical Prometheus
// label-value string (no trailing zeros, integer when whole).
func formatBucket(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
