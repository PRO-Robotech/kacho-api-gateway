package middleware_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestAuthzMetrics_Counters(t *testing.T) {
	m := middleware.NewAuthzMetrics()
	m.RecordAllow()
	m.RecordAllow()
	m.RecordDeny()
	m.RecordError()

	snap := m.Snapshot()
	assert.Equal(t, float64(2), snap[`kacho_api_gateway_authz_check_total{result="allowed"}`])
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_total{result="denied"}`])
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_total{result="error"}`])
}

func TestAuthzMetrics_CacheRatio(t *testing.T) {
	m := middleware.NewAuthzMetrics()
	for i := 0; i < 4; i++ {
		m.RecordCacheHit()
	}
	m.RecordCacheMiss()

	snap := m.Snapshot()
	assert.Equal(t, 0.8, snap["kacho_api_gateway_authz_cache_hit_ratio"])
	assert.Equal(t, 0.8, m.CacheHitRatio())
}

func TestAuthzMetrics_LatencyBuckets(t *testing.T) {
	m := middleware.NewAuthzMetrics()
	// Observations at various ms values.
	m.ObserveLatencyMs(0.5)
	m.ObserveLatencyMs(3)
	m.ObserveLatencyMs(50)
	m.ObserveLatencyMs(2000) // +Inf bucket
	snap := m.Snapshot()

	// LE 1 → counts everything <=1ms → 1 (the 0.5ms observation).
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="1"}`])
	// LE 5 → cumulative <=5ms → 2.
	assert.Equal(t, float64(2), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="5"}`])
	// LE 50 → cumulative <=50ms → 3.
	assert.Equal(t, float64(3), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="50"}`])
	// +Inf → all 4.
	assert.Equal(t, float64(4), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="+Inf"}`])
	// Count.
	assert.Equal(t, float64(4), snap["kacho_api_gateway_authz_check_latency_ms_count"])
}

func TestAuthzMetrics_CustomBuckets(t *testing.T) {
	m := middleware.NewAuthzMetricsWithBuckets([]float64{2, 4, 8})
	m.ObserveLatencyMs(3)
	m.ObserveLatencyMs(7)
	snap := m.Snapshot()
	assert.Equal(t, float64(0), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="2"}`])
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="4"}`])
	assert.Equal(t, float64(2), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="8"}`])
}

func TestAuthzMetrics_CustomBucketsBadInput_FallsBackDefault(t *testing.T) {
	// Non-monotonic input → default buckets used.
	m := middleware.NewAuthzMetricsWithBuckets([]float64{5, 2, 10})
	m.ObserveLatencyMs(1)
	snap := m.Snapshot()
	// Default bucket "1" exists; "2" does not (default has 5, not 2).
	_, hasOne := snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="1"}`]
	_, hasTwo := snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="2"}`]
	assert.True(t, hasOne)
	assert.False(t, hasTwo)
}

func TestAuthzMetrics_ConcurrentSafe(t *testing.T) {
	m := middleware.NewAuthzMetrics()
	const goroutines = 16
	const each = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				m.RecordAllow()
				m.ObserveLatencyMs(float64(i))
			}
		}()
	}
	wg.Wait()
	snap := m.Snapshot()
	assert.Equal(t, float64(goroutines*each), snap[`kacho_api_gateway_authz_check_total{result="allowed"}`])
	assert.Equal(t, float64(goroutines*each), snap["kacho_api_gateway_authz_check_latency_ms_count"])
}

func TestAuthzMetrics_CacheHitRatio_NoData(t *testing.T) {
	m := middleware.NewAuthzMetrics()
	assert.Equal(t, 0.0, m.CacheHitRatio())
}

func TestAuthzMetrics_NegativeLatencyClamped(t *testing.T) {
	m := middleware.NewAuthzMetrics()
	m.ObserveLatencyMs(-5) // clamp to 0
	snap := m.Snapshot()
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_latency_ms_bucket{le="1"}`])
}
