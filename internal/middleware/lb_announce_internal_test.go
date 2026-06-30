// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestPermissionCatalog_LBAnnounce_InternalExempt — InternalLoadBalancerAnnounceService
// (announce-state, инфра-данные placement/underlay) — cluster-internal Internal*-сервис.
// Каталог обязан нести его RPC как <exempt> (как InternalResourceLifecycleService):
// gateway на internal listener пропускает через internal-origin gate, а authz-Check
// энфорсит backend kacho-nlb на :9091. Никакого verb-bearing relation (инвариант:
// Internal*-RPC не несут v_*).
func TestPermissionCatalog_LBAnnounce_InternalExempt(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	fqns := []string{
		"kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/GetAnnounceState",
		"kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/ReportAnnounceState",
	}
	for _, fqn := range fqns {
		t.Run(fqn, func(t *testing.T) {
			entry, ok := c.Lookup(fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", fqn)
			assert.True(t, entry.IsExempt(), "announce RPC must be <exempt> (internal-origin gate): %s", fqn)
			assert.Empty(t, entry.RequiredRelation, "announce RPC must carry no verb-bearing relation: %s", fqn)
		})
	}
}

// TestRestRouter_LBAnnounce_PathFQN — REST-таблица обязана резолвить gRPC-style
// unbound-method пути announce-сервиса в их gRPC-FQN. Без этого resolveRestFQN
// упал бы в grpcMethodForPath, дал бы искаженный FQN и каталог не нашелся бы →
// authz отбил бы "catalog: no entry for method" даже на internal listener.
func TestRestRouter_LBAnnounce_PathFQN(t *testing.T) {
	r := middleware.NewRestRouter()

	cases := []struct {
		method, path, fqn string
	}{
		{"POST", "/kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/GetAnnounceState", "kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/GetAnnounceState"},
		{"POST", "/kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/ReportAnnounceState", "kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/ReportAnnounceState"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got, ok := r.Resolve(tc.method, tc.path)
			require.True(t, ok, "no route for %s %s", tc.method, tc.path)
			assert.Equal(t, tc.fqn, got)
		})
	}
}
