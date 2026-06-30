// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestPermissionCatalog_Anycast_PublicVerbBearing — AnycastAddressPool —
// tenant-facing public ресурс vpc. Object-self RPC (Get/Update/Delete/
// AttachNetwork/DetachNetwork) несут verb-bearing relations на самом пуле;
// Create — editor на parent project. List — scope-filtered <exempt> (как
// NetworkService/List): единый per-RPC Check на project отклонил бы весь вызов
// `no path` 403 ещё до handler-фильтра viewer ∪ v_list, поэтому gateway его
// освобождает (authn остаётся — валидный JWT обязателен).
func TestPermissionCatalog_Anycast_PublicVerbBearing(t *testing.T) {
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	want := []struct {
		fqn        string
		perm       string
		relation   string
		objectType string
		fromField  string
	}{
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/Get", "vpc.anycast_address_pools.get", "v_get", "vpc_anycast_address_pool", "anycast_address_pool_id"},
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/Create", "vpc.anycast_address_pools.create", "editor", "project", "project_id"},
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/Update", "vpc.anycast_address_pools.update", "v_update", "vpc_anycast_address_pool", "anycast_address_pool_id"},
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/Delete", "vpc.anycast_address_pools.delete", "v_delete", "vpc_anycast_address_pool", "anycast_address_pool_id"},
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/AttachNetwork", "vpc.anycast_address_pools.attachNetwork", "v_update", "vpc_anycast_address_pool", "anycast_address_pool_id"},
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/DetachNetwork", "vpc.anycast_address_pools.detachNetwork", "v_update", "vpc_anycast_address_pool", "anycast_address_pool_id"},
	}
	for _, w := range want {
		t.Run(w.fqn, func(t *testing.T) {
			entry, ok := c.Lookup(w.fqn)
			require.True(t, ok, "fqn missing from embedded catalog: %s", w.fqn)
			assert.Equal(t, w.perm, entry.Permission, "permission identifier on %s", w.fqn)
			assert.Equal(t, w.relation, entry.RequiredRelation, "required_relation on %s", w.fqn)
			assert.Equal(t, w.objectType, entry.ScopeExtractor.ObjectType, "scope object_type on %s", w.fqn)
			assert.Equal(t, w.fromField, entry.ScopeExtractor.FromRequestField, "scope from_request_field on %s", w.fqn)
			assert.False(t, entry.IsExempt(), "anycast object-self RPC must NOT be <exempt> on %s", w.fqn)
		})
	}

	// List — scope-filtered: handler возвращает viewer ∪ v_list-набор; gateway
	// освобождает RPC от per-RPC Check (parity с NetworkService/List), иначе
	// project-scope Check отклонил бы owner'а без отдельного v_list-tuple.
	t.Run("List is scope-filtered <exempt>", func(t *testing.T) {
		entry, ok := c.Lookup("kacho.cloud.vpc.v1.AnycastAddressPoolService/List")
		require.True(t, ok, "List missing from embedded catalog")
		assert.True(t, entry.IsExempt(), "anycast List must be <exempt> (scope-filtered)")
	})
}

// TestRestRouter_Anycast_PathFQN — REST-таблица обязана резолвить публичные
// anycast-пути в правильные gRPC-FQN; без этого authz-middleware не сопоставит
// запрос с записью каталога и каждый REST-вызов будет отклонен.
func TestRestRouter_Anycast_PathFQN(t *testing.T) {
	r := middleware.NewRestRouter()

	cases := []struct {
		method, path, fqn string
	}{
		{"GET", "/vpc/v1/anycastAddressPools", "kacho.cloud.vpc.v1.AnycastAddressPoolService/List"},
		{"POST", "/vpc/v1/anycastAddressPools", "kacho.cloud.vpc.v1.AnycastAddressPoolService/Create"},
		{"GET", "/vpc/v1/anycastAddressPools/anp-1", "kacho.cloud.vpc.v1.AnycastAddressPoolService/Get"},
		{"PATCH", "/vpc/v1/anycastAddressPools/anp-1", "kacho.cloud.vpc.v1.AnycastAddressPoolService/Update"},
		{"DELETE", "/vpc/v1/anycastAddressPools/anp-1", "kacho.cloud.vpc.v1.AnycastAddressPoolService/Delete"},
		{"POST", "/vpc/v1/anycastAddressPools/anp-1:attachNetwork", "kacho.cloud.vpc.v1.AnycastAddressPoolService/AttachNetwork"},
		{"POST", "/vpc/v1/anycastAddressPools/anp-1:detachNetwork", "kacho.cloud.vpc.v1.AnycastAddressPoolService/DetachNetwork"},
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
