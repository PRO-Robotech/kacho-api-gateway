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
// tenant-facing public ресурс vpc. Embedded-каталог обязан нести его RPC с
// verb-bearing relations (v_get/v_list/v_update/v_delete; create — editor на
// project-scope), иначе authz отдаст "catalog: no entry for method" (deny) и
// публичные методы не пройдут через gateway. Ни один из них не <exempt> —
// доступ всегда проверяется через FGA. Двойное "es" в `...poolses.list` —
// артефакт генератора (как `regionses`/`zoneses`), часть контракта каталога.
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
		{"kacho.cloud.vpc.v1.AnycastAddressPoolService/List", "vpc.anycast_address_poolses.list", "v_list", "project", "project_id"},
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
			assert.False(t, entry.IsExempt(), "anycast RPC must NOT be <exempt> on %s", w.fqn)
		})
	}
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
