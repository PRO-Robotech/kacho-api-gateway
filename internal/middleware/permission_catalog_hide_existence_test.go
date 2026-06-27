// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// TestCatalogEntry_HidesExistenceOnDeny pins the resolution rule that drives the
// gateway's read-deny → NotFound behavior:
//   - explicit catalog flag wins;
//   - otherwise: a `/Get` RPC checking `v_get` against a concrete per-resource
//     scope hides existence (the IAM verb-bearing read surface);
//   - mutations, List, and tier/non-v_get reads do NOT hide existence.
func TestCatalogEntry_HidesExistenceOnDeny(t *testing.T) {
	concrete := middleware.ScopeExtractor{ObjectType: "account", FromRequestField: "account_id"}
	wildcard := middleware.ScopeExtractor{ObjectType: "account", FromRequestField: "*"}

	cases := []struct {
		name string
		fqn  string
		e    middleware.CatalogEntry
		want bool
	}{
		{
			name: "iam account Get v_get concrete → hide",
			fqn:  "kacho.cloud.iam.v1.AccountService/Get",
			e:    middleware.CatalogEntry{RequiredRelation: "v_get", ScopeExtractor: concrete},
			want: true,
		},
		{
			name: "iam group Get v_get concrete → hide",
			fqn:  "kacho.cloud.iam.v1.GroupService/Get",
			e:    middleware.CatalogEntry{RequiredRelation: "v_get", ScopeExtractor: middleware.ScopeExtractor{ObjectType: "iam_group", FromRequestField: "group_id"}},
			want: true,
		},
		{
			name: "explicit flag on a mutation still hides (flag wins)",
			fqn:  "kacho.cloud.iam.v1.AccountService/Delete",
			e:    middleware.CatalogEntry{RequiredRelation: "v_delete", ScopeExtractor: concrete, HideExistence: true},
			want: true,
		},
		{
			name: "mutation Delete without flag → no hide (stays 403)",
			fqn:  "kacho.cloud.iam.v1.AccountService/Delete",
			e:    middleware.CatalogEntry{RequiredRelation: "v_delete", ScopeExtractor: concrete},
			want: false,
		},
		{
			name: "List (wildcard scope) → no hide",
			fqn:  "kacho.cloud.iam.v1.AccountService/List",
			e:    middleware.CatalogEntry{RequiredRelation: "v_list", ScopeExtractor: wildcard},
			want: false,
		},
		{
			name: "Get with viewer (non v_get) → no hide",
			fqn:  "kacho.cloud.vpc.v1.NetworkService/Get",
			e:    middleware.CatalogEntry{RequiredRelation: "viewer", ScopeExtractor: middleware.ScopeExtractor{ObjectType: "vpc_network", FromRequestField: "network_id"}},
			want: false,
		},
		{
			name: "Get v_get but wildcard scope → no hide",
			fqn:  "kacho.cloud.iam.v1.AccountService/Get",
			e:    middleware.CatalogEntry{RequiredRelation: "v_get", ScopeExtractor: wildcard},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.e.HidesExistenceOnDeny(tc.fqn))
		})
	}
}
