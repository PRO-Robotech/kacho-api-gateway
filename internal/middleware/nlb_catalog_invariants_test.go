// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// Инварианты authz-доступа к ресурсам kacho-nlb на gateway-стороне (embedded
// permission catalog). Закрывают тот же класс ошибок ролевок, что вскрыл anycast
// pool: пропущенный RPC в каталоге (→ deny), неверный enforcement-relation, и —
// главное — top-level project-List с per-RPC call-gate (`v_list`), который
// отклоняет легитимного viewer'а без отдельного v_list-tuple `no path` 403 ещё до
// handler-фильтра (ListObjects `viewer ∪ v_list`). Source of truth поверхности —
// gRPC-сервисы loadbalancer.v1 (NetworkLoadBalancer / Listener / TargetGroup).

// nlbTopListRPCs — top-level project-scoped List. Handler фильтрует результат
// через iam ListObjects (per-object), поэтому gateway ОБЯЗАН освобождать их от
// per-RPC Check (`<exempt>`) — иначе project-scope Check отклонит viewer'а целиком.
var nlbTopListRPCs = []string{
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
	"kacho.cloud.loadbalancer.v1.ListenerService/List",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/List",
}

// nlbObjectSelfVGet — object-self read: Check `v_get` на самом ресурсе.
var nlbObjectSelfVGet = map[string]string{
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get":             "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/GetTargetStates": "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.ListenerService/Get":                        "lb_listener",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/Get":                     "lb_target_group",
}

// nlbObjectSelfVUpdate — object-self mutation (Update + domain-verbs): Check `v_update`.
var nlbObjectSelfVUpdate = map[string]string{
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Update":            "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Start":             "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Stop":              "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Move":              "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/AttachTargetGroup": "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/DetachTargetGroup": "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.ListenerService/Update":                       "lb_listener",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/Update":                    "lb_target_group",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/Move":                      "lb_target_group",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/AddTargets":                "lb_target_group",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/RemoveTargets":             "lb_target_group",
}

// nlbObjectSelfVDelete — object-self delete: Check `v_delete`.
var nlbObjectSelfVDelete = map[string]string{
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Delete": "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.ListenerService/Delete":            "lb_listener",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/Delete":         "lb_target_group",
}

// nlbCreateRPCs — parent-scoped Create: tier `editor` на parent (project для
// NLB/TG, parent LB для Listener; create-authority = write-authz на parent, F-7).
var nlbCreateRPCs = map[string]string{
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create": "project",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/Create":         "project",
	"kacho.cloud.loadbalancer.v1.ListenerService/Create":            "lb_network_load_balancer",
}

// nlbListOnResourceRPCs — object-self list-on-resource (операции ресурса): `v_list`
// на самом ресурсе (НЕ top-level project-List).
var nlbListOnResourceRPCs = map[string]string{
	"kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/ListOperations": "lb_network_load_balancer",
	"kacho.cloud.loadbalancer.v1.ListenerService/ListOperations":            "lb_listener",
	"kacho.cloud.loadbalancer.v1.TargetGroupService/ListOperations":         "lb_target_group",
}

func nlbCatalog(t *testing.T) *middleware.PermissionCatalog {
	t.Helper()
	c, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)
	return c
}

// TestNLBCatalog_AllPublicRPCsPresent — каждый публичный nlb-RPC присутствует в
// каталоге (пропуск → authz «no entry for method» deny, как было у anycast).
func TestNLBCatalog_AllPublicRPCsPresent(t *testing.T) {
	c := nlbCatalog(t)
	all := append([]string{}, nlbTopListRPCs...)
	for fqn := range nlbObjectSelfVGet {
		all = append(all, fqn)
	}
	for fqn := range nlbObjectSelfVUpdate {
		all = append(all, fqn)
	}
	for fqn := range nlbObjectSelfVDelete {
		all = append(all, fqn)
	}
	for fqn := range nlbCreateRPCs {
		all = append(all, fqn)
	}
	for fqn := range nlbListOnResourceRPCs {
		all = append(all, fqn)
	}
	for _, fqn := range all {
		_, ok := c.Lookup(fqn)
		require.Truef(t, ok, "nlb RPC missing from embedded catalog: %s", fqn)
	}
}

// TestNLBCatalog_TopListExempt — top-level project-List ДОЛЖЕН быть <exempt>:
// handler фильтрует через ListObjects, gateway-call-gate отклонил бы viewer'а без
// отдельного v_list-tuple (баг класса #255 / anycast).
func TestNLBCatalog_TopListExempt(t *testing.T) {
	c := nlbCatalog(t)
	for _, fqn := range nlbTopListRPCs {
		entry, ok := c.Lookup(fqn)
		require.Truef(t, ok, "%s missing from catalog", fqn)
		assert.Truef(t, entry.IsExempt(),
			"%s: top-level project List must be <exempt> (handler filters via ListObjects); a v_list "+
				"call-gate rejects a viewer without an explicit v_list tuple", fqn)
	}
}

// TestNLBCatalog_ObjectSelf_VerbBearing — Get→v_get, mutate→v_update, delete→v_delete
// на object-scope самого ресурса (Design-B: enforcement по verb, не tier).
func TestNLBCatalog_ObjectSelf_VerbBearing(t *testing.T) {
	c := nlbCatalog(t)
	check := func(set map[string]string, wantRel string) {
		for fqn, wantObj := range set {
			entry, ok := c.Lookup(fqn)
			require.Truef(t, ok, "%s missing from catalog", fqn)
			assert.Equalf(t, wantRel, entry.RequiredRelation, "%s: required_relation", fqn)
			assert.Equalf(t, wantObj, entry.ScopeExtractor.ObjectType, "%s: scope object_type", fqn)
			assert.Falsef(t, entry.IsExempt(), "%s: object-self RPC must NOT be <exempt>", fqn)
		}
	}
	check(nlbObjectSelfVGet, "v_get")
	check(nlbObjectSelfVUpdate, "v_update")
	check(nlbObjectSelfVDelete, "v_delete")
	check(nlbListOnResourceRPCs, "v_list")
}

// TestNLBCatalog_Create_Editor — Create — tier editor на parent scope.
func TestNLBCatalog_Create_Editor(t *testing.T) {
	c := nlbCatalog(t)
	for fqn, wantObj := range nlbCreateRPCs {
		entry, ok := c.Lookup(fqn)
		require.Truef(t, ok, "%s missing from catalog", fqn)
		assert.Equalf(t, "editor", entry.RequiredRelation, "%s: Create stays tier editor on parent (F-7)", fqn)
		assert.Equalf(t, wantObj, entry.ScopeExtractor.ObjectType, "%s: Create scope object_type", fqn)
	}
}
