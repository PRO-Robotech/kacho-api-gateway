// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package proxy_test

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

func makeTestBackends(t *testing.T, domains []string) proxy.Backends {
	t.Helper()
	backends := make(proxy.Backends, len(domains))
	for _, d := range domains {
		conn, err := grpc.NewClient("localhost:1",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			t.Fatalf("NewClient для %s: %v", d, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		backends[d] = conn
	}
	return backends
}

// Маршрутизация Account/Project на iam-backend; публичная мутация
// UserService.Update — тоже iam (allowlist пропускает; HasInternalSuffix не ловит).
func TestResolver_RoutesToIAM(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	resolve := proxy.Resolver(backends)

	for _, m := range []string{
		"/kacho.cloud.iam.v1.AccountService/List",
		"/kacho.cloud.iam.v1.UserService/Update",
	} {
		_, conn, ok := resolve(m)
		if !ok {
			t.Fatalf("ожидали резолв для %q", m)
		}
		if conn != backends["iam"] {
			t.Errorf("метод %q должен резолвиться на iam-backend", m)
		}
	}
}

// Маршрутизация на vpc-backend.
func TestResolver_RoutesToVPC(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	resolve := proxy.Resolver(backends)

	_, conn, ok := resolve("/kacho.cloud.vpc.v1.NetworkService/List")
	if !ok || conn != backends["vpc"] {
		t.Errorf("NetworkService.List должен резолвиться на vpc-backend (ok=%v)", ok)
	}
}

// Unknown domain → не резолвится (deny-by-default).
func TestResolver_UnknownDomainNotResolved(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	resolve := proxy.Resolver(backends)

	if _, _, ok := resolve("/kacho.cloud.unknown.v1.FooService/Bar"); ok {
		t.Fatal("unknown-domain метод не должен резолвиться")
	}
}

// Удаленные resourcemanager/organizationmanager методы → не резолвятся.
func TestResolver_RemovedResourceManagerBlocked(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	resolve := proxy.Resolver(backends)
	for _, m := range []string{
		"/kacho.cloud.resourcemanager.v1.CloudService/List",
		"/kacho.cloud.resourcemanager.v1.FolderService/Get",
		"/kacho.cloud.organizationmanager.v1.OrganizationService/List",
	} {
		if _, _, ok := resolve(m); ok {
			t.Errorf("удаленный метод %q не должен резолвиться", m)
		}
	}
}

// Публичные loadbalancer-RPC резолвятся на loadbalancer-backend; Internal* — нет.
func TestResolver_LoadbalancerPublicVsInternal(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute", "loadbalancer"})
	resolve := proxy.Resolver(backends)

	for _, m := range []string{
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create",
		"/kacho.cloud.loadbalancer.v1.ListenerService/Create",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/AddTargets",
	} {
		_, conn, ok := resolve(m)
		if !ok || conn != backends["loadbalancer"] {
			t.Errorf("public nlb-метод %q должен резолвиться на loadbalancer (ok=%v)", m, ok)
		}
	}
	if _, _, ok := resolve("/kacho.cloud.loadbalancer.v1.InternalResourceLifecycleService/Subscribe"); ok {
		t.Error("Internal nlb-метод не должен резолвиться (HasInternalSuffix)")
	}
}

// Публичные compute-RPC резолвятся на compute-backend; Internal* — нет.
func TestResolver_ComputePublicVsInternal(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute"})
	resolve := proxy.Resolver(backends)

	if _, conn, ok := resolve("/kacho.cloud.compute.v1.InstanceService/Get"); !ok || conn != backends["compute"] {
		t.Errorf("InstanceService.Get должен резолвиться на compute (ok=%v)", ok)
	}
	for _, m := range []string{
		"/kacho.cloud.compute.v1.InternalDiskTypeService/Create",
		"/kacho.cloud.compute.v1.InternalWatchService/Watch",
	} {
		if _, _, ok := resolve(m); ok {
			t.Errorf("Internal compute-метод %q не должен резолвиться", m)
		}
	}
}

// Любой InternalService-метод блокируется HasInternalSuffix.
func TestResolver_BlocksInternalService(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	resolve := proxy.Resolver(backends)
	for _, m := range []string{
		"/kacho.cloud.vpc.v1.NetworkInternalService/Exists",
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
	} {
		if _, _, ok := resolve(m); ok {
			t.Errorf("Internal метод %q должен быть заблокирован", m)
		}
	}
}

// Malformed method path → не резолвится.
func TestResolver_MalformedPathNotResolved(t *testing.T) {
	backends := makeTestBackends(t, []string{"vpc"})
	resolve := proxy.Resolver(backends)
	if _, _, ok := resolve("//BadPath"); ok {
		t.Error("malformed path не должен резолвиться")
	}
}
