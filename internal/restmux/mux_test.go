// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package restmux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsInternalPath покрывает path-based dispatch правил для split-mux.
//
// Логика: любой путь, который relates к admin/internal-поверхности
// (internal-проекции, AddressPool, admin-bindings) → internal sub-mux
// (EmitUnpopulated=false); все остальное (tenant-facing public контракт
// Network/Subnet/Address/NIC/SG/RT/Gateway/PE/Instance/Disk/...) → public sub-mux
// (EmitUnpopulated=true).
func TestIsInternalPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		// --- (1) /internal segment anywhere ---
		{
			name: "internal suffix on network",
			path: "/vpc/v1/networks/net-123/internal",
			want: true,
		},
		{
			name: "internal suffix on networkInterface",
			path: "/vpc/v1/networkInterfaces/nic-456/internal",
			want: true,
		},
		{
			name: "internal mid-path (hypothetical)",
			path: "/vpc/v1/networks/internal/foo",
			want: true,
		},
		{
			name: "does not match path containing internalX",
			path: "/vpc/v1/networks/internalstuff",
			want: false,
		},

		// --- (2) /vpc/v1/addressPools[/...] ---
		// AddressPool exposes no Check / ExplainResolution RPCs.
		{
			name: "addressPools root",
			path: "/vpc/v1/addressPools",
			want: true,
		},
		{
			name: "addressPools by id",
			path: "/vpc/v1/addressPools/ap-abc",
			want: true,
		},
		// AddCidrBlocks / RemoveCidrBlocks suffix-actions on a pool.
		{
			name: "addressPools addCidrBlocks (internal)",
			path: "/vpc/v1/addressPools/ap-abc:addCidrBlocks",
			want: true,
		},
		{
			name: "addressPools removeCidrBlocks (internal)",
			path: "/vpc/v1/addressPools/ap-abc:removeCidrBlocks",
			want: true,
		},

		// --- (3) /vpc/v1/networks/{id}/addressPoolBinding ---
		{
			name: "network addressPoolBinding",
			path: "/vpc/v1/networks/net-1/addressPoolBinding",
			want: true,
		},
		// regular networks must stay public
		{
			name: "network list (public)",
			path: "/vpc/v1/networks",
			want: false,
		},
		{
			name: "network get by id (public)",
			path: "/vpc/v1/networks/net-1",
			want: false,
		},

		// Addresses and clouds expose no internal-path rules — they stay fully public.
		{
			name: "address get by id (public)",
			path: "/vpc/v1/addresses/addr-1",
			want: false,
		},
		// AnycastAddressPool — tenant-facing public ресурс. Имя похоже на admin
		// addressPools, но это другой сегмент: addressPools-правило матчит только
		// точный "addressPools" / "addressPools/" / "addressPools:", поэтому
		// anycastAddressPools остается на public mux.
		{
			name: "anycastAddressPools list (public)",
			path: "/vpc/v1/anycastAddressPools",
			want: false,
		},
		{
			name: "anycastAddressPools by id (public)",
			path: "/vpc/v1/anycastAddressPools/anp-1",
			want: false,
		},
		{
			name: "anycastAddressPools attachNetwork (public)",
			path: "/vpc/v1/anycastAddressPools/anp-1:attachNetwork",
			want: false,
		},

		// --- (4) gRPC-style unbound-method REST paths of Internal*-сервисов ---
		// InternalLoadBalancerAnnounceService (announce-state) — REST форма
		// `/kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/<Method>`.
		// HasInternalSuffix распознает `Internal<Xxx>Service` → internal mux.
		{
			name: "announce GetAnnounceState (internal)",
			path: "/kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/GetAnnounceState",
			want: true,
		},
		{
			name: "announce ReportAnnounceState (internal)",
			path: "/kacho.cloud.loadbalancer.v1.InternalLoadBalancerAnnounceService/ReportAnnounceState",
			want: true,
		},
		// Публичный gRPC-style сервис (без Internal-префикса) НЕ должен попасть на
		// internal mux — guard, что правило (4) ловит только Internal*-сервисы.
		{
			name: "public grpc-style service stays public",
			path: "/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Get",
			want: false,
		},

		// --- public surfaces (must NOT go to internal) ---
		{
			name: "instance list (public)",
			path: "/compute/v1/instances",
			want: false,
		},
		{
			name: "disk get (public)",
			path: "/compute/v1/disks/disk-1",
			want: false,
		},
		{
			name: "subnet list (public)",
			path: "/vpc/v1/subnets",
			want: false,
		},
		{
			name: "project get (public) — /iam/v1/projects",
			path: "/iam/v1/projects/prj-1",
			want: false,
		},
		{
			name: "operation get (public)",
			path: "/operations/op-1",
			want: false,
		},
		{
			name: "root health-like",
			path: "/healthz",
			want: false,
		},

		// --- InternalClusterService — cluster-admin RBAC under
		// /iam/v1/internal/cluster/...  All four RPCs (Get/GrantAdmin/RevokeAdmin/
		// ListAdmins) must be classified as internal so the path-based dispatcher
		// routes them to the internal sub-mux (which is what the cluster-internal
		// REST listener exposes). External TLS endpoint must NEVER serve these
		// paths (Internal.* не публикуются на external endpoint).
		{
			name: "iam internal cluster Get",
			path: "/iam/v1/internal/cluster",
			want: true,
		},
		{
			name: "iam internal cluster GrantAdmin / ListAdmins (POST/GET collection)",
			path: "/iam/v1/internal/cluster/admins",
			want: true,
		},
		{
			name: "iam internal cluster RevokeAdmin (DELETE by subject id)",
			path: "/iam/v1/internal/cluster/admins/usr_abc",
			want: true,
		},

		// --- kacho-nlb /nlb/v1/* — все public (никаких /internal сегментов
		// и admin-bindings в proto). InternalResourceLifecycleService — streaming
		// gRPC-direct only, REST не регистрируется вовсе.
		{
			name: "nlb networkLoadBalancers list (public)",
			path: "/nlb/v1/networkLoadBalancers",
			want: false,
		},
		{
			name: "nlb networkLoadBalancers get (public)",
			path: "/nlb/v1/networkLoadBalancers/nlb-1",
			want: false,
		},
		{
			name: "nlb networkLoadBalancers :start verb (public)",
			path: "/nlb/v1/networkLoadBalancers/nlb-1:start",
			want: false,
		},
		{
			name: "nlb networkLoadBalancers operations subroute (public)",
			path: "/nlb/v1/networkLoadBalancers/nlb-1/operations",
			want: false,
		},
		{
			name: "nlb listeners list (public)",
			path: "/nlb/v1/listeners",
			want: false,
		},
		{
			name: "nlb listeners get (public)",
			path: "/nlb/v1/listeners/lst-1",
			want: false,
		},
		{
			name: "nlb targetGroups :addTargets verb (public)",
			path: "/nlb/v1/targetGroups/tgr-1:addTargets",
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isInternalPath(tc.path); got != tc.want {
				t.Errorf("isInternalPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestNewMux_RegistersNLBRoutes — NewMux успешно регистрирует public
// сервисы kacho-nlb (NetworkLoadBalancer/Listener/TargetGroup) на /nlb/v1/*,
// когда передан адрес nlb backend. Без kacho-nlb backend (запрос на /nlb/v1/...)
// должен дойти до grpc-gateway handler и попытаться сделать gRPC-вызов
// (что для теста проявится как 503/UNAVAILABLE на disconnected dial — не как 404
// от grpc-gateway, означая «route не зарегистрирован»). Здесь проверяем сам
// факт регистрации: NewMux не падает и handler не возвращает 404 на nlb-paths.
func TestNewMux_RegistersNLBRoutes(t *testing.T) {
	addrs := map[string]string{
		"vpc":             "127.0.0.1:1",
		"vpcInternal":     "127.0.0.1:1",
		"compute":         "127.0.0.1:1",
		"computeInternal": "127.0.0.1:1",
		"iam":             "127.0.0.1:1",
		"iamInternal":     "127.0.0.1:1",
		// kacho-nlb backend (public + internal-port).
		"loadbalancer":         "127.0.0.1:1",
		"loadbalancerInternal": "127.0.0.1:1",
	}
	h, err := NewMux(context.Background(), addrs, nil /* conns */, nil /* dialOpts → insecure */)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}
	if h == nil {
		t.Fatal("NewMux returned nil http.Handler")
	}

	// nlb public routes должны быть зарегистрированы → grpc-gateway возвращает
	// НЕ 404 (Not Found). Тест НЕ проверяет успех вызова: backend на 127.0.0.1:1
	// недостижим, ответ будет 503/UNAVAILABLE; главное — route найден.
	nlbPublicPaths := []struct {
		method, path string
	}{
		{"GET", "/nlb/v1/networkLoadBalancers"},
		{"GET", "/nlb/v1/networkLoadBalancers/nlb-1"},
		{"GET", "/nlb/v1/listeners"},
		{"GET", "/nlb/v1/listeners/lst-1"},
		{"GET", "/nlb/v1/targetGroups"},
		{"GET", "/nlb/v1/targetGroups/tgr-1"},
	}
	for _, tc := range nlbPublicPaths {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("nlb-route %s %s: получили 404 от grpc-gateway — handler не зарегистрирован", tc.method, tc.path)
			}
		})
	}
}

// TestNewMux_NoNLBBackend_RouteNotRegistered — когда адрес
// loadbalancer-backend пустой, nlb-handlers НЕ регистрируются и grpc-gateway
// возвращает 404. Подтверждает, что регистрация условна (по env, как vpc/compute/iam).
func TestNewMux_NoNLBBackend_RouteNotRegistered(t *testing.T) {
	addrs := map[string]string{
		"vpc":     "127.0.0.1:1",
		"compute": "127.0.0.1:1",
		"iam":     "127.0.0.1:1",
		// loadbalancer/loadbalancerInternal отсутствуют намеренно
	}
	h, err := NewMux(context.Background(), addrs, nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	req := httptest.NewRequest("GET", "/nlb/v1/networkLoadBalancers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("без loadbalancer backend ожидали 404, получили %d", rec.Code)
	}
}

// TestNewMux_RegistersInternalClusterRoutes — InternalClusterService
// is wired on the internal mux under /iam/v1/internal/cluster/... when
// iamInternal backend is configured. The test fires HTTP requests against the
// dispatcher and checks that the response is NOT a route-level 404 (it is
// instead some downstream gRPC error because the backend at 127.0.0.1:1 is
// unreachable). A bare 404 means grpc-gateway has no route registered.
//
// Symmetric with TestNewMux_RegistersNLBRoutes — proves the surface area is
// actually exposed.
func TestNewMux_RegistersInternalClusterRoutes(t *testing.T) {
	addrs := map[string]string{
		"vpc":             "127.0.0.1:1",
		"vpcInternal":     "127.0.0.1:1",
		"compute":         "127.0.0.1:1",
		"computeInternal": "127.0.0.1:1",
		"iam":             "127.0.0.1:1",
		"iamInternal":     "127.0.0.1:1",
	}
	h, err := NewMux(context.Background(), addrs, nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}
	if h == nil {
		t.Fatal("NewMux returned nil http.Handler")
	}

	// All four RPCs of InternalClusterService — one path each.
	internalClusterPaths := []struct {
		method, path string
	}{
		{"GET", "/iam/v1/internal/cluster"},               // Get
		{"GET", "/iam/v1/internal/cluster/admins"},        // ListAdmins
		{"POST", "/iam/v1/internal/cluster/admins"},       // GrantAdmin
		{"DELETE", "/iam/v1/internal/cluster/admins/usr"}, // RevokeAdmin
	}
	for _, tc := range internalClusterPaths {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("InternalClusterService route %s %s: got 404 from grpc-gateway — handler not registered", tc.method, tc.path)
			}
		})
	}
}

// TestNewMux_NoIAMInternalBackend_ClusterRouteNotRegistered — when
// iamInternal backend address is missing, the InternalClusterService routes are
// not wired and the dispatcher returns 404. Mirrors the conditional pattern
// for vpc/compute/iam/nlb backends and confirms the registration block lives
// inside `if iamInternalAddr != ""`.
func TestNewMux_NoIAMInternalBackend_ClusterRouteNotRegistered(t *testing.T) {
	addrs := map[string]string{
		// iamInternal intentionally absent
		"iam":             "127.0.0.1:1",
		"compute":         "127.0.0.1:1",
		"vpc":             "127.0.0.1:1",
		"vpcInternal":     "127.0.0.1:1",
		"computeInternal": "127.0.0.1:1",
	}
	h, err := NewMux(context.Background(), addrs, nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	req := httptest.NewRequest("GET", "/iam/v1/internal/cluster", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("без iamInternal backend ожидали 404 на /iam/v1/internal/cluster, получили %d", rec.Code)
	}
}
