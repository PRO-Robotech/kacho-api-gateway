package restmux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsInternalPath покрывает path-based dispatch правил для split-mux (KAC-50).
//
// Логика: любой путь, который relates к admin/internal-поверхности (data-plane
// проекции, AddressPool, Hypervisor, admin-bindings) → internal sub-mux
// (EmitUnpopulated=false); всё остальное (tenant-facing public контракт
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

		// --- (2) /vpc/v1/addressPools[/...|:...] ---
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
		{
			name: "addressPools :check verb",
			path: "/vpc/v1/addressPools:check",
			want: true,
		},
		{
			name: "addressPools :explainResolution verb",
			path: "/vpc/v1/addressPools:explainResolution",
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

		// --- (4) /vpc/v1/addresses/{id}/addressPoolOverride ---
		{
			name: "address addressPoolOverride",
			path: "/vpc/v1/addresses/addr-1/addressPoolOverride",
			want: true,
		},
		{
			name: "address get by id (public)",
			path: "/vpc/v1/addresses/addr-1",
			want: false,
		},

		// --- (5) /vpc/v1/clouds/{id}/poolSelector ---
		{
			name: "cloud poolSelector",
			path: "/vpc/v1/clouds/cl-1/poolSelector",
			want: true,
		},
		{
			name: "cloud get by id (public)",
			path: "/vpc/v1/clouds/cl-1",
			want: false,
		},

		// --- (6) /compute/v1/hypervisors[/...] ---
		// Hypervisor выпилен из proto (KAC-36), но path-classification остаётся
		// helper'ом defense-in-depth, чтобы при возможной реинтродукции пустые
		// поля скрывались без отдельного релиза gateway.
		{
			name: "hypervisors root",
			path: "/compute/v1/hypervisors",
			want: true,
		},
		{
			name: "hypervisors by id",
			path: "/compute/v1/hypervisors/hv-1",
			want: true,
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
			name: "project get (public) — KAC-124: заменили /resource-manager/v1/folders на /iam/v1/projects",
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

		// --- KAC-161: kacho-nlb /nlb/v1/* — все public (никаких /internal сегментов
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

// TestNewMux_RegistersNLBRoutes (KAC-161) — NewMux успешно регистрирует public
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
		// KAC-161: kacho-nlb backend (public + internal-port).
		"loadbalancer":         "127.0.0.1:1",
		"loadbalancerInternal": "127.0.0.1:1",
	}
	h, err := NewMux(context.Background(), addrs, nil /* conns */)
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

// TestNewMux_NoNLBBackend_RouteNotRegistered (KAC-161) — когда адрес
// loadbalancer-backend пустой, nlb-handlers НЕ регистрируются и grpc-gateway
// возвращает 404. Подтверждает, что регистрация условна (по env, как vpc/compute/iam).
func TestNewMux_NoNLBBackend_RouteNotRegistered(t *testing.T) {
	addrs := map[string]string{
		"vpc":         "127.0.0.1:1",
		"compute":     "127.0.0.1:1",
		"iam":         "127.0.0.1:1",
		// loadbalancer/loadbalancerInternal отсутствуют намеренно
	}
	h, err := NewMux(context.Background(), addrs, nil)
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
