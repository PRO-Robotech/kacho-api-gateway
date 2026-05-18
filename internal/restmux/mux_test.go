package restmux

import "testing"

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
