package proxy_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// TestGateway_S5_GeoRoutesToBackend (epic kacho-geo S5) — публичные geo-RPC
// (RegionService/ZoneService) маршрутизируются на geo-backend через domain-prefix
// `kacho.cloud.geo.v1.*`, а Internal*-методы geo блокируются HasInternalSuffix
// (запрет #6) → NOT_FOUND, никогда не доходят до backend.
//
// Mirrors TestGateway_A6b_ComputeRoutesToBackend.
func TestGateway_S5_GeoRoutesToBackend(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute", "geo"})
	director := proxy.NewDirector(backends)

	publicMethods := []string{
		"/kacho.cloud.geo.v1.RegionService/Get",
		"/kacho.cloud.geo.v1.RegionService/List",
		"/kacho.cloud.geo.v1.ZoneService/Get",
		"/kacho.cloud.geo.v1.ZoneService/List",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			_, conn, err := director(context.Background(), m)
			if err != nil {
				t.Fatalf("ожидали успех для public geo-метода %q: %v", m, err)
			}
			if conn != backends["geo"] {
				t.Errorf("метод %q: директор должен вернуть geo-backend", m)
			}
		})
	}

	internalMethods := []string{
		"/kacho.cloud.geo.v1.InternalRegionService/Create",
		"/kacho.cloud.geo.v1.InternalZoneService/Delete",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			_, _, err := director(context.Background(), m)
			if err == nil {
				t.Fatalf("Internal geo-метод %q должен быть заблокирован (запрет #6)", m)
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.NotFound {
				t.Errorf("метод %q: ожидали NOT_FOUND, получили %v", m, err)
			}
		})
	}
}
