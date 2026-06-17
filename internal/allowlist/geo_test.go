package allowlist_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// TestGateway_S5_GeoActive (epic kacho-geo S5) — публичные geo.v1 read-RPC
// (RegionService/ZoneService Get+List) присутствуют в allowlist, а
// Internal*-сервисы geo (InternalRegionService/InternalZoneService admin-CRUD)
// — НЕ в allowlist и блокируются HasInternalSuffix (workspace CLAUDE.md §запрет #6).
//
// Mirrors TestGateway_D8b_ComputeActive — geo получает ту же форму регистрации,
// что compute сегодня (Region/Zone public read + Internal* admin на :9091).
func TestGateway_S5_GeoActive(t *testing.T) {
	publicMethods := []string{
		"/kacho.cloud.geo.v1.RegionService/Get",
		"/kacho.cloud.geo.v1.RegionService/List",
		"/kacho.cloud.geo.v1.ZoneService/Get",
		"/kacho.cloud.geo.v1.ZoneService/List",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный geo-метод %q должен быть в allowlist (S5)", m)
			}
			if allowlist.HasInternalSuffix(m) {
				t.Errorf("публичный geo-метод %q не должен ловиться HasInternalSuffix", m)
			}
		})
	}

	internalMethods := []string{
		"/kacho.cloud.geo.v1.InternalRegionService/Create",
		"/kacho.cloud.geo.v1.InternalRegionService/Update",
		"/kacho.cloud.geo.v1.InternalRegionService/Delete",
		"/kacho.cloud.geo.v1.InternalZoneService/Create",
		"/kacho.cloud.geo.v1.InternalZoneService/Update",
		"/kacho.cloud.geo.v1.InternalZoneService/Delete",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("Internal geo-метод %q НЕ должен быть в allowlist (запрет #6)", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("Internal geo-метод %q должен ловиться HasInternalSuffix", m)
			}
		})
	}
}
