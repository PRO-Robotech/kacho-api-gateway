// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package proxy_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// Публичные geo-RPC (RegionService/ZoneService) маршрутизируются на geo-backend
// через domain-prefix `kacho.cloud.geo.v1.*`, а Internal*-методы geo
// блокируются HasInternalSuffix → не резолвятся, никогда не доходят до backend.
func TestResolver_GeoPublicVsInternal(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute", "geo"})
	resolve := proxy.Resolver(backends)

	for _, m := range []string{
		"/kacho.cloud.geo.v1.RegionService/Get",
		"/kacho.cloud.geo.v1.RegionService/List",
		"/kacho.cloud.geo.v1.ZoneService/Get",
		"/kacho.cloud.geo.v1.ZoneService/List",
	} {
		_, conn, ok := resolve(m)
		if !ok || conn != backends["geo"] {
			t.Errorf("public geo-метод %q должен резолвиться на geo-backend (ok=%v)", m, ok)
		}
	}

	for _, m := range []string{
		"/kacho.cloud.geo.v1.InternalRegionService/Create",
		"/kacho.cloud.geo.v1.InternalZoneService/Delete",
	} {
		if _, _, ok := resolve(m); ok {
			t.Errorf("Internal geo-метод %q должен быть заблокирован", m)
		}
	}
}
