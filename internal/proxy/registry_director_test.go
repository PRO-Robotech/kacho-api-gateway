// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package proxy_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// Публичные registry-RPC (RegistryService) маршрутизируются на registry-backend
// через domain-prefix `kacho.cloud.registry.v1.*`, а InternalRegistryService.*
// блокируется HasInternalSuffix → не резолвится, никогда не доходит до backend.
func TestResolver_RegistryPublicVsInternal(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute", "registry"})
	resolve := proxy.Resolver(backends)

	for _, m := range []string{
		"/kacho.cloud.registry.v1.RegistryService/Get",
		"/kacho.cloud.registry.v1.RegistryService/List",
		"/kacho.cloud.registry.v1.RegistryService/Create",
		"/kacho.cloud.registry.v1.RegistryService/Update",
		"/kacho.cloud.registry.v1.RegistryService/Delete",
		"/kacho.cloud.registry.v1.RegistryService/ListRepositories",
		"/kacho.cloud.registry.v1.RegistryService/ListTags",
		"/kacho.cloud.registry.v1.RegistryService/DeleteTag",
	} {
		_, conn, ok := resolve(m)
		if !ok || conn != backends["registry"] {
			t.Errorf("public registry-метод %q должен резолвиться на registry-backend (ok=%v)", m, ok)
		}
	}

	for _, m := range []string{
		"/kacho.cloud.registry.v1.InternalRegistryService/TriggerGarbageCollection",
		"/kacho.cloud.registry.v1.InternalRegistryService/GetRegistryStats",
	} {
		if _, _, ok := resolve(m); ok {
			t.Errorf("Internal registry-метод %q должен быть заблокирован", m)
		}
	}
}
