// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package allowlist_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// TestGateway_Registry_PublicVsInternal — публичные registry.v1 RPC
// (RegistryService: Get/List/Create/Update/Delete + per-repo проекции
// ListRepositories/ListTags/DeleteTag) присутствуют в allowlist, а
// InternalRegistryService.* (GC/stats admin, :9091) — НЕ в allowlist и
// блокируется HasInternalSuffix (Internal не публикуется на external, ban #6).
func TestGateway_Registry_PublicVsInternal(t *testing.T) {
	publicMethods := []string{
		"/kacho.cloud.registry.v1.RegistryService/Get",
		"/kacho.cloud.registry.v1.RegistryService/List",
		"/kacho.cloud.registry.v1.RegistryService/Create",
		"/kacho.cloud.registry.v1.RegistryService/Update",
		"/kacho.cloud.registry.v1.RegistryService/Delete",
		"/kacho.cloud.registry.v1.RegistryService/ListRepositories",
		"/kacho.cloud.registry.v1.RegistryService/ListTags",
		"/kacho.cloud.registry.v1.RegistryService/DeleteTag",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный registry-метод %q должен быть в allowlist", m)
			}
			if allowlist.HasInternalSuffix(m) {
				t.Errorf("публичный registry-метод %q не должен ловиться HasInternalSuffix", m)
			}
		})
	}

	internalMethods := []string{
		"/kacho.cloud.registry.v1.InternalRegistryService/TriggerGarbageCollection",
		"/kacho.cloud.registry.v1.InternalRegistryService/GetRegistryStats",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("Internal registry-метод %q НЕ должен быть в allowlist (ban #6)", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("Internal registry-метод %q должен ловиться HasInternalSuffix", m)
			}
		})
	}
}
