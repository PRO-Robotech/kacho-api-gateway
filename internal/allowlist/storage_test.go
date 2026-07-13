// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package allowlist_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// TestGateway_Storage_PublicVsInternal — публичные storage.v1 RPC
// (VolumeService: Get/List/Create/Update/Delete/ListOperations; SnapshotService:
// Get/List/Create/Update/Delete; DiskTypeService: Get/List read-only) присутствуют
// в allowlist и НЕ ловятся HasInternalSuffix. InternalVolumeService.* (Attach/
// Detach/ListAttachments/GetInternal, :9091) и InternalDiskTypeService.* (admin
// CRUD, :9091) — НЕ в allowlist и блокируются HasInternalSuffix (Internal не
// публикуется на external, ban #6).
func TestGateway_Storage_PublicVsInternal(t *testing.T) {
	publicMethods := []string{
		// VolumeService
		"/kacho.cloud.storage.v1.VolumeService/Get",
		"/kacho.cloud.storage.v1.VolumeService/List",
		"/kacho.cloud.storage.v1.VolumeService/Create",
		"/kacho.cloud.storage.v1.VolumeService/Update",
		"/kacho.cloud.storage.v1.VolumeService/Delete",
		"/kacho.cloud.storage.v1.VolumeService/ListOperations",
		// SnapshotService
		"/kacho.cloud.storage.v1.SnapshotService/Get",
		"/kacho.cloud.storage.v1.SnapshotService/List",
		"/kacho.cloud.storage.v1.SnapshotService/Create",
		"/kacho.cloud.storage.v1.SnapshotService/Update",
		"/kacho.cloud.storage.v1.SnapshotService/Delete",
		// DiskTypeService (read-only справочник)
		"/kacho.cloud.storage.v1.DiskTypeService/Get",
		"/kacho.cloud.storage.v1.DiskTypeService/List",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			if !allowlist.IsAllowed(m) {
				t.Errorf("публичный storage-метод %q должен быть в allowlist", m)
			}
			if allowlist.HasInternalSuffix(m) {
				t.Errorf("публичный storage-метод %q не должен ловиться HasInternalSuffix", m)
			}
		})
	}

	internalMethods := []string{
		"/kacho.cloud.storage.v1.InternalVolumeService/Attach",
		"/kacho.cloud.storage.v1.InternalVolumeService/Detach",
		"/kacho.cloud.storage.v1.InternalVolumeService/ListAttachments",
		"/kacho.cloud.storage.v1.InternalVolumeService/GetInternal",
		"/kacho.cloud.storage.v1.InternalDiskTypeService/Create",
		"/kacho.cloud.storage.v1.InternalDiskTypeService/Update",
		"/kacho.cloud.storage.v1.InternalDiskTypeService/Delete",
	}
	for _, m := range internalMethods {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			if allowlist.IsAllowed(m) {
				t.Errorf("Internal storage-метод %q НЕ должен быть в allowlist (ban #6)", m)
			}
			if !allowlist.HasInternalSuffix(m) {
				t.Errorf("Internal storage-метод %q должен ловиться HasInternalSuffix", m)
			}
		})
	}
}
