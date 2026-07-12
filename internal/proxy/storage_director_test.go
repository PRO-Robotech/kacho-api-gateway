// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package proxy_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// Публичные storage-RPC (VolumeService/SnapshotService/DiskTypeService)
// маршрутизируются на storage-backend через domain-prefix
// `kacho.cloud.storage.v1.*`, а InternalVolumeService.* / InternalDiskTypeService.*
// блокируются HasInternalSuffix → не резолвятся, никогда не доходят до backend.
func TestResolver_StoragePublicVsInternal(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute", "storage"})
	resolve := proxy.Resolver(backends)

	for _, m := range []string{
		"/kacho.cloud.storage.v1.VolumeService/Get",
		"/kacho.cloud.storage.v1.VolumeService/List",
		"/kacho.cloud.storage.v1.VolumeService/Create",
		"/kacho.cloud.storage.v1.VolumeService/Update",
		"/kacho.cloud.storage.v1.VolumeService/Delete",
		"/kacho.cloud.storage.v1.VolumeService/ListOperations",
		"/kacho.cloud.storage.v1.SnapshotService/Get",
		"/kacho.cloud.storage.v1.SnapshotService/List",
		"/kacho.cloud.storage.v1.SnapshotService/Create",
		"/kacho.cloud.storage.v1.SnapshotService/Update",
		"/kacho.cloud.storage.v1.SnapshotService/Delete",
		"/kacho.cloud.storage.v1.DiskTypeService/Get",
		"/kacho.cloud.storage.v1.DiskTypeService/List",
	} {
		_, conn, ok := resolve(m)
		if !ok || conn != backends["storage"] {
			t.Errorf("public storage-метод %q должен резолвиться на storage-backend (ok=%v)", m, ok)
		}
	}

	for _, m := range []string{
		"/kacho.cloud.storage.v1.InternalVolumeService/Attach",
		"/kacho.cloud.storage.v1.InternalVolumeService/Detach",
		"/kacho.cloud.storage.v1.InternalVolumeService/ListAttachments",
		"/kacho.cloud.storage.v1.InternalVolumeService/GetInternal",
		"/kacho.cloud.storage.v1.InternalDiskTypeService/Create",
		"/kacho.cloud.storage.v1.InternalDiskTypeService/Update",
		"/kacho.cloud.storage.v1.InternalDiskTypeService/Delete",
	} {
		if _, _, ok := resolve(m); ok {
			t.Errorf("Internal storage-метод %q должен быть заблокирован", m)
		}
	}
}
