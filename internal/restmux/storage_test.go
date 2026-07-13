// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package restmux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
)

// storageMuxAddrs — backend address map including the storage public + internal
// keys, so the public VolumeService/SnapshotService/DiskTypeService AND the
// InternalVolumeService/InternalDiskTypeService admin handlers all register.
func storageMuxAddrs() map[string]string {
	return map[string]string{
		"vpc":             "127.0.0.1:1",
		"vpcInternal":     "127.0.0.1:1",
		"compute":         "127.0.0.1:1",
		"computeInternal": "127.0.0.1:1",
		"iam":             "127.0.0.1:1",
		"iamInternal":     "127.0.0.1:1",
		"storage":         "127.0.0.1:1",
		"storageInternal": "127.0.0.1:1",
	}
}

// TestStorage_PublicRoutesRegistered — публичные storage REST-пути
// (volumes/snapshots CRUD + diskTypes read) должны обслуживаться на ОБОИХ
// листенерах (external + internal): route найден (НЕ route-level 404).
// Недостижимый backend 127.0.0.1:1 дает downstream gRPC-ошибку, не 404.
func TestStorage_PublicRoutesRegistered(t *testing.T) {
	h, err := NewMux(context.Background(), storageMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	publicRoutes := []struct{ method, path string }{
		// VolumeService
		{"GET", "/storage/v1/volumes"},
		{"POST", "/storage/v1/volumes"},
		{"GET", "/storage/v1/volumes/vol-1"},
		{"PATCH", "/storage/v1/volumes/vol-1"},
		{"DELETE", "/storage/v1/volumes/vol-1"},
		{"GET", "/storage/v1/volumes/vol-1/operations"},
		// SnapshotService
		{"GET", "/storage/v1/snapshots"},
		{"POST", "/storage/v1/snapshots"},
		{"GET", "/storage/v1/snapshots/snp-1"},
		{"PATCH", "/storage/v1/snapshots/snp-1"},
		{"DELETE", "/storage/v1/snapshots/snp-1"},
		// DiskTypeService (read-only справочник)
		{"GET", "/storage/v1/diskTypes"},
		{"GET", "/storage/v1/diskTypes/network-ssd"},
	}
	for _, tc := range publicRoutes {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// External is the fail-closed default (no internal-origin marker) —
			// public routes stay served.
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("storage public %s %s on EXTERNAL listener: got 404 — public route not registered",
					tc.method, tc.path)
			}
		})
	}
}

// TestStorage_InternalVolumeService_InternalListenerServes —
// InternalVolumeService (Attach/Detach/ListAttachments/GetInternal) не имеет
// google.api.http-аннотаций → grpc-gateway создает default unbound-route
// POST /kacho.cloud.storage.v1.InternalVolumeService/*. На INTERNAL листенере
// (data-plane/admin-tooling) route должен быть найден: недостижимый backend
// дает downstream-ошибку (НЕ route-level 404).
func TestStorage_InternalVolumeService_InternalListenerServes(t *testing.T) {
	h, err := NewMux(context.Background(), storageMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	internalRoutes := []struct{ method, path string }{
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/Attach"},
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/Detach"},
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/ListAttachments"},
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/GetInternal"},
	}
	for _, tc := range internalRoutes {
		tc := tc
		t.Run("INT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = req.WithContext(listenerorigin.WithInternal(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("storage Internal* %s %s on INTERNAL listener: got 404 — Internal handler not registered (data-plane/admin broken)",
					tc.method, tc.path)
			}
		})
	}
}

// TestStorage_InternalVolumeService_ExternalListenerRejected — тот же
// InternalVolumeService default-путь на EXTERNAL TLS листенере обязан вернуть
// 404 (existence-hiding): Attach/Detach/ListAttachments/GetInternal (инфра-
// чувствительные placement-поля) не публикуются на external endpoint.
// isInternalPath ловит Internal*Service default-route (зеркалит gRPC
// HasInternalSuffix-блок).
func TestStorage_InternalVolumeService_ExternalListenerRejected(t *testing.T) {
	h, err := NewMux(context.Background(), storageMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	internalRoutes := []struct{ method, path string }{
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/Attach"},
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/Detach"},
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/ListAttachments"},
		{"POST", "/kacho.cloud.storage.v1.InternalVolumeService/GetInternal"},
	}
	for _, tc := range internalRoutes {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// External is the fail-closed default (no internal-origin marker).
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("storage Internal* %s %s on EXTERNAL listener: got %d, want 404 (CRITICAL: internal path exposed on external endpoint)",
					tc.method, tc.path, rec.Code)
			}
		})
	}
}
