// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// TestBackendAddrs_StorageKeys — BackendAddrs отдает публичный и internal
// endpoint kacho-storage ("storage" / "storageInternal"), чтобы dialBackends
// открыл conn (opsproxy маршрутизирует sop-операции), а restmux зарегистрировал
// REST-хендлеры VolumeService/SnapshotService/DiskTypeService и
// InternalVolumeService/InternalDiskTypeService.
func TestBackendAddrs_StorageKeys(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	addrs := cfg.BackendAddrs()
	for _, key := range []string{"storage", "storageInternal"} {
		if addrs[key] == "" {
			t.Errorf("BackendAddrs()[%q] пуст — storage backend не сконфигурирован", key)
		}
	}
}

// TestEdgeTLSClient_StorageEdge — edge "storage" известен EdgeTLSClient (иначе
// buildBackendDialCreds/backendEdge упадет на storage-ключах). По умолчанию mTLS
// выключен → Enable=false (insecure dial, dev backward-compat).
func TestEdgeTLSClient_StorageEdge(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tc, err := cfg.EdgeTLSClient("storage", cfg.BackendAddrs()["storage"])
	if err != nil {
		t.Fatalf("EdgeTLSClient(storage): %v", err)
	}
	if tc.Enable {
		t.Errorf("storage edge должен быть insecure по умолчанию (Enable=false), получили Enable=true")
	}
}
