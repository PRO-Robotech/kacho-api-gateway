// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// TestBackendAddrs_RegistryKeys — BackendAddrs отдает публичный и internal
// endpoint kacho-registry ("registry" / "registryInternal"), чтобы
// dialBackends открыл conn (opsproxy маршрутизирует rop-операции), а restmux
// зарегистрировал REST-хендлеры RegistryService/InternalRegistryService.
func TestBackendAddrs_RegistryKeys(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	addrs := cfg.BackendAddrs()
	for _, key := range []string{"registry", "registryInternal"} {
		if addrs[key] == "" {
			t.Errorf("BackendAddrs()[%q] пуст — registry backend не сконфигурирован", key)
		}
	}
}

// TestEdgeTLSClient_RegistryEdge — edge "registry" известен EdgeTLSClient
// (иначе buildBackendDialCreds/backendEdge упадет на registry-ключах). По
// умолчанию mTLS выключен → Enable=false (insecure dial, dev backward-compat).
func TestEdgeTLSClient_RegistryEdge(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tc, err := cfg.EdgeTLSClient("registry", cfg.BackendAddrs()["registry"])
	if err != nil {
		t.Fatalf("EdgeTLSClient(registry): %v", err)
	}
	if tc.Enable {
		t.Errorf("registry edge должен быть insecure по умолчанию (Enable=false), получили Enable=true")
	}
}
