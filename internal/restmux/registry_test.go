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

// registryMuxAddrs — backend address map including the registry public +
// internal keys, so the public RegistryService AND the InternalRegistryService
// admin handlers all register.
func registryMuxAddrs() map[string]string {
	return map[string]string{
		"vpc":                  "127.0.0.1:1",
		"vpcInternal":          "127.0.0.1:1",
		"compute":              "127.0.0.1:1",
		"computeInternal":      "127.0.0.1:1",
		"iam":                  "127.0.0.1:1",
		"iamInternal":          "127.0.0.1:1",
		"loadbalancer":         "127.0.0.1:1",
		"loadbalancerInternal": "127.0.0.1:1",
		"geo":                  "127.0.0.1:1",
		"geoInternal":          "127.0.0.1:1",
		"registry":             "127.0.0.1:1",
		"registryInternal":     "127.0.0.1:1",
	}
}

// TestRegistry_PublicRoutesRegistered — публичные registry REST-пути
// (registries CRUD + per-repo проекции) должны обслуживаться на ОБОИХ
// листенерах (external + internal): route найден (НЕ route-level 404).
// Недостижимый backend 127.0.0.1:1 дает downstream gRPC-ошибку, не 404. 404
// означает, что public registry handler не зарегистрирован.
func TestRegistry_PublicRoutesRegistered(t *testing.T) {
	h, err := NewMux(context.Background(), registryMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	publicRoutes := []struct{ method, path string }{
		{"GET", "/registry/v1/registries"},
		{"POST", "/registry/v1/registries"},
		{"GET", "/registry/v1/registries/reg-1"},
		{"PATCH", "/registry/v1/registries/reg-1"},
		{"DELETE", "/registry/v1/registries/reg-1"},
		{"GET", "/registry/v1/registries/reg-1/repositories"},
		// {repository} — единичный path-сегмент в grpc-gateway pattern; проверяем
		// сам факт регистрации route (не encoded-slash matching).
		{"GET", "/registry/v1/registries/reg-1/repositories/web/tags"},
		{"DELETE", "/registry/v1/registries/reg-1/repositories/web/tags/v1"},
	}
	for _, tc := range publicRoutes {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// Simulate arrival on the external listener — public routes stay served.
			req = req.WithContext(listenerorigin.WithExternal(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("registry public %s %s on EXTERNAL listener: got 404 — public route not registered",
					tc.method, tc.path)
			}
		})
	}
}

// TestRegistry_InternalService_InternalListenerServes — InternalRegistryService
// (GC/stats admin) не имеет google.api.http-аннотаций → grpc-gateway создает
// default unbound-route POST /kacho.cloud.registry.v1.InternalRegistryService/*.
// На INTERNAL листенере (UI/admin/port-forward) route должен быть найден:
// недостижимый backend дает downstream-ошибку (НЕ route-level 404). 404 здесь
// значит, что Internal* handler не зарегистрирован — admin-tooling сломан.
func TestRegistry_InternalService_InternalListenerServes(t *testing.T) {
	h, err := NewMux(context.Background(), registryMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	internalRoutes := []struct{ method, path string }{
		{"POST", "/kacho.cloud.registry.v1.InternalRegistryService/TriggerGarbageCollection"},
		{"POST", "/kacho.cloud.registry.v1.InternalRegistryService/GetRegistryStats"},
	}
	for _, tc := range internalRoutes {
		tc := tc
		t.Run("INT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			// No external marker → internal origin (the default).
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Errorf("registry Internal* %s %s on INTERNAL listener: got 404 — Internal handler not registered (admin-tooling broken)",
					tc.method, tc.path)
			}
		})
	}
}

// TestRegistry_InternalService_ExternalListenerRejected — тот же
// InternalRegistryService default-путь на EXTERNAL TLS листенере обязан
// вернуть 404 (existence-hiding, ban #6): GC/stats admin не публикуется на
// external endpoint. isInternalPath должен ловить Internal*Service
// default-route (зеркалит gRPC HasInternalSuffix-блок).
func TestRegistry_InternalService_ExternalListenerRejected(t *testing.T) {
	h, err := NewMux(context.Background(), registryMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	internalRoutes := []struct{ method, path string }{
		{"POST", "/kacho.cloud.registry.v1.InternalRegistryService/TriggerGarbageCollection"},
		{"POST", "/kacho.cloud.registry.v1.InternalRegistryService/GetRegistryStats"},
	}
	for _, tc := range internalRoutes {
		tc := tc
		t.Run("EXT "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req = req.WithContext(listenerorigin.WithExternal(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("registry Internal* %s %s on EXTERNAL listener: got %d, want 404 (CRITICAL: admin GC/stats exposed on external endpoint, ban #6)",
					tc.method, tc.path, rec.Code)
			}
		})
	}
}

// TestRegistry_InternalGuard_NoInternalAddr — когда registryInternalAddr пуст,
// InternalRegistryService handler НЕ регистрируется (graceful degrade,
// зеркалит vpcInternal/computeInternal/geoInternal). Публичный RegistryService
// продолжает регистрироваться из registryAddr. Доказывает, что *InternalAddr
// guard оборачивает только Internal*-регистрацию (ban #6).
func TestRegistry_InternalGuard_NoInternalAddr(t *testing.T) {
	addrs := registryMuxAddrs()
	addrs["registryInternal"] = "" // internal backend absent

	h, err := NewMux(context.Background(), addrs, nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	// Public route still registers (served from registryAddr).
	req := httptest.NewRequest("GET", "/registry/v1/registries", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("registry public GET /registry/v1/registries: got 404 with empty registryInternalAddr — public must still register")
	}
}
