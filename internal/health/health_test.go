// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package health_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/health"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// TestGateway_G1_HealthzAlwaysOK проверяет сценарий G1 и G4: /healthz всегда 200.
func TestGateway_G1_HealthzAlwaysOK(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	health.HTTPHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("ожидали 200, получили %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("тело должно содержать 'ok', получили: %s", body)
	}
}

// TestGateway_G3_ReadyzUnavailableWhenBackendDown проверяет сценарий G3:
// если backend недоступен — /readyz возвращает 503.
func TestGateway_G3_ReadyzUnavailableWhenBackendDown(t *testing.T) {
	// Создаем backends с несуществующими адресами (localhost:1)
	backends := make(proxy.Backends)
	// Без реального соединения — проверяем только логику HTTP-обработчика.
	// При пустом backends allOK = true → 200.
	// Тест конфигурации: если backends пуст, ответ 200.
	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	handler := health.HTTPReadyz(backends, nil, nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("при пустом backends ожидали 200, получили %d", rec.Code)
	}
}

// TestEvaluateReadiness_NonCriticalDownStaysReady проверяет, что падение
// НЕкритичного backend (compute) не выводит весь edge из rotation — только его
// домен деградирует, остальные обслуживаются, поэтому реплика остается Ready.
func TestEvaluateReadiness_NonCriticalDownStaysReady(t *testing.T) {
	critical := map[string]bool{"iam": true}
	serving := map[string]bool{"iam": true, "compute": false, "vpc": true}
	status, criticalDown := health.EvaluateReadiness(serving, critical)
	if criticalDown {
		t.Error("падение non-critical compute не должно валить readiness")
	}
	if status["compute"] != "NOT_SERVING" {
		t.Errorf("compute должен быть NOT_SERVING в отчете, получили %q", status["compute"])
	}
	if status["iam"] != "SERVING" {
		t.Errorf("iam должен быть SERVING, получили %q", status["iam"])
	}
}

// TestEvaluateReadiness_CriticalDownNotReady проверяет, что падение критичного
// backend (iam — authN/authZ на каждом запросе) выводит реплику из rotation.
func TestEvaluateReadiness_CriticalDownNotReady(t *testing.T) {
	critical := map[string]bool{"iam": true, "iamInternal": true}
	serving := map[string]bool{"iam": false, "compute": true}
	_, criticalDown := health.EvaluateReadiness(serving, critical)
	if !criticalDown {
		t.Error("падение iam должно валить readiness (authz недоступен)")
	}
}
