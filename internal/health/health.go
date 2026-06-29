// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// Server реализует grpc.health.v1.Health для самого gateway.
// Встроен в gRPC-сервер, чтобы отвечать на gRPC Health.Check (сценарий G5).
type Server struct {
	healthpb.UnimplementedHealthServer
	backends proxy.Backends
}

// NewServer создает health-сервер для gateway.
func NewServer(backends proxy.Backends) *Server {
	return &Server{backends: backends}
}

// Check реализует grpc.health.v1.Health/Check.
// Проверяет статус самого gateway (не backends — это задача /readyz).
func (s *Server) Check(_ context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// statusResponse — тело JSON-ответа для /healthz и /readyz.
type statusResponse struct {
	Status   string            `json:"status"`
	Backends map[string]string `json:"backends,omitempty"`
}

// HTTPHealthz обрабатывает GET /healthz.
// Всегда возвращает 200 — liveness не зависит от состояния backends (сценарии G1, G4).
func HTTPHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(statusResponse{Status: "ok"})
}

// HTTPReadyz обрабатывает GET /readyz. Опрашивает grpc.health.v1.Health.Check у
// каждого backend и решает готовность по критичным зависимостям: 503 только если
// недоступен CRITICAL-backend (iam фронтит authN+authZ на каждом запросе);
// падение НЕкритичного backend (vpc/compute/geo/nlb) — деградация одного домена,
// реплика остается Ready (иначе одно-доменный сбой амплифицируется в полный
// отказ edge). Тело ответа всегда содержит per-backend статус для диагностики.
//
// critical — множество domain-ключей, чья недоступность валит готовность. nil/
// пустое → готовность зависит только от собственной способности обслуживать
// (всегда 200, backends лишь отражаются в теле).
func HTTPReadyz(backends proxy.Backends, critical map[string]bool, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		serving := make(map[string]bool, len(backends))
		for domain, conn := range backends {
			client := healthpb.NewHealthClient(conn)
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
			ok := err == nil && resp.Status == healthpb.HealthCheckResponse_SERVING
			serving[domain] = ok
			if !ok && logger != nil {
				logger.Warn("backend not serving", "domain", domain, "error", err, "critical", critical[domain])
			}
		}

		backendStatus, criticalDown := EvaluateReadiness(serving, critical)

		w.Header().Set("Content-Type", "application/json")
		if criticalDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(statusResponse{Status: "NOT_SERVING", Backends: backendStatus})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(statusResponse{Status: "ok", Backends: backendStatus})
	}
}

// EvaluateReadiness — чистое readiness-решение поверх карты «domain → serving».
// Возвращает per-backend статус-строки и флаг criticalDown=true, если хотя бы
// один CRITICAL-backend не обслуживается. Вынесена отдельно, чтобы политику
// готовности можно было проверить без поднятия gRPC.
func EvaluateReadiness(serving map[string]bool, critical map[string]bool) (status map[string]string, criticalDown bool) {
	status = make(map[string]string, len(serving))
	for domain, ok := range serving {
		if ok {
			status[domain] = "SERVING"
			continue
		}
		status[domain] = "NOT_SERVING"
		if critical[domain] {
			criticalDown = true
		}
	}
	return status, criticalDown
}

// RegisterGRPCHealth регистрирует Health-сервер в gRPC-сервере.
func RegisterGRPCHealth(s *grpc.Server, backends proxy.Backends) {
	healthpb.RegisterHealthServer(s, NewServer(backends))
}
