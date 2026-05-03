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

// NewServer создаёт health-сервер для gateway.
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

// HTTPReadyz обрабатывает GET /readyz.
// Вызывает grpc.health.v1.Health.Check против каждого backend.
// 200 — все SERVING; 503 — хотя бы один не SERVING (сценарии G2, G3).
func HTTPReadyz(backends proxy.Backends, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		backendStatus := make(map[string]string, len(backends))
		allOK := true

		for domain, conn := range backends {
			client := healthpb.NewHealthClient(conn)
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
			if err != nil || resp.Status != healthpb.HealthCheckResponse_SERVING {
				backendStatus[domain] = "NOT_SERVING"
				allOK = false
				if logger != nil {
					logger.Warn("backend not serving", "domain", domain, "error", err)
				}
			} else {
				backendStatus[domain] = "SERVING"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if allOK {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(statusResponse{Status: "ok", Backends: backendStatus})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(statusResponse{Status: "NOT_SERVING", Backends: backendStatus})
		}
	}
}

// RegisterGRPCHealth регистрирует Health-сервер в gRPC-сервере.
func RegisterGRPCHealth(s *grpc.Server, backends proxy.Backends) {
	healthpb.RegisterHealthServer(s, NewServer(backends))
}
