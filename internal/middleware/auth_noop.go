package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"google.golang.org/grpc"
)

// UnaryAuthNoop — placeholder auth interceptor (no-op).
// AAA запланировано на фазу 1. Сейчас все запросы проходят насквозь (сценарий F7).
func UnaryAuthNoop(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		logger.Debug("auth", "status", "no-op", "method", info.FullMethod)
		return handler(ctx, req)
	}
}

// StreamAuthNoop — placeholder auth streaming interceptor (no-op).
func StreamAuthNoop(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger.Debug("auth", "status", "no-op", "method", info.FullMethod)
		return handler(srv, ss)
	}
}

// HTTPAuthNoop — placeholder HTTP auth middleware (no-op).
func HTTPAuthNoop(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
