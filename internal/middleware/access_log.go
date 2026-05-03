package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryAccessLog — unary gRPC interceptor: slog access log.
// Формат: {"level":"INFO","ts":"...","msg":"access","method":"...","status":0,"duration_ms":12,"request_id":"..."}
func UnaryAccessLog(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code()
			} else {
				code = codes.Unknown
			}
		}
		logger.Info("access",
			"method", info.FullMethod,
			"status", int(code),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", RequestIDFromContext(ctx),
		)
		return resp, err
	}
}

// StreamAccessLog — streaming gRPC interceptor: slog access log.
func StreamAccessLog(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		code := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code()
			} else {
				code = codes.Unknown
			}
		}
		logger.Info("access",
			"method", info.FullMethod,
			"status", int(code),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", RequestIDFromContext(ss.Context()),
		)
		return err
	}
}

// responseWriter оборачивает http.ResponseWriter для захвата статус-кода.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// HTTPAccessLog — HTTP middleware: slog access log для REST-запросов.
func HTTPAccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := newResponseWriter(w)
			next.ServeHTTP(rw, r)
			id := RequestIDFromContext(r.Context())
			logger.Info("access",
				"method", r.Method+" "+r.URL.Path,
				"status", rw.statusCode,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", id,
			)
		})
	}
}
