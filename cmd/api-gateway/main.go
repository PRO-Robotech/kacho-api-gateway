package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/health"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/restmux"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// --- Backend connections: один постоянный ClientConn на backend (OQ-6) ---
	keepaliveParams := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepaliveParams),
	}

	backends := make(proxy.Backends)
	for domain, addr := range cfg.BackendAddrs() {
		conn, dialErr := grpc.NewClient(addr, dialOpts...)
		if dialErr != nil {
			log.Fatalf("dial %s (%s): %v", domain, addr, dialErr)
		}
		defer conn.Close()
		backends[domain] = conn
	}

	// --- gRPC server ---
	director := proxy.NewDirector(backends)
	grpcSrv := proxy.NewServer(director,
		grpc.ChainUnaryInterceptor(
			middleware.UnaryRequestID,
			middleware.UnaryRecovery(logger),
			middleware.UnaryAuthNoop(logger),
			middleware.UnaryAccessLog(logger),
		),
		grpc.ChainStreamInterceptor(
			middleware.StreamRequestID,
			middleware.StreamRecovery(logger),
			middleware.StreamAuthNoop(logger),
			middleware.StreamAccessLog(logger),
		),
	)
	health.RegisterGRPCHealth(grpcSrv, backends)

	// --- REST mux (grpc-gateway) ---
	// Примечание: proto-файлы не содержат HTTP-аннотаций (google.api.http),
	// поэтому REST-маршруты /v1/... недоступны до фазы 1 (см. internal/restmux/mux.go).
	restAddrs := cfg.BackendAddrs()
	restHandler, err := restmux.NewMux(ctx, restAddrs)
	if err != nil {
		log.Fatalf("rest mux: %v", err)
	}

	// --- HTTP mux с health endpoints ---
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", health.HTTPHealthz)
	httpMux.Handle("/readyz", health.HTTPReadyz(backends, logger))
	httpMux.Handle("/", restHandler)

	httpHandler := middleware.HTTPRequestID(
		middleware.HTTPRecovery(logger)(
			middleware.HTTPAuthNoop(
				middleware.HTTPAccessLog(logger)(httpMux),
			),
		),
	)

	httpSrv := &http.Server{
		Handler:      httpHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// --- cmux: HTTP/2 gRPC vs HTTP/1.1 REST на одном порту ---
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.ListenAddr, err)
	}
	logger.Info("api-gateway started", "addr", cfg.ListenAddr)

	cmuxer := cmux.New(listener)
	// HTTP/2 с Content-Type: application/grpc → gRPC listener
	grpcL := cmuxer.MatchWithWriters(
		cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
	)
	// Всё остальное → HTTP listener (grpc-gateway + healthz/readyz)
	httpL := cmuxer.Match(cmux.Any())

	go func() {
		if serveErr := grpcSrv.Serve(grpcL); serveErr != nil {
			logger.Error("grpc serve error", "error", serveErr)
		}
	}()

	go func() {
		if serveErr := httpSrv.Serve(httpL); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Error("http serve error", "error", serveErr)
		}
	}()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		grpcSrv.GracefulStop()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	if serveErr := cmuxer.Serve(); serveErr != nil {
		logger.Error("cmux serve error", "error", serveErr)
	}
}
