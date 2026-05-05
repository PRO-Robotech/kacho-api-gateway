package main

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soheilhy/cmux"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	// Регистрация errdetails-типов в protoregistry — иначе protojson не
	// разворачивает Any в BadRequest.FieldViolations / ResourceInfo при
	// marshalling InvalidArgument-ответов в JSON, и клиент видит только
	// "failed to marshal error message".
	_ "google.golang.org/genproto/googleapis/rpc/errdetails"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/health"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
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

	// --- Backend connections: один постоянный ClientConn на backend ---
	// Активные backends: resource-manager + vpc.
	// Compute и loadbalancer заморожены — dial не выполняется.
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

	// OpsProxy регистрируется как нативный gRPC-сервис в gateway-сервере.
	// Запросы /kacho.cloud.operation.OperationService/* идут напрямую сюда,
	// минуя transparent-proxy director.
	opsProxy := opsproxy.New(backends)
	operationpb.RegisterOperationServiceServer(grpcSrv, opsProxy)

	// gRPC reflection — позволяет grpcurl и совместимым CLI получить список
	// сервисов через ServerReflection. Видны только сервисы, нативно
	// зарегистрированные на api-gateway (OperationService + Health). Сервисы
	// vpc/resource-manager доступны через transparent-proxy и видны в
	// reflection их собственных backends (если включить там).
	reflection.Register(grpcSrv)

	// --- REST mux (grpc-gateway) ---
	// Регистрирует активные публичные сервисы + OperationService через OpsProxy.
	// *InternalService* не регистрируются (запрет #7).
	restAddrs := cfg.BackendAddrs()
	restHandler, err := restmux.NewMux(ctx, restAddrs, backends)
	if err != nil {
		log.Fatalf("rest mux: %v", err)
	}

	// --- HTTP mux с health endpoints ---
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", health.HTTPHealthz)
	httpMux.Handle("/readyz", health.HTTPReadyz(backends, logger))
	httpMux.Handle("/", restHandler)

	// Idempotency-Key store: in-memory с TTL=24h (как в YC).
	idempStore := middleware.NewIdempotencyStore(middleware.IdempotencyTTL)

	httpHandler := middleware.HTTPRequestID(
		middleware.HTTPRecovery(logger)(
			middleware.HTTPAuthNoop(
				middleware.HTTPAccessLog(logger)(
					middleware.HTTPIdempotency(idempStore)(httpMux),
				),
			),
		),
	)

	httpSrv := &http.Server{
		Handler:     httpHandler,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
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

	// --- TLS listener (опционально) для совместимости с yc CLI / TLS-клиентами ---
	// Запускаем отдельный TLS-листенер; за ним — отдельный cmux, который точно так же
	// разделяет gRPC vs HTTP/REST после TLS-handshake. Тот же grpcSrv и httpSrv обслуживают
	// connections (через два независимых serve goroutine).
	var tlsCmux cmux.CMux
	if cfg.TLSEnabled() {
		cert, certErr := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if certErr != nil {
			log.Fatalf("load TLS cert (%s, %s): %v", cfg.TLSCertFile, cfg.TLSKeyFile, certErr)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		}
		tlsListener, tlsErr := tls.Listen("tcp", cfg.TLSListenAddr, tlsCfg)
		if tlsErr != nil {
			log.Fatalf("tls listen %s: %v", cfg.TLSListenAddr, tlsErr)
		}
		logger.Info("api-gateway TLS started", "addr", cfg.TLSListenAddr)

		// Включаем h2c-style HTTP/2 поддержку для http.Server (через golang.org/x/net/http2),
		// иначе HTTP/2 over TLS не работает корректно.
		_ = http2.ConfigureServer(httpSrv, &http2.Server{})

		tlsCmux = cmux.New(tlsListener)
		tlsGrpcL := tlsCmux.MatchWithWriters(
			cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
		)
		tlsHTTPL := tlsCmux.Match(cmux.Any())

		go func() {
			if serveErr := grpcSrv.Serve(tlsGrpcL); serveErr != nil {
				logger.Error("tls grpc serve error", "error", serveErr)
			}
		}()
		go func() {
			if serveErr := httpSrv.Serve(tlsHTTPL); serveErr != nil && serveErr != http.ErrServerClosed {
				logger.Error("tls http serve error", "error", serveErr)
			}
		}()
		go func() {
			if serveErr := tlsCmux.Serve(); serveErr != nil {
				logger.Error("tls cmux serve error", "error", serveErr)
			}
		}()
	}

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
