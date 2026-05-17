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

	endpointpb "github.com/PRO-Robotech/kacho-yc-shim/gen/go/yandex/cloud/endpoint"
	iampb "github.com/PRO-Robotech/kacho-yc-shim/gen/go/yandex/cloud/iam/v1"
	shimendpoint "github.com/PRO-Robotech/kacho-yc-shim/endpoint"
	shimiam "github.com/PRO-Robotech/kacho-yc-shim/iam"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/clients"
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
	// Активные backends: resource-manager + vpc + compute (+ их internal-порты).
	// loadbalancer заморожен — dial не выполняется. grpc.NewClient ленив:
	// фактическое соединение устанавливается при первом RPC, поэтому отсутствие
	// ещё-не-задеплоенного backend не валит запуск.
	keepaliveParams := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepaliveParams),
		// Client-side round-robin across all backend pods. Combined with `dns:///`
		// scheme on the dial target (or a Headless Service) this opens one subconn
		// per backend Pod IP and distributes RPCs across them — vs the default
		// pick_first which pins to one Pod per ClusterIP forever.
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
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

	// Self-loopback ClientConn for the "operation" domain. Requests for
	// /kacho.cloud.operation.OperationService/* arrive natively (registered
	// below) and are dispatched directly to OpsProxy. But yc CLI sends
	// /yandex.cloud.operation.OperationService/* — that path is NOT registered
	// natively, so it hits the UnknownServiceHandler, which rewrites it to
	// /kacho.cloud.operation.OperationService/* and looks up backend by domain
	// "operation". This loopback satisfies the lookup; the connection re-enters
	// the gateway through the listening port and matches the natively-registered
	// kacho.cloud.operation.OperationService.
	loopbackAddr := cfg.ListenAddr
	if len(loopbackAddr) > 0 && loopbackAddr[0] == ':' {
		loopbackAddr = "127.0.0.1" + loopbackAddr
	}
	opsLoopback, dialErr := grpc.NewClient(loopbackAddr, dialOpts...)
	if dialErr != nil {
		log.Fatalf("dial operation self-loopback (%s): %v", loopbackAddr, dialErr)
	}
	defer opsLoopback.Close()
	backends["operation"] = opsLoopback

	// --- IAM subject client (gRPC-direct к kacho-iam:9091 для LookupSubject; KAC-107 E2) ---
	// Loop-prevention запрет #6: InternalIAMService НЕ регистрируется в restmux,
	// поэтому subject-lookup идёт напрямую через grpc.NewClient.
	iamSubjectClient, err := clients.NewIAMSubjectClient(cfg.IAMInternalAddr, logger)
	if err != nil {
		log.Fatalf("iam subject client: %v", err)
	}
	defer func() { _ = iamSubjectClient.Close() }()

	authInterceptor := middleware.NewAuthInterceptor(
		middleware.AuthMode(cfg.AuthNMode),
		cfg.AuthNDevSecret,
		iamSubjectClient,
		logger,
	)
	logger.Info("auth-interceptor configured",
		"mode", cfg.AuthNMode,
		"iam_internal_addr", cfg.IAMInternalAddr,
		"dev_secret_set", cfg.AuthNDevSecret != "")

	// --- gRPC server ---
	// Resolver handles both native kacho.cloud.* and yandex.cloud.* (yc CLI compat
	// shim, kacho-yc-shim repo) — performs path rewrite + allowlist + domain routing.
	resolver := proxy.Resolver(backends)
	grpcSrv := proxy.NewServer(resolver,
		grpc.ChainUnaryInterceptor(
			middleware.UnaryRequestID,
			middleware.UnaryRecovery(logger),
			authInterceptor.Unary(),
			middleware.UnaryAccessLog(logger),
		),
		grpc.ChainStreamInterceptor(
			middleware.StreamRequestID,
			middleware.StreamRecovery(logger),
			authInterceptor.Stream(),
			middleware.StreamAccessLog(logger),
		),
	)
	health.RegisterGRPCHealth(grpcSrv, backends)

	// OpsProxy регистрируется как нативный gRPC-сервис в gateway-сервере.
	// Запросы /kacho.cloud.operation.OperationService/* идут напрямую сюда,
	// минуя transparent-proxy director.
	opsProxy := opsproxy.New(backends)
	operationpb.RegisterOperationServiceServer(grpcSrv, opsProxy)

	// yc CLI compatibility shim (kacho-yc-shim repo): register
	// yandex.cloud.endpoint.ApiEndpointService for service discovery and
	// yandex.cloud.iam.v1.IamTokenService for OAuth-token exchange. The shim
	// uses the yandex.cloud.* proto namespace (isolated to that one repo); all
	// other yandex.cloud.* calls are method-rewritten to kacho.cloud.* by the
	// unknown-service handler.
	advertisedEndpoint := cfg.AdvertisedEndpoint()
	endpointpb.RegisterApiEndpointServiceServer(grpcSrv, shimendpoint.New(advertisedEndpoint))
	iampb.RegisterIamTokenServiceServer(grpcSrv, shimiam.New())

	// gRPC reflection — позволяет grpcurl и совместимым CLI получить список
	// сервисов через ServerReflection. Видны только сервисы, нативно
	// зарегистрированные на api-gateway (OperationService + Health). Сервисы
	// vpc/resource-manager доступны через transparent-proxy и видны в
	// reflection их собственных backends (если включить там).
	reflection.Register(grpcSrv)

	// --- REST mux (grpc-gateway) ---
	// Регистрирует активные публичные сервисы + OperationService через OpsProxy
	// + kacho-only Internal admin-сервисы (vpc Region/Zone/AddressPool, compute
	// DiskType/Zone) на их internal-портах (9091). Internal-методы НЕ публикуются
	// на external/TLS endpoint в gRPC-проксе (allowlist + HasInternalSuffix);
	// REST-доступ к ним — только для UI / admin-tooling через cluster-internal
	// REST listener (см. workspace CLAUDE.md §запрет 6, kacho-vpc/CLAUDE.md §16).
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
			authInterceptor.HTTP(
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
