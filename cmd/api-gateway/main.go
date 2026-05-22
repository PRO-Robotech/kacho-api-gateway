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

	// KAC-122: kacho-yc-shim удалён (yc CLI compatibility deprecated).

	"github.com/PRO-Robotech/kacho-api-gateway/internal/clients"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/health"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/opsproxy"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/restmux"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/watcher"
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

	// SIGHUP — operator-driven reload signal for the permission catalog +
	// authz overrides. The signal handler is wired up after the middleware
	// is constructed (see `installAuthzSIGHUP` below).
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	// --- Backend connections: один постоянный ClientConn на backend ---
	// Активные backends: iam + vpc + compute (+ их internal-порты).
	// KAC-124: resource-manager упразднён — backend заменён на kacho-iam (Account/Project).
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

	// KAC-116: Kratos session-based auth для SPA (cookie ory_kratos_session).
	// Env KACHO_API_GATEWAY_KRATOS_PUBLIC_URL — base URL Kratos public API.
	// Default = cluster-internal kratos-public service.
	kratosURL := os.Getenv("KACHO_API_GATEWAY_KRATOS_PUBLIC_URL")
	if kratosURL == "" {
		kratosURL = "http://kacho-umbrella-kratos-public.kacho.svc.cluster.local:80"
	}
	if kratosURL != "disabled" {
		authInterceptor = authInterceptor.WithKratos(middleware.NewKratosClient(kratosURL))
		logger.Info("kratos session-auth wired", "kratos_url", kratosURL)
	} else {
		logger.Info("kratos session-auth disabled by env")
	}

	logger.Info("auth-interceptor configured",
		"mode", cfg.AuthNMode,
		"iam_internal_addr", cfg.IAMInternalAddr,
		"dev_secret_set", cfg.AuthNDevSecret != "")

	// --- KAC-127 Phase 2: DPoP / JWT verifier / mTLS-bound / step-up gate ---
	//
	// All wiring is feature-gated by KACHO_API_GATEWAY_AUTHN_ENABLE_DPOP.
	// When disabled (default) the legacy auth-interceptor path remains the only
	// authN code path. When enabled we add a second middleware after the legacy
	// one — verified Hydra-issued tokens flow through it; dev / Kratos / HMAC
	// tokens pass through unchanged (they're not in JWT alg whitelist and the
	// JWT verifier rejects them gracefully → middleware passes through as
	// anonymous when requireForAllRequests=false).
	var dpopMiddleware *middleware.DPoPMiddleware
	if cfg.AuthNEnableDPoP {
		var verifierErr error
		verifier, verifierErr := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
			JWKSURL:          cfg.ResolvedHydraJWKSURL(),
			JWKSCacheTTL:     time.Duration(cfg.JWKSCacheTTLSeconds) * time.Second,
			JWKSFetchTimeout: time.Duration(cfg.JWKSFetchTimeoutSeconds) * time.Second,
			ExpectedIssuer:   cfg.ResolvedHydraIssuer(),
			ExpectedAudience: cfg.ExpectedAudience(),
			ClockSkew:        time.Duration(cfg.JWTClockSkewSeconds) * time.Second,
		})
		if verifierErr != nil {
			log.Fatalf("jwt verifier: %v", verifierErr)
		}
		replayCache := middleware.NewDPoPReplayCache(middleware.DPoPReplayCacheConfig{
			MaxEntries: cfg.DPoPReplayCacheSize,
			TTL:        time.Duration(cfg.DPoPReplayCacheTTLSeconds) * time.Second,
		})
		dpopValidator, derr := middleware.NewDPoPValidator(middleware.DPoPValidatorConfig{
			ReplayCache:  replayCache,
			IatFreshness: time.Duration(cfg.DPoPIatFreshnessSeconds) * time.Second,
		})
		if derr != nil {
			log.Fatalf("dpop validator: %v", derr)
		}
		stepUp := middleware.NewStepUpGate(time.Now)

		var introspection *middleware.IntrospectionCache
		if cfg.ResolvedHydraIntrospectionURL() != "" {
			ic, ierr := middleware.NewIntrospectionCache(middleware.IntrospectionCacheConfig{
				HydraIntrospectionURL: cfg.ResolvedHydraIntrospectionURL(),
				MaxEntries:            cfg.IntrospectionCacheSize,
				TTL:                   time.Duration(cfg.IntrospectionCacheTTLSeconds) * time.Second,
			})
			if ierr != nil {
				log.Fatalf("introspection cache: %v", ierr)
			}
			introspection = ic
		}

		dpopMiddleware, verifierErr = middleware.NewDPoPMiddleware(middleware.DPoPMiddlewareConfig{
			Verifier:              verifier,
			DPoP:                  dpopValidator,
			MTLS:                  middleware.NewMTLSBoundValidator(),
			StepUp:                stepUp,
			Introspection:         introspection,
			Logger:                logger,
			APIDomain:             cfg.APIDomain,
			RequireForAllRequests: cfg.AuthNMode == string(middleware.AuthModeProductionStrict),
		})
		if verifierErr != nil {
			log.Fatalf("dpop middleware: %v", verifierErr)
		}
		logger.Info("dpop-mw wired",
			"api_domain", cfg.APIDomain,
			"jwks_url", cfg.ResolvedHydraJWKSURL(),
			"issuer", cfg.ResolvedHydraIssuer(),
			"audience", cfg.ExpectedAudience(),
			"introspection_enabled", introspection != nil,
		)
	} else {
		logger.Info("dpop-mw disabled (set KACHO_API_GATEWAY_AUTHN_ENABLE_DPOP=true to enable)")
	}

	// --- KAC-127 Phase 2: logout handler ---
	logoutHandler, lerr := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:          logger,
		Revocations:     clients.NewSessionRevocationsAdapter(backends["iamInternal"]),
		HydraAdminURL:   cfg.ResolvedHydraAdminURL(),
		HookSharedToken: cfg.HookSharedSecret,
	})
	if lerr != nil {
		log.Fatalf("logout handler: %v", lerr)
	}

	// --- KAC-127 Phase 3: AuthZ middleware (per-RPC enforcement) ---
	//
	// Pipeline order (after Phase 2 DPoP/JWT/mTLS/step-up):
	//   DPoP → JWT → mTLS-bound → Step-up → AUTHZ → handler
	//
	// All wiring is feature-gated by KACHO_API_GATEWAY_AUTHZ_ENABLED.
	// When false the middleware mounts as a no-op pass-through (compat
	// with Phase 1/2 dev environments).
	var authzMW *middleware.AuthzMiddleware
	{
		authzMW, err = buildAuthzMiddleware(cfg, logger)
		if err != nil {
			log.Fatalf("authz middleware: %v", err)
		}
		if cfg.AuthZEnabled {
			logger.Info("authz-mw wired",
				"iam_authorize_url", cfg.ResolvedIAMAuthorizeURL(),
				"cache_ttl_s", cfg.AuthZCacheTTLSeconds,
				"cache_max", cfg.AuthZCacheMaxEntries,
				"check_timeout_ms", cfg.AuthZCheckTimeoutMs,
				"fail_open", cfg.AuthZFailOpen,
				"catalog_override_file", cfg.AuthZPermissionCatalogFile,
				"overrides_file", cfg.AuthZOverridesFile,
				"trusted_xff", cfg.AuthZTrustedXForwardedFor,
			)
		} else {
			logger.Info("authz-mw disabled (set KACHO_API_GATEWAY_AUTHZ_ENABLED=true to enable)")
		}
	}

	// --- WS-2.3: subject-change poll-loop for cross-replica authz cache invalidation ---
	// Runs only when authz is enabled (authzMW != nil covers both enabled and
	// disabled — InvalidateCache is nil-safe, but polling is pointless when the
	// cache is a no-op). Gate on cfg.AuthZEnabled to avoid spurious IAM polling
	// in environments without authz.
	if authzMW != nil {
		scPoller := clients.NewSubjectChangePoller(backends["iamInternal"])
		scWatcher := watcher.New(scPoller, authzMW.InvalidateCache,
			cfg.SubjectChangePollInterval, logger)
		go scWatcher.Run(ctx)
		logger.Info("WS-2.3 subject-change watcher started",
			"interval", cfg.SubjectChangePollInterval)
	}

	// --- gRPC server ---
	// Resolver handles native kacho.cloud.* — performs allowlist + domain
	// routing. KAC-127: yc-CLI compat shim удалён.
	resolver := proxy.Resolver(backends)
	grpcUnaryInterceptors := []grpc.UnaryServerInterceptor{
		middleware.UnaryRequestID,
		middleware.UnaryRecovery(logger),
		authInterceptor.Unary(),
	}
	grpcStreamInterceptors := []grpc.StreamServerInterceptor{
		middleware.StreamRequestID,
		middleware.StreamRecovery(logger),
		authInterceptor.Stream(),
	}
	if authzMW != nil {
		grpcUnaryInterceptors = append(grpcUnaryInterceptors, authzMW.Unary())
		grpcStreamInterceptors = append(grpcStreamInterceptors, authzMW.Stream())
	}
	grpcUnaryInterceptors = append(grpcUnaryInterceptors, middleware.UnaryAccessLog(logger))
	grpcStreamInterceptors = append(grpcStreamInterceptors, middleware.StreamAccessLog(logger))
	grpcSrv := proxy.NewServer(resolver,
		grpc.ChainUnaryInterceptor(grpcUnaryInterceptors...),
		grpc.ChainStreamInterceptor(grpcStreamInterceptors...),
	)
	health.RegisterGRPCHealth(grpcSrv, backends)

	// OpsProxy регистрируется как нативный gRPC-сервис в gateway-сервере.
	// Запросы /kacho.cloud.operation.OperationService/* идут напрямую сюда,
	// минуя transparent-proxy director.
	opsProxy := opsproxy.New(backends)
	operationpb.RegisterOperationServiceServer(grpcSrv, opsProxy)

	// KAC-127: yandex.cloud.* path-rewrite в proxy.Resolver удалён вслед за
	// KAC-122 (kacho-yc-shim drop) — backends не expose'ят yandex-services,
	// и Native YC-services (ApiEndpoint / IamToken) не регистрируются. Если
	// в будущем понадобится yc-CLI compat, его реализует отдельный
	// `kacho-yc-shim` сервис.
	_ = cfg.AdvertisedEndpoint()

	// gRPC reflection — позволяет grpcurl и совместимым CLI получить список
	// сервисов через ServerReflection. Видны только сервисы, нативно
	// зарегистрированные на api-gateway (OperationService + Health). Сервисы
	// vpc/iam доступны через transparent-proxy и видны в reflection их
	// собственных backends (если включить там).
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

	// OIDC login/callback/me/logout (KAC-107 closeout, KAC-109 DoD #1).
	// Регистрируется ДО `/` чтобы перебить grpc-gateway catch-all.
	oidcHandler := middleware.NewOIDCHandler(middleware.OIDCConfig{
		Issuer:         os.Getenv("KACHO_API_GATEWAY_OIDC_ISSUER"),
		ExternalIssuer: os.Getenv("KACHO_API_GATEWAY_OIDC_EXTERNAL_ISSUER"),
		ClientID:       os.Getenv("KACHO_API_GATEWAY_OIDC_CLIENT_ID"),
		ClientSecret:   os.Getenv("KACHO_API_GATEWAY_OIDC_CLIENT_SECRET"),
		RedirectURI:    os.Getenv("KACHO_API_GATEWAY_OIDC_REDIRECT_URI"),
		Disabled:       os.Getenv("KACHO_API_GATEWAY_OIDC_ISSUER") == "",
	}, logger)
	// KAC-116: /me читает Kratos session если есть cookie ory_kratos_session.
	if kratosURL != "disabled" {
		oidcHandler = oidcHandler.WithKratos(middleware.NewKratosClient(kratosURL), iamSubjectClient).
			WithAdminChecker(iamSubjectClient) // KAC-123: permissions = ["*","admin"] для system-admin
	}
	oidcHandler.Register(httpMux)

	// KAC-127 Phase 2: POST /oauth/logout — RFC 7009 token revocation +
	// best-effort Hydra session-kill (triggers RFC 8254 back-channel logout
	// to registered SPs).
	httpMux.Handle("/oauth/logout", logoutHandler)

	httpMux.Handle("/", restHandler)

	// Idempotency-Key store: in-memory с TTL=24h (как в YC).
	idempStore := middleware.NewIdempotencyStore(middleware.IdempotencyTTL)

	// Build the HTTP chain. The DPoP middleware (Phase 2) sits between the
	// legacy auth-interceptor and the access-log: legacy fills principal
	// from Kratos / dev-HMAC if present; DPoP middleware fills it from a
	// verified Hydra JWT if present. Anonymous requests pass through both
	// unless production-strict.
	//
	// Phase 3 (AuthZ): the authz middleware mounts AFTER DPoP — by then
	// the request has principal-headers set; the authz layer reads them
	// to build the subject + condition context, then dispatches to
	// AuthorizeService.Check.
	var inner http.Handler = httpMux
	inner = middleware.HTTPIdempotency(idempStore)(inner)
	inner = middleware.HTTPAccessLog(logger)(inner)
	if authzMW != nil {
		inner = authzMW.HTTP(inner)
	}
	if dpopMiddleware != nil {
		inner = dpopMiddleware.Wrap(inner)
	}
	inner = authInterceptor.HTTP(inner)
	httpHandler := middleware.HTTPRequestID(
		middleware.HTTPRecovery(logger)(inner),
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

	// Drain hupCh — log + ignore so the channel doesn't fill up. Actual
	// reload wiring is per-component (catalog / overrides) via the closures
	// passed to installAuthzSIGHUP.
	go func() {
		for sig := range hupCh {
			logger.Info("SIGHUP received; reloading authz config", "signal", sig)
			// best-effort; failures keep previous-good config.
			// (No-op when authz disabled.)
		}
	}()

	if serveErr := cmuxer.Serve(); serveErr != nil {
		logger.Error("cmux serve error", "error", serveErr)
	}
}

// buildAuthzMiddleware constructs the Phase 3 AuthZ middleware from
// configuration. When AuthZEnabled=false this returns a no-op middleware
// (the caller still wires it into the chain, but it pass-through everything).
func buildAuthzMiddleware(cfg config.Config, logger *slog.Logger) (*middleware.AuthzMiddleware, error) {
	if !cfg.AuthZEnabled {
		return middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{
			Enabled: false,
			Logger:  logger,
		})
	}

	catalog, err := middleware.LoadEmbeddedPermissionCatalog(cfg.AuthZPermissionCatalogFile)
	if err != nil {
		return nil, err
	}

	overrides := middleware.NewAuthzOverrides()
	if cfg.AuthZOverridesFile != "" {
		if oerr := overrides.LoadFromFile(cfg.AuthZOverridesFile); oerr != nil {
			// Reload-failures on first start are fatal — we have no prior
			// good state to fall back to.
			return nil, oerr
		}
	}

	authzClient, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:    cfg.ResolvedIAMAuthorizeURL(),
		Timeout: time.Duration(cfg.AuthZCheckTimeoutMs) * time.Millisecond,
		Logger:  logger,
	})
	if err != nil {
		return nil, err
	}

	// KAC-127 Problem 1: build the REST<->gRPC route table so the authz
	// middleware can resolve an incoming REST path to a gRPC FQN (and the
	// catalog entry). Also feeds the ResourceExtractor's HTTP path strategy
	// with FQN -> path-template mappings to pluck `{field}` scope ids.
	restRouter := middleware.NewRestRouter()

	return middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{
		Enabled:         true,
		FailOpen:        cfg.AuthZFailOpen,
		Catalog:         catalog,
		Subjects:        middleware.NewSubjectExtractor(true),
		Context:         middleware.NewContextExtractor(time.Now, cfg.AuthZTrustedXForwardedFor),
		Resources:       middleware.NewResourceExtractor(restRouter.PathTemplates()),
		Checker:         clients.NewAuthzChecker(authzClient),
		Overrides:       overrides,
		Logger:          logger,
		Now:             time.Now,
		CacheTTL:        time.Duration(cfg.AuthZCacheTTLSeconds) * time.Second,
		CacheMaxEntries: cfg.AuthZCacheMaxEntries,
		PublicAllowlist: middleware.DefaultPublicAllowlist(),
		RestRouter:      restRouter,
	})
}
