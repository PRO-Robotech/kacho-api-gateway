// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"crypto/tls"
	"fmt"
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
	"google.golang.org/grpc/reflection"

	// Регистрация errdetails-типов в protoregistry — иначе protojson не
	// разворачивает Any в BadRequest.FieldViolations / ResourceInfo при
	// marshalling InvalidArgument-ответов в JSON, и клиент видит только
	// "failed to marshal error message".
	_ "google.golang.org/genproto/googleapis/rpc/errdetails"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	// Обслуживается только нативный API kacho.cloud.*.

	"github.com/PRO-Robotech/kacho-api-gateway/internal/clients"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/health"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
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
	// Account/Project обслуживает kacho-iam.
	// loadbalancer заморожен — dial не выполняется. grpc.NewClient ленив:
	// фактическое соединение устанавливается при первом RPC, поэтому отсутствие
	// еще-не-задеплоенного backend не валит запуск.
	//
	// Each backend dial selects its per-edge transport creds (mTLS
	// client-cert when KACHO_API_GATEWAY_MTLS_<EDGE>_ENABLE=true + cert material
	// present, else insecure — dev backward-compat). The "operation" self-loopback
	// stays always-insecure (in-process re-entry). Fail-fast on misconfig
	// (enabled edge w/o cert material) so the process never starts half-secured.
	backends, closeBackends, err := dialBackends(cfg)
	if err != nil {
		log.Fatalf("backend dial: %v", err)
	}
	defer closeBackends()

	// --- IAM subject client (gRPC-direct к kacho-iam:9091 для LookupSubject) ---
	// InternalIAMService НЕ регистрируется в restmux (Internal* не на external),
	// поэтому subject-lookup идет напрямую через grpc.NewClient.
	// Это ребро gateway→iam → те же MTLS_IAM_ENABLE creds, что и у iam
	// backend conns. Fail-fast on misconfig.
	iamSubjectCreds, err := iamEdgeDialCreds(cfg, cfg.IAMInternalAddr)
	if err != nil {
		log.Fatalf("iam subject mTLS creds: %v", err)
	}
	iamSubjectClient, err := clients.NewIAMSubjectClient(cfg.IAMInternalAddr, logger, iamSubjectCreds)
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

	// Kratos session-based auth для SPA (cookie ory_kratos_session).
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

	// --- Hydra JWKS verifier wired into the principal-setting path ---
	//
	// The same JWTVerifier is the authoritative validator for Hydra-issued
	// RS256 access JWTs. It is constructed here (independent of the DPoP
	// feature flag) and wired into the AuthInterceptor so a real login token
	// authenticates on the principal path.
	// The DPoP middleware (below) reuses the SAME instance when enabled.
	//
	// Construction failure (e.g. empty resolved JWKS URL) is non-fatal — the
	// gateway keeps the HMAC-dev path; only the RS256/JWKS strategy is absent.
	jwtVerifier, jverr := middleware.NewJWTVerifier(middleware.JWTVerifierConfig{
		JWKSURL:          cfg.ResolvedHydraJWKSURL(),
		JWKSCacheTTL:     time.Duration(cfg.JWKSCacheTTLSeconds) * time.Second,
		JWKSFetchTimeout: time.Duration(cfg.JWKSFetchTimeoutSeconds) * time.Second,
		ExpectedIssuer:   cfg.ResolvedHydraIssuer(),
		ExpectedAudience: cfg.ExpectedAudience(),
		ClockSkew:        time.Duration(cfg.JWTClockSkewSeconds) * time.Second,
	})
	if jverr != nil {
		logger.Warn("jwks verifier not wired into principal path (HMAC-dev only)",
			"err", jverr, "jwks_url", cfg.ResolvedHydraJWKSURL())
	} else {
		authInterceptor = authInterceptor.WithVerifier(jwtVerifier)
		logger.Info("hydra jwks verifier wired into principal path",
			"jwks_url", cfg.ResolvedHydraJWKSURL(),
			"issuer", cfg.ResolvedHydraIssuer())
	}

	// Hybrid external listener: when enabled, a client that presents a
	// valid Kachō cert over the external listener (tls.VerifyClientCertIfGiven,
	// wired on the TLS listener below) authenticates on its mTLS SPIFFE identity —
	// the AuthInterceptor derives the principal from the verified cert and skips
	// the JWT requirement. Default off ⇒ JWT-only authN, behaviour unchanged.
	if cfg.HybridMTLSEnabled() {
		authInterceptor = authInterceptor.WithMTLSPrincipal(true)
		logger.Info("hybrid mTLS external listener: cert-principal path enabled")
	}

	logger.Info("auth-interceptor configured",
		"mode", cfg.AuthNMode,
		"iam_internal_addr", cfg.IAMInternalAddr,
		"dev_secret_set", cfg.AuthNDevSecret != "",
		"jwks_verifier_set", jverr == nil)

	// --- DPoP / JWT verifier / mTLS-bound / step-up gate ---
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
		// Reuse the SAME verifier instance already wired into the
		// AuthInterceptor (single JWKS cache, one source of truth). If its
		// construction failed above, DPoP cannot run either — fail-fast.
		if jverr != nil {
			log.Fatalf("jwt verifier (required by DPoP): %v", jverr)
		}
		verifier := jwtVerifier
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

	// --- logout handler ---
	logoutHandler, lerr := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:          logger,
		Revocations:     clients.NewSessionRevocationsAdapter(backends["iamInternal"]),
		HydraAdminURL:   cfg.ResolvedHydraAdminURL(),
		HookSharedToken: cfg.HookSharedSecret,
	})
	if lerr != nil {
		log.Fatalf("logout handler: %v", lerr)
	}

	// --- AuthZ middleware (per-RPC enforcement) ---
	//
	// Pipeline order (after DPoP/JWT/mTLS/step-up):
	//   DPoP → JWT → mTLS-bound → Step-up → AUTHZ → handler
	//
	// All wiring is feature-gated by KACHO_API_GATEWAY_AUTHZ_ENABLED.
	// When false the middleware mounts as a no-op pass-through.
	var authzMW *middleware.AuthzMiddleware
	{
		// Refuse to start if authz is disabled or fail-open in
		// any production-class environment (prod / production / staging). The
		// KACHO_APP_ENV signal is emitted from the helm overlay via extraEnv
		// (see kacho-deploy values.prod.yaml). Non-prod envs are tolerated and
		// surfaced via the WARN log below.
		appEnv := os.Getenv("KACHO_APP_ENV")
		if vErr := validateProductionAuthzConfig(appEnv, AuthzMiddlewareConfig{
			Enabled:   cfg.AuthZEnabled,
			FailOpen:  cfg.AuthZFailOpen,
			AuthNMode: cfg.AuthNMode,
		}); vErr != nil {
			log.Fatalf("authz config startup-validation: %v", vErr)
		}
		// In non-prod envs surface relaxed config as a structured warning so
		// operators see it in pod logs without grepping env-vars manually.
		switch appEnv {
		case "", "dev", "local":
			if !cfg.AuthZEnabled || cfg.AuthZFailOpen {
				logger.Warn("authz config relaxed for non-prod env",
					"env", appEnv,
					"enabled", cfg.AuthZEnabled,
					"fail_open", cfg.AuthZFailOpen,
				)
			}
		}

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
				"app_env", appEnv,
				"catalog_override_file", cfg.AuthZPermissionCatalogFile,
				"overrides_file", cfg.AuthZOverridesFile,
				"trusted_xff", cfg.AuthZTrustedXForwardedFor,
			)
		} else {
			logger.Info("authz-mw disabled (set KACHO_API_GATEWAY_AUTHZ_ENABLED=true to enable)")
		}
	}

	// --- subject-change poll-loop for cross-replica authz cache invalidation ---
	// Runs only when authz is enabled (authzMW != nil covers both enabled and
	// disabled — InvalidateCache is nil-safe, but polling is pointless when the
	// cache is a no-op). Gate on cfg.AuthZEnabled to avoid spurious IAM polling
	// in environments without authz.
	if authzMW != nil {
		scPoller := clients.NewSubjectChangePoller(backends["iamInternal"])
		scWatcher := watcher.New(scPoller, authzMW.InvalidateCache,
			cfg.SubjectChangePollInterval, logger)
		// The watcher is poll-only with no shutdown cleanup; it exits when ctx is
		// cancelled (SIGTERM/SIGINT). No WaitGroup join needed — nothing to flush on exit.
		go scWatcher.Run(ctx)
		logger.Info("subject-change watcher started",
			"interval", cfg.SubjectChangePollInterval)
	}

	// --- gRPC server ---
	// Resolver handles native kacho.cloud.* — performs allowlist + domain
	// routing.
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
	// минуя transparent-proxy routing (server.go Resolver).
	opsProxy := opsproxy.New(backends)
	operationpb.RegisterOperationServiceServer(grpcSrv, opsProxy)

	// proxy.Resolver маршрутизирует только нативные kacho.cloud.* сервисы;
	// advertised endpoint в роутинге не участвует.
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
	// REST listener.
	restAddrs := cfg.BackendAddrs()
	// The REST-mux is a SEPARATE proxy-path from the gRPC routing — it dials each
	// backend itself. It threads the SAME per-edge dial creds the gRPC routing /
	// authz use (mTLS client-cert + per-backend ServerName when the edge is
	// enabled, else insecure) so backends requiring a verified client-cert do not
	// reset the UI REST calls. Fail-fast on misconfig — never start half-secured.
	restDialCreds, err := buildBackendDialCreds(cfg)
	if err != nil {
		log.Fatalf("rest mux backend dial creds: %v", err)
	}
	restHandler, err := restmux.NewMux(ctx, restAddrs, backends, restDialCreds)
	if err != nil {
		log.Fatalf("rest mux: %v", err)
	}

	// --- HTTP mux с health endpoints ---
	// Critical backends: iam фронтит authN+authZ на каждом запросе, без него
	// gateway не обслуживает аутентифицированный трафик → его недоступность валит
	// readiness. Прочие backends (vpc/compute/geo/nlb) — деградация одного домена,
	// реплика остается в rotation (см. health.HTTPReadyz).
	criticalBackends := map[string]bool{"iam": true, "iamInternal": true}
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", health.HTTPHealthz)
	httpMux.Handle("/readyz", health.HTTPReadyz(backends, criticalBackends, logger))

	// OIDC login/callback/me/logout.
	// Регистрируется ДО `/` чтобы перебить grpc-gateway catch-all.
	oidcHandler := middleware.NewOIDCHandler(middleware.OIDCConfig{
		Issuer:         os.Getenv("KACHO_API_GATEWAY_OIDC_ISSUER"),
		ExternalIssuer: os.Getenv("KACHO_API_GATEWAY_OIDC_EXTERNAL_ISSUER"),
		ClientID:       os.Getenv("KACHO_API_GATEWAY_OIDC_CLIENT_ID"),
		ClientSecret:   os.Getenv("KACHO_API_GATEWAY_OIDC_CLIENT_SECRET"),
		RedirectURI:    os.Getenv("KACHO_API_GATEWAY_OIDC_REDIRECT_URI"),
		Disabled:       os.Getenv("KACHO_API_GATEWAY_OIDC_ISSUER") == "",
	}, logger)
	// /me читает Kratos session если есть cookie ory_kratos_session.
	if kratosURL != "disabled" {
		oidcHandler = oidcHandler.WithKratos(middleware.NewKratosClient(kratosURL), iamSubjectClient).
			WithAdminChecker(iamSubjectClient) // permissions = ["*","admin"] для system-admin
	}
	oidcHandler.Register(httpMux)

	// POST /oauth/logout — RFC 7009 token revocation +
	// best-effort Hydra session-kill (triggers RFC 8254 back-channel logout
	// to registered SPs).
	httpMux.Handle("/oauth/logout", logoutHandler)

	httpMux.Handle("/", restHandler)

	// Idempotency-Key store: in-memory, bounded, с TTL.
	idempStore := middleware.NewIdempotencyStore(middleware.IdempotencyTTL)

	// Build the HTTP chain. The DPoP middleware sits between the
	// legacy auth-interceptor and the access-log: legacy fills principal
	// from Kratos / dev-HMAC if present; DPoP middleware fills it from a
	// verified Hydra JWT if present. Anonymous requests pass through both
	// unless production-strict.
	//
	// AuthZ: the authz middleware mounts AFTER DPoP — by then
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
		// SECURITY: the SAME httpSrv serves both
		// the cluster-internal listener and the advertised external TLS listener.
		// ConnContext tags requests whose connection was accepted on the external
		// listener (wrapped with listenerorigin.ExternalListener below) so the REST
		// dispatcher / authz middleware can reject Internal* paths arriving from the
		// edge. Internal-listener connections pass through unmarked.
		ConnContext: listenerorigin.ExternalConnContext,
	}

	// --- internal-only gRPC listener for InternalAuthzCacheService ---
	//
	// Dedicated listener on KACHO_API_GATEWAY_INTERNAL_GRPC_ADDR (default :9091)
	// for cluster-internal RPCs that MUST NOT be on the external TLS endpoint.
	// iam's subject_change push-drainer
	// dials this listener to invoke InvalidateSubject within ~1s of revoke;
	// without it, the 30s subject-change poll-loop is the only convergence path.
	//
	// Wiring is unconditional — listener is always up. When authz is disabled
	// (cfg.AuthZEnabled=false), authzMW.AsInvalidator() returns a nopAuthzInvalidator
	// and the handler returns NotFound on every InvalidateSubject (idempotent
	// miss; drainer marks the row as already applied).
	internalGRPCAddr := os.Getenv("KACHO_API_GATEWAY_INTERNAL_GRPC_ADDR")
	if internalGRPCAddr == "" {
		internalGRPCAddr = ":9091"
	}
	internalGrpcSrv, internalLis, ierr := startInternalGRPCListener(
		internalGRPCAddr, authzMW.AsInvalidator(), grpcSrv, logger)
	if ierr != nil {
		log.Fatalf("internal grpc listener: %v", ierr)
	}
	defer func() { _ = internalLis.Close() }()
	go func() {
		serveErr := internalGrpcSrv.Serve(internalLis)
		// An unexpected death of the internal listener silently disables iam's
		// push cache-invalidation; surface it and bring the process down so the
		// orchestrator restarts a healthy replica (readiness alone can't see it).
		if serveErr != nil && serveErr != grpc.ErrServerStopped && ctx.Err() == nil {
			logger.Error("internal grpc listener died; shutting down", "error", serveErr)
			cancel()
		}
	}()

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
	// Все остальное → HTTP listener (grpc-gateway + healthz/readyz)
	httpL := cmuxer.Match(cmux.Any())

	go func() {
		serveErr := grpcSrv.Serve(grpcL)
		if serveErr != nil && serveErr != grpc.ErrServerStopped && ctx.Err() == nil {
			logger.Error("grpc listener died; shutting down", "error", serveErr)
			cancel()
		}
	}()

	go func() {
		serveErr := httpSrv.Serve(httpL)
		if serveErr != nil && serveErr != http.ErrServerClosed && ctx.Err() == nil {
			logger.Error("http listener died; shutting down", "error", serveErr)
			cancel()
		}
	}()

	// --- TLS listener (опционально) для TLS-клиентов ---
	// Запускаем отдельный TLS-листенер; за ним — отдельный cmux, который точно так же
	// разделяет gRPC vs HTTP/REST после TLS-handshake. Тот же grpcSrv и httpSrv обслуживают
	// connections (через два независимых serve goroutine).
	var (
		tlsCmux     cmux.CMux
		tlsListener net.Listener
	)
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
		// Hybrid: when enabled, accept an OPTIONAL client cert
		// (tls.VerifyClientCertIfGiven) with the internal CA as ClientCAs — a
		// browser without a cert still handshakes (JWT path), a client presenting a
		// valid Kachō cert gets it verified so the principal can be derived from its
		// SPIFFE SAN. Default (disabled) leaves ClientAuth=NoClientCert. This is the
		// EXTERNAL listener only; internal service listeners stay strict.
		if tlsCfg, certErr = cfg.ExternalListenerClientAuth(tlsCfg); certErr != nil {
			log.Fatalf("hybrid mTLS external listener: %v", certErr)
		}
		if cfg.HybridMTLSEnabled() {
			logger.Info("api-gateway external listener: optional client-cert (VerifyClientCertIfGiven) enabled")
		}
		var tlsErr error
		tlsListener, tlsErr = tls.Listen("tcp", cfg.TLSListenAddr, tlsCfg)
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
			serveErr := grpcSrv.Serve(tlsGrpcL)
			if serveErr != nil && serveErr != grpc.ErrServerStopped && ctx.Err() == nil {
				logger.Error("tls grpc listener died; shutting down", "error", serveErr)
				cancel()
			}
		}()
		// SECURITY: wrap the EXTERNAL TLS HTTP
		// sub-listener so every connection ConnContext receives is tagged external
		// origin (listenerorigin.ExternalConnContext). The REST dispatcher then 404s
		// Internal* paths arriving here; the cluster-internal listener (plain httpL)
		// stays unmarked and keeps serving Internal* to UI / admin / port-forward.
		externalTLSHTTPL := listenerorigin.ExternalListener(tlsHTTPL)
		go func() {
			serveErr := httpSrv.Serve(externalTLSHTTPL)
			if serveErr != nil && serveErr != http.ErrServerClosed && ctx.Err() == nil {
				logger.Error("tls http listener died; shutting down", "error", serveErr)
				cancel()
			}
		}()
		go func() {
			serveErr := tlsCmux.Serve()
			if serveErr != nil && ctx.Err() == nil {
				logger.Error("tls cmux died; shutting down", "error", serveErr)
				cancel()
			}
		}()
	}

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		// Bound GracefulStop by the grace window, then force Stop(): a long-lived
		// proxied stream must not block exit until the kubelet sends SIGKILL.
		// The internal listener drains in-flight iam drainer InvalidateSubject RPCs.
		stopGraceful(grpcSrv, 10*time.Second)
		stopGraceful(internalGrpcSrv, 10*time.Second)
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
		// Close the accept listeners so cmuxer.Serve()/tlsCmux.Serve() return and
		// main() exits instead of blocking until the kubelet sends SIGKILL.
		_ = listener.Close()
		if tlsListener != nil {
			_ = tlsListener.Close()
		}
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

// stopGraceful runs GracefulStop bounded by timeout, then forces Stop() — so a
// long-lived proxied stream cannot block process shutdown past the grace window.
func stopGraceful(s *grpc.Server, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		s.Stop()
	}
}

// buildAuthzMiddleware constructs the AuthZ middleware from
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

	// iam-authorize is the gateway→iam edge → mTLS under MTLS_IAM_ENABLE
	// (same edge as iam-subject + iam backend conns). Fail-fast on
	// misconfig (enabled without cert material) — never a silent insecure fallback.
	authorizeAddr := cfg.ResolvedIAMAuthorizeURL()
	authorizeCreds, err := iamEdgeDialCreds(cfg, authorizeAddr)
	if err != nil {
		return nil, fmt.Errorf("iam authorize mTLS creds: %w", err)
	}
	authzClient, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:           authorizeAddr,
		Timeout:        time.Duration(cfg.AuthZCheckTimeoutMs) * time.Millisecond,
		Logger:         logger,
		TransportCreds: authorizeCreds,
	})
	if err != nil {
		return nil, err
	}

	// Build the REST<->gRPC route table so the authz
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
