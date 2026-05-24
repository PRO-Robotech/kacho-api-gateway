package config

import (
	"time"

	corecfg "github.com/PRO-Robotech/kacho-corelib/config"
)

// Config хранит конфигурацию api-gateway.
// Переменные окружения:
//
//	KACHO_API_GATEWAY_LISTEN_ADDR         — адрес для cmux listener (default: :8080)
//	KACHO_API_GATEWAY_TLS_LISTEN_ADDR     — адрес для TLS listener (default: пусто — TLS отключён)
//	KACHO_API_GATEWAY_TLS_CERT_FILE       — путь к TLS-сертификату (PEM)
//	KACHO_API_GATEWAY_TLS_KEY_FILE        — путь к TLS-приватному ключу (PEM)
//	KACHO_API_GATEWAY_VPC_GRPC            — адрес backend vpc
//	KACHO_API_GATEWAY_COMPUTE_GRPC        — адрес backend compute (public, port 9090)
//	KACHO_API_GATEWAY_COMPUTE_INTERNAL_GRPC — адрес backend compute internal-port (9091)
//	KACHO_API_GATEWAY_IAM_GRPC            — адрес backend iam (public, port 9090)
//	KACHO_API_GATEWAY_IAM_INTERNAL_GRPC   — адрес backend iam internal-port (9091)
//	KACHO_API_GATEWAY_NLB_GRPC            — адрес backend kacho-nlb (public, port 9090) (KAC-161)
//	KACHO_API_GATEWAY_NLB_INTERNAL_GRPC   — адрес backend kacho-nlb internal-port (9091) (KAC-161)
//
// TLS требуется для совместимости с CLI-клиентами (yc CLI hardcoded требует TLS).
// Когда TLS_LISTEN_ADDR пустой — TLS не запускается; plain-cmux на ListenAddr.
//
// KAC-161: loadbalancer активирован (kacho-nlb) — env vars добавлены ниже.
type Config struct {
	ListenAddr    string `envconfig:"KACHO_API_GATEWAY_LISTEN_ADDR"          default:":8080"`
	TLSListenAddr string `envconfig:"KACHO_API_GATEWAY_TLS_LISTEN_ADDR"      default:""`
	TLSCertFile   string `envconfig:"KACHO_API_GATEWAY_TLS_CERT_FILE"        default:""`
	TLSKeyFile    string `envconfig:"KACHO_API_GATEWAY_TLS_KEY_FILE"         default:""`
	// KAC-124/127: ResourceManagerAddr удалён — kacho-resource-manager заменён на kacho-iam.
	VPCAddr string `envconfig:"KACHO_API_GATEWAY_VPC_GRPC"              default:"vpc.kacho.svc.cluster.local:9090"`
	// VPCInternalAddr — admin-only internal-port (9091) of vpc backend.
	// Routes Region/Zone/AddressPool RESTful endpoints (kacho-only, NOT YC-verbatim).
	VPCInternalAddr string `envconfig:"KACHO_API_GATEWAY_VPC_INTERNAL_GRPC" default:"vpc.kacho.svc.cluster.local:9091"`
	// ComputeAddr — public gRPC backend of kacho-compute (Disk/Image/Snapshot/Instance/DiskType/Zone).
	ComputeAddr string `envconfig:"KACHO_API_GATEWAY_COMPUTE_GRPC" default:"compute.kacho.svc.cluster.local:9090"`
	// ComputeInternalAddr — admin-only internal-port (9091) of compute backend.
	// Routes InternalDiskType/InternalZone RESTful endpoints (kacho-only, NOT YC-verbatim).
	ComputeInternalAddr string `envconfig:"KACHO_API_GATEWAY_COMPUTE_INTERNAL_GRPC" default:"compute.kacho.svc.cluster.local:9091"`
	// IAMAddr — public gRPC backend of kacho-iam (Account/Project/User/ServiceAccount/Group/Role/AccessBinding).
	// Все RPC под /iam/v1/* (KAC-105, E0).
	IAMAddr string `envconfig:"KACHO_API_GATEWAY_IAM_GRPC" default:"iam.kacho.svc.cluster.local:9090"`
	// IAMInternalAddr — admin-only internal-port (9091) of iam backend.
	// E0: InternalUserService.Get для admin tooling (gRPC-direct; REST-routing no-op,
	// proto-аннотации `google.api.http` отсутствуют — handler регистрируется в mux
	// pro-forma, реальный трафик идёт по gRPC).
	// E2: добавится REST для InternalUserService.UpsertFromIdentity (OIDC-callback).
	// InternalIAMService.LookupSubject/ListPermissions — НЕ регистрируется в REST
	// (auth-interceptor zвонит kacho-iam:9091 напрямую через grpc-client).
	IAMInternalAddr string `envconfig:"KACHO_API_GATEWAY_IAM_INTERNAL_GRPC" default:"iam.kacho.svc.cluster.local:9091"`

	// NLBAddr — public gRPC backend of kacho-nlb (NetworkLoadBalancer/Listener/TargetGroup).
	// Public RPC под /nlb/v1/* (KAC-161). При пустом значении nlb-handlers не
	// регистрируются (graceful — позволяет деплоить api-gateway до kacho-nlb pod'a).
	NLBAddr string `envconfig:"KACHO_API_GATEWAY_NLB_GRPC" default:"kacho-nlb.kacho.svc.cluster.local:9090"`

	// NLBInternalAddr — admin-only internal-port (9091) of kacho-nlb backend.
	// InternalResourceLifecycleService.Subscribe — gRPC server-streaming для
	// подписки на CREATED/UPDATED/DELETED события (data-plane consumer'ы дозваниваются
	// напрямую). Регистрируется в REST mux pro-forma (как iam InternalUserService),
	// реальный трафик идёт через gRPC-direct. См. workspace CLAUDE.md §запрет #6.
	NLBInternalAddr string `envconfig:"KACHO_API_GATEWAY_NLB_INTERNAL_GRPC" default:"kacho-nlb.kacho.svc.cluster.local:9091"`

	// AdvertisedEndpointAddr — host:port that the api-gateway advertises in
	// the yc CLI compatibility shim (yandex.cloud.endpoint.ApiEndpointService).
	// External clients dial this address. Defaults to api.kacho.local:443.
	AdvertisedEndpointAddr string `envconfig:"KACHO_API_GATEWAY_ADVERTISED_ENDPOINT" default:"api.kacho.local:443"`

	// AuthNMode — режим auth-interceptor (KAC-107 E2):
	//   - "dev" (default): backwards-compat. Без Bearer = anonymous; невалидный
	//     Bearer = fallback anonymous. С валидным Bearer + subject в kacho-iam =
	//     real Principal.
	//   - "production": Bearer обязателен. Невалидный или unknown subject =
	//     Unauthenticated.
	//   - "production-strict": то же что production + reject missing Bearer.
	AuthNMode string `envconfig:"KACHO_API_GATEWAY_AUTHN_MODE" default:"dev"`

	// AuthNDevSecret — HMAC-secret для подписи dev-JWT (mode=dev).
	// Если пуст — Bearer-токены в dev-режиме игнорируются (всегда anonymous).
	// Production / production-strict — нужен Hydra JWKS (см. KAC-127 Phase 2).
	AuthNDevSecret string `envconfig:"KACHO_API_GATEWAY_AUTHN_DEV_SECRET" default:""`

	// --- KAC-127 Phase 2: AuthN core (DPoP / JWT / mTLS-bound / step-up / BCL) ---

	// APIDomain — публичный домен kacho-api (используется для построения canonical
	// `htu` в DPoP-валидации и для resolve issuer/audience). НЕ хардкод. Default
	// меняется в production helm-values.
	APIDomain string `envconfig:"KACHO_API_DOMAIN" default:"api.kacho.cloud"`

	// HydraIssuer — issuer URL Ory Hydra; используется как expected `iss` в
	// access tokens + base URL для JWKS fetch (`{HydraIssuer}/.well-known/jwks.json`).
	// Пустой → derived as `https://hydra.{APIDomain}`.
	HydraIssuer string `envconfig:"KACHO_HYDRA_ISSUER" default:""`

	// HydraJWKSURL — explicit JWKS endpoint; пустой → derived from HydraIssuer.
	HydraJWKSURL string `envconfig:"KACHO_HYDRA_JWKS_URL" default:""`

	// HydraIntrospectionURL — explicit Hydra introspection endpoint (admin API);
	// пустой → derived as `{HydraIssuer}/oauth2/introspect`.
	HydraIntrospectionURL string `envconfig:"KACHO_HYDRA_INTROSPECTION_URL" default:""`

	// HydraAdminURL — explicit Hydra admin API base URL (used by logout handler
	// to revoke sessions via `DELETE /admin/oauth2/auth/sessions/login`); пустой
	// → derived from HydraIssuer.
	HydraAdminURL string `envconfig:"KACHO_HYDRA_ADMIN_URL" default:""`

	// JWKSCacheTTL — TTL для JWKS cache (sec); RFC рекомендация 5–60 min.
	JWKSCacheTTLSeconds int `envconfig:"KACHO_JWKS_CACHE_TTL_SECONDS" default:"300"`

	// JWKSFetchTimeout — таймаут на single JWKS fetch (sec).
	JWKSFetchTimeoutSeconds int `envconfig:"KACHO_JWKS_FETCH_TIMEOUT_SECONDS" default:"5"`

	// DPoPReplayCacheSize — LRU capacity для DPoP-replay (entries).
	DPoPReplayCacheSize int `envconfig:"KACHO_DPOP_REPLAY_CACHE_SIZE" default:"100000"`

	// DPoPReplayCacheTTLSeconds — TTL для DPoP-replay entries (sec). Должен быть
	// ≥ 2× iat-freshness-window (60s × 2 = 120s default).
	DPoPReplayCacheTTLSeconds int `envconfig:"KACHO_DPOP_REPLAY_CACHE_TTL_SECONDS" default:"120"`

	// DPoPIatFreshnessSeconds — допустимое отклонение DPoP `iat` от now() (sec).
	// RFC 9449 рекомендация 60s.
	DPoPIatFreshnessSeconds int `envconfig:"KACHO_DPOP_IAT_FRESHNESS_SECONDS" default:"60"`

	// JWTClockSkewSeconds — допустимый clock skew для JWT `exp`/`nbf` (sec).
	JWTClockSkewSeconds int `envconfig:"KACHO_JWT_CLOCK_SKEW_SECONDS" default:"30"`

	// IntrospectionCacheTTLSeconds — TTL для introspection-cache entries (sec).
	IntrospectionCacheTTLSeconds int `envconfig:"KACHO_INTROSPECTION_CACHE_TTL_SECONDS" default:"5"`

	// IntrospectionCacheSize — LRU capacity для introspection cache (entries).
	IntrospectionCacheSize int `envconfig:"KACHO_INTROSPECTION_CACHE_SIZE" default:"10000"`

	// HookSharedSecret — shared secret для Hydra→kacho-iam back-channel logout
	// (RFC 8254). Также используется как HMAC для CAEP push payload integrity.
	HookSharedSecret string `envconfig:"KACHO_IAM_HOOK_TOKEN" default:""`

	// AuthNEnableDPoP — feature toggle; true → требовать DPoP/mTLS-bound для
	// tokens с `cnf` claim, валидировать. False → skip DPoP проверки (legacy
	// dev mode без sender-constrained tokens).
	AuthNEnableDPoP bool `envconfig:"KACHO_API_GATEWAY_AUTHN_ENABLE_DPOP" default:"false"`

	// --- KAC-127 Phase 3: AuthZ core (per-RPC enforcement) ---

	// AuthZEnabled — master toggle for the per-RPC AuthZ middleware. When
	// false (default), the middleware mounts as a pass-through (compat with
	// Phase 1/2 dev environments without OpenFGA/IAM AuthorizeService).
	AuthZEnabled bool `envconfig:"KACHO_API_GATEWAY_AUTHZ_ENABLED" default:"false"`

	// AuthZFailOpen — when true, transient IAM-Check failures (Unavailable
	// / DeadlineExceeded) PASS the request through (logged ERROR). Default
	// false (fail-closed); only flip to true in dev / staging emergencies.
	AuthZFailOpen bool `envconfig:"KACHO_API_GATEWAY_AUTHZ_FAIL_OPEN" default:"false"`

	// IAMAuthorizeURL — gRPC address of kacho-iam AuthorizeService. Empty
	// → derives from IAMAddr (public iam endpoint, port 9090). Spec'd as
	// a separate env so operators can split AuthorizeService onto its own
	// pod (Phase 4 HA target).
	IAMAuthorizeURL string `envconfig:"KACHO_API_GATEWAY_IAM_AUTHORIZE_URL" default:""`

	// AuthZCacheTTLSeconds — decision-cache TTL (sec). Default 5s.
	AuthZCacheTTLSeconds int `envconfig:"KACHO_API_GATEWAY_AUTHZ_CACHE_TTL_SECONDS" default:"5"`

	// AuthZCacheMaxEntries — LRU cap. Default 10000.
	AuthZCacheMaxEntries int `envconfig:"KACHO_API_GATEWAY_AUTHZ_CACHE_MAX_ENTRIES" default:"10000"`

	// AuthZCheckTimeoutMs — hard timeout per AuthorizeService.Check (ms).
	// Default 200ms (impl brief).
	AuthZCheckTimeoutMs int `envconfig:"KACHO_API_GATEWAY_AUTHZ_CHECK_TIMEOUT_MS" default:"200"`

	// AuthZPermissionCatalogFile — runtime override path for the catalog
	// JSON. Empty → use the embedded asset (build-time pinned). ConfigMap
	// mounts go here; SIGHUP triggers reload.
	AuthZPermissionCatalogFile string `envconfig:"KACHO_API_GATEWAY_PERMISSION_CATALOG_FILE" default:""`

	// AuthZOverridesFile — file-based per-route overrides (allow/deny).
	// Empty → no overrides. SIGHUP reload.
	AuthZOverridesFile string `envconfig:"KACHO_API_GATEWAY_AUTHZ_OVERRIDES_FILE" default:""`

	// AuthZTrustedXForwardedFor — honour X-Forwarded-For / X-Real-IP when
	// computing the `client_ip` Condition context value. True for typical
	// k8s ingress topology (api-gateway sits behind an L7 LB that strips
	// client-supplied values). Flip to false when running api-gateway
	// directly on the wire.
	AuthZTrustedXForwardedFor bool `envconfig:"KACHO_API_GATEWAY_AUTHZ_TRUSTED_XFF" default:"true"`

	// SubjectChangePollInterval — how often the WS-2.3 subject-change watcher
	// polls kacho-iam InternalIAMService.PollSubjectChanges to flush the authz
	// decision cache on sibling replicas that did not process the mutation.
	// Default 2s. Omit the env var (or set 0) to use the built-in default.
	SubjectChangePollInterval time.Duration `envconfig:"KACHO_API_GATEWAY_SUBJECT_CHANGE_POLL_INTERVAL" default:"2s"`
}

// TLSEnabled возвращает true, если TLS-listener должен быть запущен.
// Требует одновременно TLS_LISTEN_ADDR + TLS_CERT_FILE + TLS_KEY_FILE.
func (c Config) TLSEnabled() bool {
	return c.TLSListenAddr != "" && c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// AdvertisedEndpoint returns the host:port to advertise in the yc CLI
// compatibility shim (ApiEndpointService.List response).
func (c Config) AdvertisedEndpoint() string {
	return c.AdvertisedEndpointAddr
}

// ResolvedHydraIssuer returns the Hydra issuer URL, deriving it from APIDomain
// when explicitly unset. Trailing slash is stripped.
func (c Config) ResolvedHydraIssuer() string {
	iss := c.HydraIssuer
	if iss == "" {
		iss = "https://hydra." + c.APIDomain
	}
	for len(iss) > 0 && iss[len(iss)-1] == '/' {
		iss = iss[:len(iss)-1]
	}
	return iss
}

// ResolvedHydraJWKSURL returns the JWKS endpoint, deriving from issuer when
// not explicitly set.
func (c Config) ResolvedHydraJWKSURL() string {
	if c.HydraJWKSURL != "" {
		return c.HydraJWKSURL
	}
	return c.ResolvedHydraIssuer() + "/.well-known/jwks.json"
}

// ResolvedHydraIntrospectionURL returns the Hydra introspection endpoint.
func (c Config) ResolvedHydraIntrospectionURL() string {
	if c.HydraIntrospectionURL != "" {
		return c.HydraIntrospectionURL
	}
	return c.ResolvedHydraIssuer() + "/oauth2/introspect"
}

// ResolvedHydraAdminURL returns the Hydra admin API base.
func (c Config) ResolvedHydraAdminURL() string {
	if c.HydraAdminURL != "" {
		return c.HydraAdminURL
	}
	return c.ResolvedHydraIssuer()
}

// ExpectedAudience returns the audience value injected in tokens for this
// API gateway — `https://{APIDomain}`. Used as the expected `aud` during JWT
// validation.
func (c Config) ExpectedAudience() string {
	return "https://" + c.APIDomain
}

// ResolvedIAMAuthorizeURL returns the AuthorizeService address, deriving it
// from IAMAddr when the explicit IAMAuthorizeURL is unset.
func (c Config) ResolvedIAMAuthorizeURL() string {
	if c.IAMAuthorizeURL != "" {
		return c.IAMAuthorizeURL
	}
	return c.IAMAddr
}

// BackendAddrs возвращает карту domain → адрес для инициализации Backends.
// "iam" / "iamInternal" — kacho-iam public (9090) / internal (9091) endpoints (KAC-105).
// KAC-124/127: "resourcemanager" / "organizationmanager" удалены — заменены на /iam/v1/*.
// KAC-161: "loadbalancer" / "loadbalancerInternal" — kacho-nlb public / internal endpoints.
// Domain-ключ "loadbalancer" совпадает с proto-package `kacho.cloud.loadbalancer.v1.*`,
// который парсит director (proxy/director.go) для маршрутизации gRPC-вызовов.
func (c Config) BackendAddrs() map[string]string {
	return map[string]string{
		"vpc":                  c.VPCAddr,
		"vpcInternal":          c.VPCInternalAddr,
		"compute":              c.ComputeAddr,
		"computeInternal":      c.ComputeInternalAddr,
		"iam":                  c.IAMAddr,
		"iamInternal":          c.IAMInternalAddr,
		"loadbalancer":         c.NLBAddr,
		"loadbalancerInternal": c.NLBInternalAddr,
	}
}

// Load читает конфигурацию из переменных окружения.
func Load() (Config, error) {
	var cfg Config
	if err := corecfg.Load(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
