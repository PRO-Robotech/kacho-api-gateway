// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	corecfg "github.com/PRO-Robotech/kacho-corelib/config"
	"github.com/PRO-Robotech/kacho-corelib/grpcclient"
)

// Config хранит конфигурацию api-gateway.
// Переменные окружения:
//
//	KACHO_API_GATEWAY_LISTEN_ADDR         — адрес для cmux listener (default: :8080)
//	KACHO_API_GATEWAY_TLS_LISTEN_ADDR     — адрес для TLS listener (default: пусто — TLS отключен)
//	KACHO_API_GATEWAY_TLS_CERT_FILE       — путь к TLS-сертификату (PEM)
//	KACHO_API_GATEWAY_TLS_KEY_FILE        — путь к TLS-приватному ключу (PEM)
//	KACHO_API_GATEWAY_VPC_GRPC            — адрес backend vpc
//	KACHO_API_GATEWAY_COMPUTE_GRPC        — адрес backend compute (public, port 9090)
//	KACHO_API_GATEWAY_COMPUTE_INTERNAL_GRPC — адрес backend compute internal-port (9091)
//	KACHO_API_GATEWAY_IAM_GRPC            — адрес backend iam (public, port 9090)
//	KACHO_API_GATEWAY_IAM_INTERNAL_GRPC   — адрес backend iam internal-port (9091)
//	KACHO_API_GATEWAY_NLB_GRPC            — адрес backend kacho-nlb (public, port 9090)
//	KACHO_API_GATEWAY_NLB_INTERNAL_GRPC   — адрес backend kacho-nlb internal-port (9091)
//	KACHO_API_GATEWAY_GEO_GRPC            — адрес backend kacho-geo (public, port 9090)
//	KACHO_API_GATEWAY_GEO_INTERNAL_GRPC   — адрес backend kacho-geo internal-port (9091)
//	KACHO_API_GATEWAY_REGISTRY_GRPC          — адрес backend kacho-registry (public, port 9090)
//	KACHO_API_GATEWAY_REGISTRY_INTERNAL_GRPC — адрес backend kacho-registry internal-port (9091)
//	KACHO_APP_ENV                            — deployment-env label (keys the prod authz guard)
//	KACHO_API_GATEWAY_KRATOS_PUBLIC_URL      — Ory Kratos public API base ("disabled" turns it off)
//	KACHO_API_GATEWAY_INTERNAL_GRPC_ADDR     — cluster-internal gRPC listener (default :9091)
//	KACHO_API_GATEWAY_OIDC_ISSUER / _EXTERNAL_ISSUER / _CLIENT_ID / _CLIENT_SECRET / _REDIRECT_URI — OIDC UI flow
//
// TLS требуется для совместимости с CLI-клиентами, жестко ожидающими TLS-endpoint.
// Когда TLS_LISTEN_ADDR пустой — TLS не запускается; plain-cmux на ListenAddr.
type Config struct {
	ListenAddr    string `envconfig:"KACHO_API_GATEWAY_LISTEN_ADDR"          default:":8080"`
	TLSListenAddr string `envconfig:"KACHO_API_GATEWAY_TLS_LISTEN_ADDR"      default:""`
	TLSCertFile   string `envconfig:"KACHO_API_GATEWAY_TLS_CERT_FILE"        default:""`
	TLSKeyFile    string `envconfig:"KACHO_API_GATEWAY_TLS_KEY_FILE"         default:""`
	VPCAddr       string `envconfig:"KACHO_API_GATEWAY_VPC_GRPC"              default:"vpc.kacho.svc.cluster.local:9090"`
	// VPCInternalAddr — admin-only internal-port (9091) of vpc backend.
	// Routes AddressPool RESTful endpoints (kacho-only admin).
	VPCInternalAddr string `envconfig:"KACHO_API_GATEWAY_VPC_INTERNAL_GRPC" default:"vpc.kacho.svc.cluster.local:9091"`
	// ComputeAddr — public gRPC backend of kacho-compute (Disk/Image/Snapshot/Instance/DiskType/Zone).
	ComputeAddr string `envconfig:"KACHO_API_GATEWAY_COMPUTE_GRPC" default:"compute.kacho.svc.cluster.local:9090"`
	// ComputeInternalAddr — admin-only internal-port (9091) of compute backend.
	// Routes InternalDiskType RESTful endpoints (kacho-only admin).
	ComputeInternalAddr string `envconfig:"KACHO_API_GATEWAY_COMPUTE_INTERNAL_GRPC" default:"compute.kacho.svc.cluster.local:9091"`
	// IAMAddr — public gRPC backend of kacho-iam (Account/Project/User/ServiceAccount/Group/Role/AccessBinding).
	// Все RPC под /iam/v1/*.
	IAMAddr string `envconfig:"KACHO_API_GATEWAY_IAM_GRPC" default:"iam.kacho.svc.cluster.local:9090"`
	// IAMInternalAddr — admin-only internal-port (9091) of iam backend.
	// InternalUserService.Get для admin tooling (gRPC-direct; REST-routing no-op,
	// proto-аннотации `google.api.http` отсутствуют — handler регистрируется в mux
	// pro-forma, реальный трафик идет по gRPC) + REST для
	// InternalUserService.UpsertFromIdentity (OIDC-callback).
	// InternalIAMService.LookupSubject/ListPermissions — НЕ регистрируется в REST
	// (auth-interceptor звонит kacho-iam:9091 напрямую через grpc-client).
	IAMInternalAddr string `envconfig:"KACHO_API_GATEWAY_IAM_INTERNAL_GRPC" default:"iam.kacho.svc.cluster.local:9091"`

	// NLBAddr — public gRPC backend of kacho-nlb (NetworkLoadBalancer/Listener/TargetGroup).
	// Public RPC под /nlb/v1/*. При пустом значении nlb-handlers не регистрируются
	// (graceful — позволяет деплоить api-gateway до kacho-nlb pod'a).
	NLBAddr string `envconfig:"KACHO_API_GATEWAY_NLB_GRPC" default:"kacho-nlb.kacho.svc.cluster.local:9090"`

	// NLBInternalAddr — admin-only internal-port (9091) of kacho-nlb backend.
	// InternalResourceLifecycleService.Subscribe — gRPC server-streaming для
	// подписки на CREATED/UPDATED/DELETED события (data-plane consumer'ы дозваниваются
	// напрямую). Регистрируется в REST mux pro-forma (как iam InternalUserService),
	// реальный трафик идет через gRPC-direct. См. запрет #6.
	NLBInternalAddr string `envconfig:"KACHO_API_GATEWAY_NLB_INTERNAL_GRPC" default:"kacho-nlb.kacho.svc.cluster.local:9091"`

	// GeoAddr — public gRPC backend of kacho-geo (RegionService/ZoneService read).
	// Public RPC под /geo/v1/*. Geography — отдельный leaf-сервис kacho-geo. При
	// пустом значении geo-handlers не регистрируются (graceful — позволяет
	// деплоить api-gateway до kacho-geo pod'a).
	// The geo k8s Service is "kacho-geo" — the bare "geo.kacho.svc.cluster.local"
	// host does NOT resolve (NXDOMAIN) → the grpc resolver returns no addresses →
	// "no children to pick from" 503 on every /geo/v1/* request. Target the real
	// Service name (mirrors kacho-iam / kacho-nlb).
	GeoAddr string `envconfig:"KACHO_API_GATEWAY_GEO_GRPC" default:"kacho-geo.kacho.svc.cluster.local:9090"`

	// GeoInternalAddr — admin-only internal-port (9091) of kacho-geo backend.
	// Routes InternalRegionService/InternalZoneService admin-CRUD endpoints
	// (kacho-only). Cluster-internal listener only (запрет #6).
	// Separate Service "kacho-geo-internal" (mirrors kacho-iam-internal).
	GeoInternalAddr string `envconfig:"KACHO_API_GATEWAY_GEO_INTERNAL_GRPC" default:"kacho-geo-internal.kacho.svc.cluster.local:9091"`

	// RegistryAddr — public gRPC backend of kacho-registry (RegistryService:
	// control-plane реестра). Public RPC под /registry/v1/*. При пустом значении
	// registry-handlers не регистрируются (graceful — позволяет деплоить
	// api-gateway до kacho-registry pod'a). Data-plane OCI v2 (/v2/*) — отдельный
	// ingress, НЕ через api-gateway.
	RegistryAddr string `envconfig:"KACHO_API_GATEWAY_REGISTRY_GRPC" default:"kacho-registry.kacho.svc.cluster.local:9090"`

	// RegistryInternalAddr — admin-only internal-port (9091) of kacho-registry
	// backend. Routes InternalRegistryService (TriggerGarbageCollection/
	// GetRegistryStats) — GC zot-стора + инфра-статистика namespace. Cluster-internal
	// listener only (запрет #6). Same host, internal port (mirrors iam/nlb).
	RegistryInternalAddr string `envconfig:"KACHO_API_GATEWAY_REGISTRY_INTERNAL_GRPC" default:"kacho-registry.kacho.svc.cluster.local:9091"`

	// AdvertisedEndpointAddr — host:port that the api-gateway advertises through
	// the endpoint-discovery RPC. External clients dial this address. Defaults to
	// api.kacho.local:443.
	AdvertisedEndpointAddr string `envconfig:"KACHO_API_GATEWAY_ADVERTISED_ENDPOINT" default:"api.kacho.local:443"`

	// AuthNMode — режим auth-interceptor:
	//   - "dev" (default): backwards-compat. Без Bearer = anonymous; невалидный
	//     Bearer = fallback anonymous. С валидным Bearer + subject в kacho-iam =
	//     real Principal.
	//   - "production": Bearer обязателен. Невалидный или unknown subject =
	//     Unauthenticated.
	//   - "production-strict": то же что production + reject missing Bearer.
	AuthNMode string `envconfig:"KACHO_API_GATEWAY_AUTHN_MODE" default:"dev"`

	// AuthNDevSecret — HMAC-secret для подписи dev-JWT (mode=dev).
	// Если пуст — Bearer-токены в dev-режиме игнорируются (всегда anonymous).
	// Production / production-strict — нужен Hydra JWKS.
	AuthNDevSecret string `envconfig:"KACHO_API_GATEWAY_AUTHN_DEV_SECRET" default:""`

	// --- composition-root settings (previously read via ad-hoc os.Getenv in
	// main.go; centralised here so they carry documented defaults + appear in the
	// single Config env contract) ---

	// AppEnv — deployment-environment label (prod / production / staging / dev /
	// local / test / ""). Keys the fail-fast production authz guard
	// (validateProductionAuthzConfig) and relaxed-posture warnings. Emitted from
	// the helm overlay via extraEnv.
	AppEnv string `envconfig:"KACHO_APP_ENV" default:""`

	// KratosPublicURL — base URL of the Ory Kratos public API (session /whoami).
	// The sentinel "disabled" turns Kratos session-auth off entirely. Default is
	// the cluster-internal kratos-public Service.
	KratosPublicURL string `envconfig:"KACHO_API_GATEWAY_KRATOS_PUBLIC_URL" default:"http://kacho-umbrella-kratos-public.kacho.svc.cluster.local:80"`

	// InternalGRPCAddr — dedicated cluster-internal gRPC listener for RPCs that
	// must not be on the external TLS endpoint (InternalAuthzCacheService).
	InternalGRPCAddr string `envconfig:"KACHO_API_GATEWAY_INTERNAL_GRPC_ADDR" default:":9091"`

	// --- OIDC login/callback flow (UI auth) ---
	// OIDCIssuer empty ⇒ the OIDC handler is disabled (login → 503). A partial
	// config (issuer set, client-id/redirect missing) is TOLERATED at startup —
	// the bootstrap Job populates the client-id secret post-install and Login
	// returns a descriptive 503 until then — but surfaced via a startup WARN.
	OIDCIssuer         string `envconfig:"KACHO_API_GATEWAY_OIDC_ISSUER"          default:""`
	OIDCExternalIssuer string `envconfig:"KACHO_API_GATEWAY_OIDC_EXTERNAL_ISSUER" default:""`
	OIDCClientID       string `envconfig:"KACHO_API_GATEWAY_OIDC_CLIENT_ID"       default:""`
	OIDCClientSecret   string `envconfig:"KACHO_API_GATEWAY_OIDC_CLIENT_SECRET"   default:""`
	OIDCRedirectURI    string `envconfig:"KACHO_API_GATEWAY_OIDC_REDIRECT_URI"    default:""`

	// --- AuthN core (DPoP / JWT / mTLS-bound / step-up / BCL) ---

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

	// --- AuthZ core (per-RPC enforcement) ---

	// AuthZEnabled — master toggle for the per-RPC AuthZ middleware. When
	// false (default), the middleware mounts as a pass-through (compat with
	// dev environments without OpenFGA/IAM AuthorizeService).
	AuthZEnabled bool `envconfig:"KACHO_API_GATEWAY_AUTHZ_ENABLED" default:"false"`

	// AuthZFailOpen — when true, transient IAM-Check failures (Unavailable
	// / DeadlineExceeded) PASS the request through (logged ERROR). Default
	// false (fail-closed); only flip to true in dev / staging emergencies.
	AuthZFailOpen bool `envconfig:"KACHO_API_GATEWAY_AUTHZ_FAIL_OPEN" default:"false"`

	// IAMAuthorizeURL — gRPC address of kacho-iam AuthorizeService. Empty
	// → derives from IAMAddr (public iam endpoint, port 9090). Отдельный env
	// позволяет вынести AuthorizeService на свой pod ради HA.
	IAMAuthorizeURL string `envconfig:"KACHO_API_GATEWAY_IAM_AUTHORIZE_URL" default:""`

	// AuthZCacheTTLSeconds — decision-cache TTL (sec). Default 5s.
	AuthZCacheTTLSeconds int `envconfig:"KACHO_API_GATEWAY_AUTHZ_CACHE_TTL_SECONDS" default:"5"`

	// AuthZCacheMaxEntries — LRU cap. Default 10000.
	AuthZCacheMaxEntries int `envconfig:"KACHO_API_GATEWAY_AUTHZ_CACHE_MAX_ENTRIES" default:"10000"`

	// AuthZCheckTimeoutMs — hard timeout per AuthorizeService.Check (ms).
	// Default 200ms.
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

	// SubjectChangePollInterval — how often the subject-change watcher polls
	// kacho-iam InternalIAMService.PollSubjectChanges to flush the authz
	// decision cache on sibling replicas that did not process the mutation.
	// Default 2s. Omit the env var (or set 0) to use the built-in default.
	SubjectChangePollInterval time.Duration `envconfig:"KACHO_API_GATEWAY_SUBJECT_CHANGE_POLL_INTERVAL" default:"2s"`

	// --- per-edge backend-dial mTLS ---
	//
	// Backward-compat default = OFF: all *_ENABLE false, cert/key/ca empty ⇒
	// every backend dial is insecure, identical to current dev. When an edge is
	// enabled the gateway presents the shared "api-gateway" client-cert
	// (CertFile/KeyFile), verifies the backend server-cert against CAFile, and
	// checks the server-cert SAN against the per-edge ServerName (or the dial-host
	// when unset). enable=true with missing cert material ⇒ fail-fast at startup,
	// never a silent insecure fallback.
	//
	// One shared client cert/key/ca across all edges (one "api-gateway" module
	// identity); per-edge ENABLE + SERVER_NAME give independent rollback.
	MTLSClientCertFile string `envconfig:"KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE" default:""`
	MTLSClientKeyFile  string `envconfig:"KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE"  default:""`
	MTLSCAFile         string `envconfig:"KACHO_API_GATEWAY_MTLS_CA_FILE"          default:""`

	MTLSVPCEnable      bool `envconfig:"KACHO_API_GATEWAY_MTLS_VPC_ENABLE"      default:"false"`
	MTLSComputeEnable  bool `envconfig:"KACHO_API_GATEWAY_MTLS_COMPUTE_ENABLE"  default:"false"`
	MTLSIAMEnable      bool `envconfig:"KACHO_API_GATEWAY_MTLS_IAM_ENABLE"      default:"false"`
	MTLSNLBEnable      bool `envconfig:"KACHO_API_GATEWAY_MTLS_NLB_ENABLE"      default:"false"`
	MTLSGeoEnable      bool `envconfig:"KACHO_API_GATEWAY_MTLS_GEO_ENABLE"      default:"false"`
	MTLSRegistryEnable bool `envconfig:"KACHO_API_GATEWAY_MTLS_REGISTRY_ENABLE" default:"false"`

	// Per-edge SNI/server-name overrides. Empty ⇒ derive from the dial-addr host.
	MTLSVPCServerName      string `envconfig:"KACHO_API_GATEWAY_MTLS_VPC_SERVER_NAME"      default:""`
	MTLSComputeServerName  string `envconfig:"KACHO_API_GATEWAY_MTLS_COMPUTE_SERVER_NAME"  default:""`
	MTLSIAMServerName      string `envconfig:"KACHO_API_GATEWAY_MTLS_IAM_SERVER_NAME"      default:""`
	MTLSNLBServerName      string `envconfig:"KACHO_API_GATEWAY_MTLS_NLB_SERVER_NAME"      default:""`
	MTLSGeoServerName      string `envconfig:"KACHO_API_GATEWAY_MTLS_GEO_SERVER_NAME"      default:""`
	MTLSRegistryServerName string `envconfig:"KACHO_API_GATEWAY_MTLS_REGISTRY_SERVER_NAME" default:""`

	// Hybrid external listener: when true, the external TLS listener
	// (TLSListenAddr) runs with tls.VerifyClientCertIfGiven and the internal CA
	// (MTLSCAFile) as ClientCAs — an OPTIONAL client cert. A browser (no cert)
	// handshakes and takes the JWT path; a client presenting a valid Kachō cert
	// is verified so the AuthInterceptor can derive a principal from its SPIFFE
	// SAN (no JWT required). Default false ⇒ ClientAuth stays NoClientCert,
	// behaviour unchanged. Internal service listeners are NOT affected by this
	// flag (they stay strict RequireAndVerifyClientCert).
	HybridMTLSExternal bool `envconfig:"KACHO_API_GATEWAY_HYBRID_MTLS_EXTERNAL" default:"false"`
}

// TLSEnabled возвращает true, если TLS-listener должен быть запущен.
// Требует одновременно TLS_LISTEN_ADDR + TLS_CERT_FILE + TLS_KEY_FILE.
func (c Config) TLSEnabled() bool {
	return c.TLSListenAddr != "" && c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// AdvertisedEndpoint returns the host:port to advertise through the
// endpoint-discovery RPC.
func (c Config) AdvertisedEndpoint() string {
	return c.AdvertisedEndpointAddr
}

// HybridMTLSEnabled reports whether the external TLS listener should accept an
// optional client cert. When false (default) the listener stays NoClientCert
// (JWT-only authN).
func (c Config) HybridMTLSEnabled() bool {
	return c.HybridMTLSExternal
}

// ExternalListenerClientAuth applies the hybrid client-auth policy to the
// external listener's *tls.Config and returns it. When hybrid is disabled it is a
// no-op (ClientAuth stays NoClientCert). When enabled it sets
// tls.VerifyClientCertIfGiven with the internal CA (MTLSCAFile) as ClientCAs, so
// a browser without a cert still handshakes (JWT path) while a client that DOES
// present a cert has it verified against the trust anchor — the AuthInterceptor
// then derives the principal from the verified cert's SPIFFE SAN.
//
// Fail-fast: hybrid enabled with no readable CA file is an error (a listener that
// cannot verify any client cert would silently degrade every cert client to the
// JWT path — the operator must know).
func (c Config) ExternalListenerClientAuth(base *tls.Config) (*tls.Config, error) {
	if base == nil {
		base = &tls.Config{}
	}
	if !c.HybridMTLSExternal {
		return base, nil
	}
	if c.MTLSCAFile == "" {
		return nil, fmt.Errorf(
			"hybrid mTLS external listener enabled but client-CA missing " +
				"(KACHO_API_GATEWAY_MTLS_CA_FILE)")
	}
	caPEM, err := os.ReadFile(c.MTLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read hybrid client-CA %q: %w", c.MTLSCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("hybrid client-CA %q: no certificates parsed", c.MTLSCAFile)
	}
	base.ClientAuth = tls.VerifyClientCertIfGiven
	base.ClientCAs = pool
	return base, nil
}

// OIDCDisabled reports whether the OIDC login/callback flow is off (no issuer).
func (c Config) OIDCDisabled() bool { return c.OIDCIssuer == "" }

// OIDCPartial reports whether OIDC is enabled (issuer set) but missing a field
// required to complete the flow (client-id or redirect-uri). This is TOLERATED
// at startup (the bootstrap Job fills the client-id secret post-install; Login
// returns a descriptive 503 until then) but the caller surfaces it as a WARN so
// a stuck bootstrap is visible in pod logs rather than only at runtime.
func (c Config) OIDCPartial() bool {
	return c.OIDCIssuer != "" && (c.OIDCClientID == "" || c.OIDCRedirectURI == "")
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
// "iam" / "iamInternal" — kacho-iam public (9090) / internal (9091) endpoints.
// "loadbalancer" / "loadbalancerInternal" — kacho-nlb public / internal endpoints.
// Domain-ключ "loadbalancer" совпадает с proto-package `kacho.cloud.loadbalancer.v1.*`,
// по которому gRPC-роутер (server.go Resolver / shimproxy.go) выбирает backend.
// "geo" / "geoInternal" — kacho-geo public / internal endpoints. Domain-ключ
// "geo" совпадает с proto-package `kacho.cloud.geo.v1.*` (та же маршрутизация).
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
		"geo":                  c.GeoAddr,
		"geoInternal":          c.GeoInternalAddr,
		"registry":             c.RegistryAddr,
		"registryInternal":     c.RegistryInternalAddr,
	}
}

// EdgeTLSClient assembles the corelib grpcclient.TLSClient value-struct for a
// backend edge ("vpc" | "compute" | "iam" | "nlb" | "geo" | "registry"),
// deriving the server-name from the dial address host when no per-edge override
// is set.
//
// Contract:
//   - edge disabled ⇒ {Enable:false}; cert material is NOT consulted (insecure
//     dial; dev backward-compat). The returned struct is safe to pass to
//     grpcclient.TLSClientCreds.
//   - edge enabled ⇒ {Enable:true, CertFile, KeyFile, CAFiles, ServerName}; if any
//     of cert/key/ca is empty the call FAILS (fail-fast), never a silent insecure
//     fallback. PEM validity itself is enforced later by grpcclient.TLSClientCreds.
//   - unknown edge ⇒ error (programming error).
func (c Config) EdgeTLSClient(edge, dialAddr string) (grpcclient.TLSClient, error) {
	enable, serverNameOverride, err := c.edgeMTLS(edge)
	if err != nil {
		return grpcclient.TLSClient{}, err
	}
	if !enable {
		return grpcclient.TLSClient{Enable: false}, nil
	}

	// Fail-fast: enabled edge demands the full shared cert material. A silent
	// insecure fallback here would defeat the security contract.
	if c.MTLSClientCertFile == "" || c.MTLSClientKeyFile == "" || c.MTLSCAFile == "" {
		return grpcclient.TLSClient{}, fmt.Errorf(
			"mtls %s enabled but client cert/key/ca missing "+
				"(KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE/_KEY_FILE/_CA_FILE)", edge)
	}

	serverName := serverNameOverride
	if serverName == "" {
		serverName = hostFromAddr(dialAddr)
	}
	if serverName == "" {
		return grpcclient.TLSClient{}, fmt.Errorf(
			"mtls %s enabled but server_name could not be derived from dial addr %q "+
				"(set KACHO_API_GATEWAY_MTLS_%s_SERVER_NAME)", edge, dialAddr, strings.ToUpper(edge))
	}

	return grpcclient.TLSClient{
		Enable:     true,
		CertFile:   c.MTLSClientCertFile,
		KeyFile:    c.MTLSClientKeyFile,
		CAFiles:    []string{c.MTLSCAFile},
		ServerName: serverName,
	}, nil
}

// edgeMTLS resolves the per-edge enable flag + server-name override.
func (c Config) edgeMTLS(edge string) (enable bool, serverName string, err error) {
	switch edge {
	case "vpc":
		return c.MTLSVPCEnable, c.MTLSVPCServerName, nil
	case "compute":
		return c.MTLSComputeEnable, c.MTLSComputeServerName, nil
	case "iam":
		return c.MTLSIAMEnable, c.MTLSIAMServerName, nil
	case "nlb":
		return c.MTLSNLBEnable, c.MTLSNLBServerName, nil
	case "geo":
		return c.MTLSGeoEnable, c.MTLSGeoServerName, nil
	case "registry":
		return c.MTLSRegistryEnable, c.MTLSRegistryServerName, nil
	default:
		return false, "", fmt.Errorf("unknown mtls edge %q", edge)
	}
}

// hostFromAddr returns the host portion of a "host:port" dial address (or the
// input unchanged when it has no port).
func hostFromAddr(addr string) string {
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return addr
	}
	return host
}

// Load читает конфигурацию из переменных окружения.
func Load() (Config, error) {
	var cfg Config
	if err := corecfg.Load(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
