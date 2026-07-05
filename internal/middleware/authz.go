// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz.go — per-RPC AuthZ middleware for the api-gateway.
//
// Position in the middleware chain (mounted after the JWT-verifier):
//
//	DPoP → JWT verifier → mTLS-bound → Step-up → AUTHZ → handler
//
// Pipeline per request:
//
//  1. Resolve the gRPC FQN (gRPC-server path: trivially `info.FullMethod`;
//     HTTP path: best-effort REST-to-FQN mapping via the explicit route
//     table — see RestRouter below).
//
//  2. Lookup permission catalog entry (`PermissionCatalog`). Missing entry
//     OR `IsExempt` → bypass. Public allow-list is independent (login,
//     health, recovery) and overrides catalog absence.
//
//  3. Extract subject from verified JWT (SubjectExtractor). No subject →
//     deny unless the entry is on the explicit anonymous allowlist
//     (per-route override or `<exempt>` catalog).
//
//  4. Extract resource id (ResourceExtractor) using the catalog's
//     `scope_extractor` directive.
//
//  5. Build Conditions context (ContextExtractor).
//
//  6. Decision cache lookup — LRU 10k entries / 5s TTL, keyed on
//     (subject, action, resource_type:resource_id, acr, mfa_at, source_ip).
//     Hit → reuse decision. Miss → call IAM AuthorizeService.Check.
//
//  7. On allow → pass through. On deny → build PermissionDenied with
//     PreconditionFailure violations + WWW-Authenticate when reasons
//     suggest step-up. On IAM error → fail-closed (Unavailable) unless
//     `KACHO_API_GATEWAY_AUTHZ_FAIL_OPEN=true`.
//
//  8. Always emit metric + structured log.
//
// Configuration is supplied via `AuthzMiddlewareConfig` constructed in
// main.go from `config.Config`. No global state.
package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
)

// AuthzCheckInput — caller-friendly Check arguments. Mirrors
// `clients.AuthorizeCheckInput` to avoid a middleware → clients import
// cycle (clients itself imports middleware for Subject / ResolvedSubject
// types). Adapters convert between the two shapes.
type AuthzCheckInput struct {
	Subject string
	Action  string
	// RequiredRelation — explicit FGA relation from the catalog. When
	// non-empty, IAM honors this verbatim instead of
	// deriving from action verb. Required for admin-only RPCs whose
	// `*.list`/`*.get` verb would resolve to `viewer` and slip through
	// the `cluster.viewer = user:*` cascade.
	RequiredRelation string
	ResourceType     string
	ResourceID       string
	Context          map[string]any
	TraceID          string
}

// AuthzCheckResult — caller-friendly Check result.
type AuthzCheckResult struct {
	Allowed              bool
	DenyReasons          []string
	AuthorizationModelID string
	CheckedAt            time.Time
}

// AuthorizeChecker — narrowed dependency (mock-able). The clients package
// supplies a thin adapter; tests pass a closure / mock struct.
type AuthorizeChecker interface {
	Check(ctx context.Context, in AuthzCheckInput) (AuthzCheckResult, error)
}

// AuthzMiddlewareConfig — DI bag.
type AuthzMiddlewareConfig struct {
	// Enabled — master toggle. When false the middleware is a no-op
	// pass-through (legacy compatibility).
	Enabled bool

	// FailOpen — when true, IAM unreachable / Check returning error
	// permits the request (logged as ERROR). Default false (production
	// fail-closed — never leak access on failure).
	FailOpen bool

	// Catalog — permission lookup. Required when Enabled=true.
	Catalog *PermissionCatalog

	// Subjects — JWT → ResolvedSubject. Required when Enabled=true.
	Subjects *SubjectExtractor

	// Context — JWT + request → Condition-context. Required when Enabled=true.
	Context *ContextExtractor

	// Resources — request → ResourceID. Required when Enabled=true.
	Resources *ResourceExtractor

	// Checker — IAM AuthorizeService client (or test mock). Required when
	// Enabled=true.
	Checker AuthorizeChecker

	// Overrides — per-route override registry (file-based, SIGHUP reload).
	// Optional.
	Overrides *AuthzOverrides

	// Metrics — counters + histograms. When nil a fresh sink is allocated.
	Metrics *AuthzMetrics

	// Logger — slog. Required when Enabled=true.
	Logger *slog.Logger

	// Now — clock injection for tests. Defaults to time.Now.
	Now func() time.Time

	// CacheTTL — decision-cache TTL. Default 5s (spec).
	CacheTTL time.Duration

	// CacheMaxEntries — LRU cap. Default 10000 (spec).
	CacheMaxEntries int

	// PublicAllowlist — gRPC FQNs that ALWAYS pass without subject /
	// catalog check. Login flow, health, recovery — set this in main.go.
	PublicAllowlist []string

	// RestRouter — best-effort REST-path → gRPC-FQN mapping. nil → only
	// path-prefix-based mapping (see grpcMethodForPath in dpop_http_middleware).
	RestRouter RestRouteResolver
}

// RestRouteResolver — interface to map an HTTP path/method to a gRPC FQN.
// Implementations may parse google.api.http annotations or a hand-rolled
// route table.
type RestRouteResolver interface {
	Resolve(httpMethod, httpPath string) (fqn string, ok bool)
}

// AuthzMiddleware — gRPC + HTTP middleware orchestrator.
type AuthzMiddleware struct {
	cfg     AuthzMiddlewareConfig
	cache   *decisionCache
	allow   map[string]struct{}
	metrics *AuthzMetrics
	now     func() time.Time
}

// NewAuthzMiddleware constructs the middleware from cfg. Returns an error
// when required fields are missing.
func NewAuthzMiddleware(cfg AuthzMiddlewareConfig) (*AuthzMiddleware, error) {
	if !cfg.Enabled {
		// no-op stand-in: callers may still wire it into the chain and rely
		// on the pass-through; missing deps are silently tolerated.
		if cfg.Logger == nil {
			cfg.Logger = slog.Default()
		}
		return &AuthzMiddleware{cfg: cfg, metrics: NewAuthzMetrics(), now: time.Now}, nil
	}
	if cfg.Catalog == nil {
		return nil, errors.New("authz middleware: Catalog is required")
	}
	if cfg.Subjects == nil {
		return nil, errors.New("authz middleware: Subjects is required")
	}
	if cfg.Context == nil {
		return nil, errors.New("authz middleware: Context is required")
	}
	if cfg.Resources == nil {
		return nil, errors.New("authz middleware: Resources is required")
	}
	if cfg.Checker == nil {
		return nil, errors.New("authz middleware: Checker is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("authz middleware: Logger is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Second
	}
	if cfg.CacheMaxEntries <= 0 {
		cfg.CacheMaxEntries = 10000
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = NewAuthzMetrics()
	}

	allow := make(map[string]struct{}, len(cfg.PublicAllowlist))
	for _, fqn := range cfg.PublicAllowlist {
		allow[fqn] = struct{}{}
	}

	return &AuthzMiddleware{
		cfg:     cfg,
		cache:   newDecisionCache(cfg.CacheMaxEntries, cfg.CacheTTL, cfg.Now),
		allow:   allow,
		metrics: metrics,
		now:     cfg.Now,
	}, nil
}

// Metrics returns the metrics sink; used by `/metrics` rendering elsewhere.
func (m *AuthzMiddleware) Metrics() *AuthzMetrics { return m.metrics }

// subjectChangingFQNs — gRPC FQNs whose success changes a subject's grants.
// On a 2xx response the gateway flushes its decision cache so the new grant
// state takes effect immediately for this replica (self-flush). Sibling
// replicas converge via the subject-change poll-loop.
// It is read-only after package init — do not mutate at runtime.
var subjectChangingFQNs = map[string]struct{}{
	"kacho.cloud.iam.v1.AccessBindingService/Create": {},
	"kacho.cloud.iam.v1.AccessBindingService/Delete": {},
}

// MaybeFlushOnMutation flushes the decision cache when fqn is a grant-changing
// RPC and the proxied response was successful (HTTP 2xx). Safe to call on every
// request — it is a no-op for non-mutating FQNs and non-2xx responses.
func (m *AuthzMiddleware) MaybeFlushOnMutation(fqn string, httpStatus int) {
	if m.cache == nil || httpStatus < 200 || httpStatus >= 300 {
		return
	}
	if _, ok := subjectChangingFQNs[normalizeFQN(fqn)]; !ok {
		return
	}
	m.cache.Invalidate()
	m.cfg.Logger.Info("authz decision-cache flushed on grant mutation", "fqn", fqn)
}

// InvalidateCache flushes the whole authz decision cache. Used by the
// subject-change watcher to converge this replica after a grant change
// observed on another replica. No-op when authz is disabled (cache is nil).
func (m *AuthzMiddleware) InvalidateCache() {
	if m.cache != nil {
		m.cache.Invalidate()
	}
}

// AsInvalidator returns a small port (Invalidator) over this middleware's
// decision cache, used by the InternalAuthzCacheService
// handler. Returns a non-nil no-op adapter when authz is disabled
// (m.cache == nil) so the main.go wiring works on disabled-authz configs.
//
// The returned Invalidator exposes:
//   - InvalidateSubject(subject) int — per-subject drop (push-drain path)
//   - Invalidate() — whole-cache flush (safety net fallback)
func (m *AuthzMiddleware) AsInvalidator() AuthzInvalidator {
	if m == nil || m.cache == nil {
		return nopAuthzInvalidator{}
	}
	return cacheInvalidatorAdapter{cache: m.cache}
}

// AuthzInvalidator — port consumed by the InternalAuthzCacheService handler
// in internal/handler/internal_authz_cache_server.go. Lives here (not in
// handler/) to keep middleware as the canonical owner of the decision cache.
type AuthzInvalidator interface {
	// InvalidateSubject drops decision-cache entries whose key is prefixed
	// with the given FGA subject (e.g. "user:usr_abc"). Returns the count
	// of entries dropped.
	InvalidateSubject(subject string) int
	// Invalidate flushes the whole decision cache (safety-net fallback).
	Invalidate()
}

type cacheInvalidatorAdapter struct{ cache *decisionCache }

func (a cacheInvalidatorAdapter) InvalidateSubject(subject string) int {
	return a.cache.InvalidateSubject(subject)
}

func (a cacheInvalidatorAdapter) Invalidate() { a.cache.Invalidate() }

type nopAuthzInvalidator struct{}

func (nopAuthzInvalidator) InvalidateSubject(string) int { return 0 }
func (nopAuthzInvalidator) Invalidate()                  {}

// Unary returns a gRPC UnaryServerInterceptor enforcing per-RPC authz.
func (m *AuthzMiddleware) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !m.cfg.Enabled {
			return handler(ctx, req)
		}
		fqn := normalizeFQN(info.FullMethod)
		decision := m.decide(ctx, decisionRequest{
			FQN:      fqn,
			ProtoReq: req,
			GRPCPeer: peerAddr(ctx),
			GRPCMeta: incomingMD(ctx),
		})
		switch decision.outcome {
		case outcomeAllow:
			resp, hErr := handler(ctx, req)
			if hErr == nil {
				m.MaybeFlushOnMutation(fqn, 200)
			}
			return resp, hErr
		case outcomeDeny:
			return nil, decision.gRPCStatus().Err()
		case outcomeUnauthenticated:
			// No credentials → Unauthenticated(16), not PermissionDenied(7).
			return nil, decision.gRPCStatus().Err()
		case outcomeInvalidArgument:
			// Malformed resource id → InvalidArgument(3), Check not run.
			return nil, decision.gRPCStatus().Err()
		case outcomeNotFound:
			// Hide existence: read-deny on a verb-bearing IAM read → NotFound(5).
			return nil, decision.gRPCStatus().Err()
		case outcomeError:
			if m.cfg.FailOpen {
				m.cfg.Logger.Error("authz middleware fail-open: passing request despite error",
					"fqn", fqn, "err", decision.checkErr)
				return handler(ctx, req)
			}
			// Redact the raw backend/transport detail from the client message —
			// leaking it aids fabric mapping. The code is preserved (retryable,
			// fail-closed) and the detail is already logged in decide().
			return nil, status.Error(codes.Unavailable, "authz service unavailable")
		default:
			return handler(ctx, req)
		}
	}
}

// Stream returns a gRPC StreamServerInterceptor enforcing per-RPC authz.
// Streaming RPCs are gated once before the stream runs; the messages flowing
// through it inherit the decision.
func (m *AuthzMiddleware) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !m.cfg.Enabled {
			return handler(srv, ss)
		}
		fqn := normalizeFQN(info.FullMethod)
		decision := m.decide(ss.Context(), decisionRequest{
			FQN:      fqn,
			ProtoReq: nil, // stream requests aren't materialised yet
			GRPCPeer: peerAddr(ss.Context()),
			GRPCMeta: incomingMD(ss.Context()),
		})
		switch decision.outcome {
		case outcomeAllow:
			return handler(srv, ss)
		case outcomeDeny:
			return decision.gRPCStatus().Err()
		case outcomeUnauthenticated:
			// No credentials → Unauthenticated(16), not PermissionDenied(7).
			return decision.gRPCStatus().Err()
		case outcomeInvalidArgument:
			// Malformed resource id → InvalidArgument(3), Check not run.
			return decision.gRPCStatus().Err()
		case outcomeNotFound:
			// Hide existence: read-deny on a verb-bearing IAM read → NotFound(5).
			return decision.gRPCStatus().Err()
		case outcomeError:
			if m.cfg.FailOpen {
				m.cfg.Logger.Error("authz middleware fail-open: passing stream despite error",
					"fqn", fqn, "err", decision.checkErr)
				return handler(srv, ss)
			}
			// Redact the raw backend/transport detail from the client message —
			// leaking it aids fabric mapping. The code is preserved (retryable,
			// fail-closed) and the detail is already logged in decide().
			return status.Error(codes.Unavailable, "authz service unavailable")
		default:
			return handler(srv, ss)
		}
	}
}

// HTTP returns an http.Handler middleware enforcing per-RPC authz on the
// REST surface.
func (m *AuthzMiddleware) HTTP(next http.Handler) http.Handler {
	if !m.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The DPoP middleware already short-circuits health/auth-flow URLs. We
		// still guard here for completeness when this middleware is mounted
		// without it (dev mode).
		if isPublicHTTPPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		fqn := m.resolveRestFQN(r)
		decision := m.decide(r.Context(), decisionRequest{
			FQN:     fqn,
			HTTPReq: r,
		})
		switch decision.outcome {
		case outcomeAllow:
			rw := newResponseWriter(w)
			next.ServeHTTP(rw, r)
			m.MaybeFlushOnMutation(fqn, rw.statusCode)
		case outcomeDeny:
			challenge := ""
			if shouldStepUpChallenge(decision.reasons) {
				// Build a step-up challenge using the catalog's
				// required_acr_min as the target.
				challenge = `Bearer error="insufficient_user_authentication", acr_values="` +
					decision.requiredACRMin() + `"`
			}
			writeHTTPDeny(w, decision.descriptor, decision.reasons, challenge)
		case outcomeUnauthenticated:
			// No credentials → 401 Unauthorized + code 16,
			// not 403 Forbidden + code 7.
			writeHTTPUnauth(w, decision.descriptor, decision.reasons)
		case outcomeInvalidArgument:
			// Malformed resource id → 400 + code 3, Check not run.
			writeHTTPInvalidArg(w, decision.invalidArgID)
		case outcomeNotFound:
			// Hide existence: read-deny on a verb-bearing IAM read → 404, no reasons.
			writeHTTPNotFound(w, decision.descriptor)
		case outcomeError:
			if m.cfg.FailOpen {
				m.cfg.Logger.Error("authz middleware fail-open: passing http request despite error",
					"path", r.URL.Path, "err", decision.checkErr)
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":14,"message":"authz service unavailable"}`))
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// ---- decide() — single decision path used by Unary / Stream / HTTP ----

type decisionRequest struct {
	FQN      string
	ProtoReq any
	HTTPReq  *http.Request
	GRPCPeer string
	GRPCMeta metadata.MD
}

type decisionOutcome int

const (
	outcomeAllow decisionOutcome = iota
	outcomeDeny
	outcomeError
	// outcomeUnauthenticated — request carries NO credentials at all (no valid
	// JWT / no authenticated subject). Maps to gRPC Unauthenticated(16) / HTTP
	// 401. Distinct from outcomeDeny, which is reserved for authenticated
	// subjects whose FGA check was denied (→ 7/403).
	//
	// gRPC/HTTP convention (RFC 7235, gRPC status code guide):
	//   missing/invalid credentials → 16 UNAUTHENTICATED → HTTP 401
	//   authenticated subject, access denied → 7 PERMISSION_DENIED → HTTP 403
	outcomeUnauthenticated
	// outcomeInvalidArgument — the extracted per-resource scope id is
	// syntactically malformed (unknown 3-char prefix / wrong length). Maps to
	// gRPC InvalidArgument(3) / HTTP 400. The FGA Check
	// must NOT run for a malformed id — a no-FGA-path deny would surface as 403,
	// masking the Kachō-convention 400 the handler itself returns first. The
	// gateway cannot tell malformed from well-formed-but-nonexistent, so ONLY the
	// malformed (wrong-prefix / wrong-length) case is short-circuited here;
	// well-formed-nonexistent stays a 403 deny (existence-leak protection).
	outcomeInvalidArgument
	// outcomeNotFound — an authz deny on a hide-existence read RPC (catalog
	// HideExistence / IAM verb-bearing `v_get` read). Maps to gRPC NotFound(5) /
	// HTTP 404 with NO deny reasons. The gateway Check runs BEFORE the resource
	// owner (kacho-iam), which itself returns NotFound for a denied read; surfacing
	// a 403 here would override that hide-existence contract and leak both existence
	// and the deny reasons. Enforcement is unchanged — the deny still blocks the
	// request and the handler is never reached; only the surfaced code/body differ.
	// A well-formed-but-nonexistent id and an existing-but-denied id both yield the
	// same FGA deny → the same NotFound → no enumeration leak.
	outcomeNotFound
)

type decision struct {
	outcome    decisionOutcome
	reasons    []string
	descriptor permissionDeniedDescriptor
	checkErr   error
	entry      CatalogEntry
	// invalidArgID — the malformed resource id, set only for
	// outcomeInvalidArgument. Surfaced verbatim in the 400 message.
	invalidArgID string
}

func (d decision) gRPCStatus() *status.Status {
	switch d.outcome {
	case outcomeUnauthenticated:
		return buildGRPCUnauthStatus(d.descriptor, d.reasons)
	case outcomeInvalidArgument:
		return buildGRPCInvalidArgStatus(d.invalidArgID)
	case outcomeNotFound:
		return buildGRPCNotFoundStatus(d.descriptor)
	default:
		return buildGRPCDenyStatus(d.descriptor, d.reasons)
	}
}

// requiredACRMin returns the catalog-declared ACR floor (default "2").
func (d decision) requiredACRMin() string {
	if d.entry.RequiredACRMin == "" {
		return "2"
	}
	return d.entry.RequiredACRMin
}

// isExternalRequest reports whether the request must be treated as arriving
// from the external edge (fail-closed default). For the HTTP path the origin
// marker lives in the request context (set per-listener by
// listenerorigin.InternalConnContext, which marks ONLY the dedicated
// cluster-internal admin listener). For the gRPC path there is no HTTP request
// and Internal* RPCs never reach this
// middleware via the gateway (the proxy routing blocks them), so we fail closed —
// treat an unknown origin as external, meaning the internal-origin gate does NOT
// admit it and the normal catalog/authN path decides.
func (m *AuthzMiddleware) isExternalRequest(dr decisionRequest) bool {
	if dr.HTTPReq != nil {
		return listenerorigin.IsExternal(dr.HTTPReq.Context())
	}
	// No HTTP request → gRPC path. Fail closed for the internal-origin gate.
	return true
}

func (m *AuthzMiddleware) decide(ctx context.Context, dr decisionRequest) decision {
	start := m.now()
	defer func() {
		m.metrics.ObserveLatencyMs(float64(m.now().Sub(start).Microseconds()) / 1000.0)
	}()

	// The decision pipeline is a sequence of phases, each of which may return a
	// terminal decision (handled=true) or defer to the next. Ordering is
	// security-critical and preserved exactly; see each phase's doc.

	// 1. Public-allowlist short-circuit.
	if dec, handled := m.phaseAllowlist(dr); handled {
		return dec
	}
	// 1b. Internal-listener-origin exempt gate.
	if dec, handled := m.phaseInternalOriginExempt(dr); handled {
		return dec
	}
	// 2. Per-route file override (allow/deny).
	if dec, handled := m.phaseOverride(dr); handled {
		return dec
	}
	// 3. Catalog lookup (exempt-allow / exempt-unauth / catalog-miss deny).
	entry, dec, handled := m.phaseCatalog(ctx, dr)
	if handled {
		return dec
	}
	// 4. Subject extraction (unauthenticated → 401).
	verified, subj, dec, handled := m.phaseSubject(ctx, dr, entry)
	if handled {
		return dec
	}
	// 5. Resource-scope resolution (+ 5b malformed-id short-circuit).
	resourceID, resourceType, descriptor, dec, handled := m.phaseResource(dr, entry, subj)
	if handled {
		return dec
	}
	// 6–8. Context build, decision-cache read, IAM Check.
	return m.phaseCheck(ctx, dr, entry, verified, subj, resourceID, resourceType, descriptor)
}

// phaseAllowlist admits FQNs on the public allowlist (login, health, recovery)
// without any subject/catalog check.
func (m *AuthzMiddleware) phaseAllowlist(dr decisionRequest) (decision, bool) {
	if _, ok := m.allow[dr.FQN]; ok {
		m.metrics.RecordAllow()
		return decision{outcome: outcomeAllow, descriptor: permissionDeniedDescriptor{FQN: dr.FQN}}, true
	}
	return decision{}, false
}

// phaseInternalOriginExempt admits an `<exempt>` Internal* RPC ONLY when it
// arrived on the cluster-internal listener (not the advertised external TLS
// listener). Internal callers (api-gateway self-call, kacho-iam drainer,
// port-forward admin) carry no external user JWT, so the catalog's authN-
// enforcing exempt path would otherwise 401 them. Gated Internal* RPCs (a real
// `required_relation`, e.g. InternalClusterService) are NOT bypassed — they run
// the full subject-extraction + FGA Check below even on the internal listener.
// An external caller of any Internal* RPC is not admitted here and falls through
// to the normal catalog/authN path (deny / 401); the REST dispatcher
// independently 404s these on the external listener.
func (m *AuthzMiddleware) phaseInternalOriginExempt(dr decisionRequest) (decision, bool) {
	if allowlist.HasInternalSuffix("/"+dr.FQN) && !m.isExternalRequest(dr) {
		if entry, found := m.cfg.Catalog.Lookup(dr.FQN); found && entry.IsExempt() {
			m.metrics.RecordAllow()
			return decision{
				outcome:    outcomeAllow,
				descriptor: permissionDeniedDescriptor{FQN: dr.FQN, Action: entry.Permission},
				entry:      entry,
			}, true
		}
	}
	return decision{}, false
}

// phaseOverride applies a file-based per-route override (explicit allow/deny).
func (m *AuthzMiddleware) phaseOverride(dr decisionRequest) (decision, bool) {
	if m.cfg.Overrides == nil {
		return decision{}, false
	}
	dec, ok := m.cfg.Overrides.Lookup(dr.FQN)
	if !ok {
		return decision{}, false
	}
	switch dec {
	case OverrideAllow:
		m.metrics.RecordAllow()
		m.cfg.Logger.Info("authz override allow", "fqn", dr.FQN)
		return decision{outcome: outcomeAllow, descriptor: permissionDeniedDescriptor{FQN: dr.FQN}}, true
	case OverrideDeny:
		m.metrics.RecordDeny()
		m.cfg.Logger.Info("authz override deny", "fqn", dr.FQN)
		return decision{
			outcome:    outcomeDeny,
			reasons:    []string{"override: explicit deny"},
			descriptor: permissionDeniedDescriptor{FQN: dr.FQN},
		}, true
	}
	return decision{}, false
}

// phaseCatalog looks up the catalog entry. It returns handled=true for the two
// terminal catalog outcomes: an `<exempt>` entry (allow, or 401 when
// unauthenticated) and a catalog miss (deny). Otherwise it returns the resolved
// entry with handled=false so the pipeline continues to subject extraction.
func (m *AuthzMiddleware) phaseCatalog(ctx context.Context, dr decisionRequest) (CatalogEntry, decision, bool) {
	entry, found := m.cfg.Catalog.Lookup(dr.FQN)
	if found && entry.IsExempt() {
		// `<exempt>` skips the FGA authz check, NOT authentication.
		// An exempt RPC (scope-filter List, tenant-wide catalog read) still
		// requires an authenticated principal — the handler's own scope-filter
		// is meaningless for an anonymous caller. Without this gate an
		// anonymous request (no Bearer → injected system:anonymous principal)
		// would reach exempt List RPCs and get a 200 empty page instead of 401.
		exemptVerified, _ := verifiedTokenFromCtxOrHTTP(ctx, dr.HTTPReq)
		if _, authned := m.cfg.Subjects.Extract(exemptVerified); !authned {
			// No credentials on an exempt RPC → Unauthenticated(16),
			// not PermissionDenied(7). The request was not even authenticated; a
			// "deny" response would mislead callers into thinking they are
			// authenticated but forbidden.
			m.metrics.RecordDeny()
			return entry, decision{
				outcome: outcomeUnauthenticated,
				reasons: []string{"subject: unauthenticated request"},
				descriptor: permissionDeniedDescriptor{
					FQN:    dr.FQN,
					Action: entry.Permission,
				},
				entry: entry,
			}, true
		}
		m.metrics.RecordAllow()
		return entry, decision{
			outcome:    outcomeAllow,
			descriptor: permissionDeniedDescriptor{FQN: dr.FQN, Action: entry.Permission},
			entry:      entry,
		}, true
	}
	if !found {
		// Production policy: deny when catalog has no entry — every RPC must
		// be classified. Dev / staging may surface this differently via the
		// overrides file (explicit allow).
		//
		// Classify the denial reason based on authentication status
		// so the caller (and observability) can distinguish:
		//   - authenticated caller hitting an uncatalogued method →
		//     PermissionDenied ("catalog: no entry for method") — 403
		//   - unauthenticated caller hitting an uncatalogued method →
		//     PermissionDenied ("catalog: no entry for method; unauthenticated")
		// Both are code 7 (PermissionDenied) — we never reveal internal
		// resource existence to unauthenticated callers, and we don't upgrade
		// to Unauthenticated (16) for uncatalogued methods because the method
		// itself is unknown/denied regardless of auth state.
		missVerified, _ := verifiedTokenFromCtxOrHTTP(ctx, dr.HTTPReq)
		_, isAuthed := m.cfg.Subjects.Extract(missVerified)
		missReason := "catalog: no entry for method"
		if !isAuthed {
			missReason = "catalog: no entry for method; unauthenticated"
		}
		m.metrics.RecordDeny()
		m.cfg.Logger.Warn("authz catalog miss, denying",
			"fqn", dr.FQN,
			"authenticated", isAuthed)
		return entry, decision{
			outcome: outcomeDeny,
			reasons: []string{missReason},
			descriptor: permissionDeniedDescriptor{
				FQN: dr.FQN,
			},
		}, true
	}
	return entry, decision{}, false
}

// phaseSubject extracts the authenticated subject. A missing/invalid credential
// terminates with Unauthenticated(16)/401. On success it returns the verified
// token and resolved subject for the downstream phases.
func (m *AuthzMiddleware) phaseSubject(ctx context.Context, dr decisionRequest, entry CatalogEntry) (*VerifiedToken, ResolvedSubject, decision, bool) {
	verified, _ := verifiedTokenFromCtxOrHTTP(ctx, dr.HTTPReq)
	subj, ok := m.cfg.Subjects.Extract(verified)
	if !ok {
		// No authenticated subject (no JWT / invalid JWT) →
		// Unauthenticated(16) / 401, not PermissionDenied(7) / 403.
		// gRPC convention: UNAUTHENTICATED means "the caller is not identified";
		// PERMISSION_DENIED means "identified caller has no access to the resource".
		m.metrics.RecordDeny()
		return verified, subj, decision{
			outcome: outcomeUnauthenticated,
			reasons: []string{"subject: unauthenticated request"},
			descriptor: permissionDeniedDescriptor{
				FQN:    dr.FQN,
				Action: entry.Permission,
			},
			entry: entry,
		}, true
	}
	return verified, subj, decision{}, false
}

// phaseResource resolves the FGA resource scope (type + id) and applies the
// malformed-id short-circuit (5b). It returns handled=true only for the
// malformed-id case (InvalidArgument/400); otherwise it returns the resolved
// scope + descriptor for the Check phase.
func (m *AuthzMiddleware) phaseResource(dr decisionRequest, entry CatalogEntry, subj ResolvedSubject) (ResourceID, string, permissionDeniedDescriptor, decision, bool) {
	var resourceID ResourceID
	if dr.HTTPReq != nil {
		resourceID, _ = m.cfg.Resources.ExtractFromHTTP(dr.HTTPReq, dr.FQN, entry)
	} else if dr.ProtoReq != nil {
		resourceID, _ = m.cfg.Resources.ExtractFromProto(dr.ProtoReq, entry)
	} else {
		resourceID = ResourceID("*")
	}
	resourceType := entry.ScopeExtractor.ObjectType
	// Scope-polymorphic RPCs (e.g. AccessBindingService.ListByScope) carry
	// the FGA object type in a request field (catalog
	// `object_type_from_request_field`, value project|account|cluster). When
	// declared + present, it overrides the static `object_type` — otherwise an
	// account/cluster-scoped read would check `project:<id>` → 403.
	// `object_type` remains the fallback when the field is absent/empty.
	if otField := strings.TrimSpace(entry.ScopeExtractor.ObjectTypeFromRequestField); otField != "" {
		var dynType string
		if dr.HTTPReq != nil {
			dynType = m.cfg.Resources.ScopeTypeFromHTTP(dr.HTTPReq, otField)
		} else if dr.ProtoReq != nil {
			dynType = m.cfg.Resources.ScopeTypeFromProto(dr.ProtoReq, otField)
		}
		if dynType != "" {
			resourceType = dynType
		}
	}
	if resourceType == "" {
		// Project-level scope is the platform default (every
		// permission has a project scope unless overridden — top-level
		// `cluster` / `organization` types use explicit object_type).
		resourceType = "project"
	}

	// cluster — это singleton (`cluster_kacho_root`,
	// см. kacho-iam/internal/domain/cluster.go::ClusterSingletonID).
	// Catalog для reference-data (compute.Region/Zone, etc.) задает
	// scope_extractor: {object_type: cluster, from_request_field: '*'}.
	// Extractor выдает ResourceID("*") → object="cluster:*" → kacho-iam
	// AuthorizeService.Check отбивает с "no path: unscoped resource"
	// (authorize_service.go блокирует req.Resource.ID == "*"). Тут
	// substitute'им wildcard на канонический singleton id, чтобы Check
	// шел на cluster:cluster_kacho_root, где tuple-cascade
	// `define viewer: [user, user:*, ...]` действительно работает.
	if resourceType == "cluster" && resourceID.IsWildcard() {
		resourceID = ResourceID("cluster_kacho_root")
	}

	descriptor := permissionDeniedDescriptor{
		FQN:          dr.FQN,
		Subject:      subj.FGA,
		Action:       entry.Permission,
		ResourceType: resourceType,
		ResourceID:   resourceID.String(),
	}

	// 5b. Malformed-id short-circuit.
	//
	// For an entry whose scope is a CONCRETE per-resource id (the
	// `from_request_field` names a real resource-id field, not the wildcard /
	// subject-as-scope / scope-polymorphic forms), a syntactically-invalid id
	// (unknown 3-char prefix / wrong length) must surface as InvalidArgument(3)
	// /400 — the Kachō convention — instead of reaching the FGA Check, where a
	// no-path deny would mask it as PermissionDenied(7)/403. We deliberately do
	// NOT validate the scope-polymorphic path (`object_type_from_request_field`),
	// where `resource_id` is a foreign-family scope id, nor the wildcard /
	// subject forms. Well-formed-but-nonexistent ids still pass through to the
	// FGA Check → 403 (existence-leak protection, by design). The result is NOT
	// cached: it is a property of the request input, not of subject↔resource
	// authz state.
	if isConcreteResourceScope(entry) && !resourceID.IsWildcard() && resourceID.String() != "" {
		if err := corevalidate.ResourceID("resource", "", resourceID.String()); err != nil {
			m.metrics.RecordDeny()
			m.cfg.Logger.Info("authz invalid resource id",
				"fqn", dr.FQN,
				"subject", subj.FGA,
				"action", entry.Permission,
				"resource", descriptor.ResourceType+":"+descriptor.ResourceID,
			)
			return resourceID, resourceType, descriptor, decision{
				outcome:      outcomeInvalidArgument,
				reasons:      []string{"resource id is malformed"},
				descriptor:   descriptor,
				entry:        entry,
				invalidArgID: resourceID.String(),
			}, true
		}
	}
	return resourceID, resourceType, descriptor, decision{}, false
}

// phaseCheck builds the Conditions context, consults the decision cache
// (write-after-invalidate epoch-guarded) and, on a miss, runs the IAM FGA Check.
// It is the terminal phase — it always returns a decision.
func (m *AuthzMiddleware) phaseCheck(
	ctx context.Context,
	dr decisionRequest,
	entry CatalogEntry,
	verified *VerifiedToken,
	subj ResolvedSubject,
	resourceID ResourceID,
	resourceType string,
	descriptor permissionDeniedDescriptor,
) decision {
	// 6. Context build.
	var contextMap map[string]any
	if dr.HTTPReq != nil {
		contextMap = m.cfg.Context.BuildHTTP(verified, dr.HTTPReq, subj)
	} else if dr.GRPCMeta != nil || dr.GRPCPeer != "" {
		contextMap = m.cfg.Context.BuildPeerAddr(verified, peerAddrToAddr(dr.GRPCPeer), grpcMetaForwardedFor(dr.GRPCMeta), subj)
	} else {
		contextMap = m.cfg.Context.BuildHTTP(verified, nil, subj)
	}

	// 7. Decision cache lookup.
	traceID := traceFromContext(ctx, dr.HTTPReq, dr.GRPCMeta)
	cacheKey := buildCacheKey(subj.FGA, entry.Permission, resourceType, resourceID.String(), contextMap)
	// Snapshot the invalidation generation BEFORE reading the cache. Any
	// Invalidate/InvalidateSubject that races the upcoming Check will move the
	// generation, and the put below is dropped so a grant revoked mid-Check is
	// never re-cached (write-after-invalidate guard; CWE-362 + CWE-613).
	cacheGen := m.cache.generation()
	if cached, ok := m.cache.get(cacheKey); ok {
		m.metrics.RecordCacheHit()
		if cached.allowed {
			m.metrics.RecordAllow()
			return decision{outcome: outcomeAllow, descriptor: descriptor, entry: entry}
		}
		m.metrics.RecordDeny()
		return denyDecision(dr.FQN, entry, descriptor, cached.reasons)
	}
	m.metrics.RecordCacheMiss()

	// 8. IAM Check.
	result, err := m.cfg.Checker.Check(ctx, AuthzCheckInput{
		Subject: subj.FGA,
		Action:  entry.Permission,
		// Pass catalog's required_relation through to
		// IAM so admin-only RPCs (system_admin) gate correctly even when
		// the verb (`list`/`get`) would otherwise derive to `viewer`.
		RequiredRelation: entry.RequiredRelation,
		ResourceType:     resourceType,
		ResourceID:       resourceID.String(),
		Context:          contextMap,
		TraceID:          traceID,
	})
	if err != nil {
		// PermissionDenied surfaced as an error from the gRPC stub is a
		// real deny (the AuthorizeService returns `allowed=false` with
		// reasons, but defensive code handles both shapes).
		if code := status.Code(err); code == codes.PermissionDenied {
			st, _ := status.FromError(err)
			m.metrics.RecordDeny()
			reasons := []string{st.Message()}
			m.cache.putIfGen(cacheKey, decisionCacheEntry{allowed: false, reasons: reasons}, cacheGen)
			return denyDecision(dr.FQN, entry, descriptor, reasons)
		}
		m.metrics.RecordError()
		m.cfg.Logger.Error("authz check failed",
			"fqn", dr.FQN,
			"subject", subj.FGA,
			"action", entry.Permission,
			"resource", descriptor.ResourceType+":"+descriptor.ResourceID,
			"err", err,
		)
		return decision{outcome: outcomeError, checkErr: err, descriptor: descriptor, entry: entry}
	}

	if result.Allowed {
		m.cache.putIfGen(cacheKey, decisionCacheEntry{allowed: true}, cacheGen)
		m.metrics.RecordAllow()
		m.cfg.Logger.Info("authz allow",
			"fqn", dr.FQN,
			"subject", subj.FGA,
			"action", entry.Permission,
			"resource", descriptor.ResourceType+":"+descriptor.ResourceID,
			"risk", entry.RiskLevel,
			"model_id", result.AuthorizationModelID,
		)
		return decision{outcome: outcomeAllow, descriptor: descriptor, entry: entry}
	}

	reasons := result.DenyReasons
	if len(reasons) == 0 {
		reasons = []string{"no path"}
	}
	m.cache.putIfGen(cacheKey, decisionCacheEntry{allowed: false, reasons: reasons}, cacheGen)
	m.metrics.RecordDeny()
	m.cfg.Logger.Info("authz deny",
		"fqn", dr.FQN,
		"subject", subj.FGA,
		"action", entry.Permission,
		"resource", descriptor.ResourceType+":"+descriptor.ResourceID,
		"reasons", reasons,
		"risk", entry.RiskLevel,
		"hide_existence", entry.HidesExistenceOnDeny(dr.FQN),
	)
	return denyDecision(dr.FQN, entry, descriptor, reasons)
}

// denyDecision builds the terminal decision for an authz deny on a known catalog
// entry. For a hide-existence read RPC (HidesExistenceOnDeny) it returns
// outcomeNotFound — NotFound(5)/404 with NO deny reasons — so the gateway does
// not override the resource owner's hide-existence contract or leak the reasons.
// Otherwise it returns the regular outcomeDeny — PermissionDenied(7)/403 with
// reasons. Enforcement is identical in both cases: the request is blocked.
func denyDecision(fqn string, entry CatalogEntry, descriptor permissionDeniedDescriptor, reasons []string) decision {
	if entry.HidesExistenceOnDeny(fqn) {
		return decision{
			outcome:    outcomeNotFound,
			descriptor: descriptor,
			entry:      entry,
		}
	}
	return decision{
		outcome:    outcomeDeny,
		reasons:    reasons,
		descriptor: descriptor,
		entry:      entry,
	}
}
