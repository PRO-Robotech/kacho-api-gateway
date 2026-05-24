// authz.go — per-RPC AuthZ middleware for the api-gateway (KAC-127 Phase 3).
//
// Position in the middleware chain (mounted after Phase 2 JWT-verifier):
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// AuthzCheckInput — caller-friendly Check arguments. Mirrors
// `clients.AuthorizeCheckInput` to avoid a middleware → clients import
// cycle (clients itself imports middleware for Subject / ResolvedSubject
// types). Adapters convert between the two shapes.
type AuthzCheckInput struct {
	Subject      string
	Action       string
	ResourceType string
	ResourceID   string
	Context      map[string]any
	TraceID      string
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
	// fail-closed per запрет #6 spirit — never leak access on failure).
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
// state takes effect immediately for this replica (WS-2.3 self-flush). Sibling
// replicas converge via the subject-change poll-loop (WS-2.3 Task 4).
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

// InvalidateCache flushes the whole authz decision cache. Used by the WS-2.3
// subject-change watcher (Task 4) to converge this replica after a grant change
// observed on another replica. No-op when authz is disabled (cache is nil).
func (m *AuthzMiddleware) InvalidateCache() {
	if m.cache != nil {
		m.cache.Invalidate()
	}
}

// AsInvalidator returns a small port (Invalidator) over this middleware's
// decision cache, used by the W1.2 (KAC-138) InternalAuthzCacheService
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
			// KAC-130 BUG-2: no credentials → Unauthenticated(16), not PermissionDenied(7).
			return nil, decision.gRPCStatus().Err()
		case outcomeError:
			if m.cfg.FailOpen {
				m.cfg.Logger.Error("authz middleware fail-open: passing request despite error",
					"fqn", fqn, "err", decision.checkErr)
				return handler(ctx, req)
			}
			return nil, status.Errorf(codes.Unavailable,
				"authz service unavailable: %v", decision.checkErr)
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
			// KAC-130 BUG-2: no credentials → Unauthenticated(16), not PermissionDenied(7).
			return decision.gRPCStatus().Err()
		case outcomeError:
			if m.cfg.FailOpen {
				m.cfg.Logger.Error("authz middleware fail-open: passing stream despite error",
					"fqn", fqn, "err", decision.checkErr)
				return handler(srv, ss)
			}
			return status.Errorf(codes.Unavailable,
				"authz service unavailable: %v", decision.checkErr)
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
		// Phase 2 already short-circuits health/auth-flow URLs. We still
		// guard here for completeness when the middleware is mounted
		// without Phase 2 (dev mode).
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
			// KAC-130 BUG-2: no credentials → 401 Unauthorized + code 16,
			// not 403 Forbidden + code 7.
			writeHTTPUnauth(w, decision.descriptor, decision.reasons)
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
	// KAC-130 BUG-2: gRPC/HTTP convention (RFC 7235, gRPC status code guide):
	//   missing/invalid credentials → 16 UNAUTHENTICATED → HTTP 401
	//   authenticated subject, access denied → 7 PERMISSION_DENIED → HTTP 403
	outcomeUnauthenticated
)

type decision struct {
	outcome    decisionOutcome
	reasons    []string
	descriptor permissionDeniedDescriptor
	checkErr   error
	entry      CatalogEntry
}

func (d decision) gRPCStatus() *status.Status {
	if d.outcome == outcomeUnauthenticated {
		return buildGRPCUnauthStatus(d.descriptor, d.reasons)
	}
	return buildGRPCDenyStatus(d.descriptor, d.reasons)
}

// requiredACRMin returns the catalog-declared ACR floor (default "2").
func (d decision) requiredACRMin() string {
	if d.entry.RequiredACRMin == "" {
		return "2"
	}
	return d.entry.RequiredACRMin
}

func (m *AuthzMiddleware) decide(ctx context.Context, dr decisionRequest) decision {
	start := m.now()
	defer func() {
		m.metrics.ObserveLatencyMs(float64(m.now().Sub(start).Microseconds()) / 1000.0)
	}()

	// 1. Allowlist short-circuit.
	if _, ok := m.allow[dr.FQN]; ok {
		m.metrics.RecordAllow()
		return decision{outcome: outcomeAllow, descriptor: permissionDeniedDescriptor{FQN: dr.FQN}}
	}

	// 2. Per-route override (file-based).
	if m.cfg.Overrides != nil {
		if dec, ok := m.cfg.Overrides.Lookup(dr.FQN); ok {
			switch dec {
			case OverrideAllow:
				m.metrics.RecordAllow()
				m.cfg.Logger.Info("authz override allow", "fqn", dr.FQN)
				return decision{outcome: outcomeAllow, descriptor: permissionDeniedDescriptor{FQN: dr.FQN}}
			case OverrideDeny:
				m.metrics.RecordDeny()
				m.cfg.Logger.Info("authz override deny", "fqn", dr.FQN)
				return decision{
					outcome:    outcomeDeny,
					reasons:    []string{"override: explicit deny"},
					descriptor: permissionDeniedDescriptor{FQN: dr.FQN},
				}
			}
		}
	}

	// 3. Catalog lookup.
	entry, found := m.cfg.Catalog.Lookup(dr.FQN)
	if found && entry.IsExempt() {
		// KAC-127: `<exempt>` skips the FGA authz check, NOT authentication.
		// An exempt RPC (scope-filter List, tenant-wide catalog read) still
		// requires an authenticated principal — the handler's own scope-filter
		// is meaningless for an anonymous caller. Without this gate an
		// anonymous request (no Bearer → injected system:anonymous principal)
		// reached exempt List RPCs and got a 200 empty page instead of 401.
		exemptVerified, _ := verifiedTokenFromCtxOrHTTP(ctx, dr.HTTPReq)
		if _, authned := m.cfg.Subjects.Extract(exemptVerified); !authned {
			// KAC-130 BUG-2: no credentials on an exempt RPC → Unauthenticated(16),
			// not PermissionDenied(7). The request was not even authenticated; a
			// "deny" response would mislead callers into thinking they are
			// authenticated but forbidden.
			m.metrics.RecordDeny()
			return decision{
				outcome: outcomeUnauthenticated,
				reasons: []string{"subject: unauthenticated request"},
				descriptor: permissionDeniedDescriptor{
					FQN:    dr.FQN,
					Action: entry.Permission,
				},
				entry: entry,
			}
		}
		m.metrics.RecordAllow()
		return decision{
			outcome:    outcomeAllow,
			descriptor: permissionDeniedDescriptor{FQN: dr.FQN, Action: entry.Permission},
			entry:      entry,
		}
	}
	if !found {
		// Production policy: deny when catalog has no entry — every RPC must
		// be classified. Dev / staging may surface this differently via the
		// overrides file (explicit allow).
		//
		// KAC-127: classify the denial reason based on authentication status
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
		return decision{
			outcome: outcomeDeny,
			reasons: []string{missReason},
			descriptor: permissionDeniedDescriptor{
				FQN: dr.FQN,
			},
		}
	}

	// 4. Subject extraction.
	verified, _ := verifiedTokenFromCtxOrHTTP(ctx, dr.HTTPReq)
	subj, ok := m.cfg.Subjects.Extract(verified)
	if !ok {
		// KAC-130 BUG-2: no authenticated subject (no JWT / invalid JWT) →
		// Unauthenticated(16) / 401, not PermissionDenied(7) / 403.
		// gRPC convention: UNAUTHENTICATED means "the caller is not identified";
		// PERMISSION_DENIED means "identified caller has no access to the resource".
		m.metrics.RecordDeny()
		return decision{
			outcome: outcomeUnauthenticated,
			reasons: []string{"subject: unauthenticated request"},
			descriptor: permissionDeniedDescriptor{
				FQN:    dr.FQN,
				Action: entry.Permission,
			},
			entry: entry,
		}
	}

	// 5. Resource extraction.
	var resourceID ResourceID
	if dr.HTTPReq != nil {
		resourceID, _ = m.cfg.Resources.ExtractFromHTTP(dr.HTTPReq, dr.FQN, entry)
	} else if dr.ProtoReq != nil {
		resourceID, _ = m.cfg.Resources.ExtractFromProto(dr.ProtoReq, entry)
	} else {
		resourceID = ResourceID("*")
	}
	resourceType := entry.ScopeExtractor.ObjectType
	if resourceType == "" {
		// Project-level scope is the platform default per design §4 (every
		// permission has a project scope unless overridden — top-level
		// `cluster` / `organization` types use explicit object_type).
		resourceType = "project"
	}

	// KAC-178 §3 follow-up: cluster — это singleton (`cluster_kacho_root`,
	// см. kacho-iam/internal/domain/cluster.go::ClusterSingletonID).
	// Catalog для reference-data (compute.Region/Zone, etc.) задаёт
	// scope_extractor: {object_type: cluster, from_request_field: '*'}.
	// Extractor выдаёт ResourceID("*") → object="cluster:*" → kacho-iam
	// AuthorizeService.Check отбивает с "no path: unscoped resource"
	// (authorize_service.go блокирует req.Resource.ID == "*"). Тут
	// substitute'им wildcard на канонический singleton id, чтобы Check
	// шёл на cluster:cluster_kacho_root, где tuple-cascade
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
	if cached, ok := m.cache.get(cacheKey); ok {
		m.metrics.RecordCacheHit()
		if cached.allowed {
			m.metrics.RecordAllow()
			return decision{outcome: outcomeAllow, descriptor: descriptor, entry: entry}
		}
		m.metrics.RecordDeny()
		return decision{
			outcome:    outcomeDeny,
			reasons:    cached.reasons,
			descriptor: descriptor,
			entry:      entry,
		}
	}
	m.metrics.RecordCacheMiss()

	// 8. IAM Check.
	result, err := m.cfg.Checker.Check(ctx, AuthzCheckInput{
		Subject:      subj.FGA,
		Action:       entry.Permission,
		ResourceType: resourceType,
		ResourceID:   resourceID.String(),
		Context:      contextMap,
		TraceID:      traceID,
	})
	if err != nil {
		// PermissionDenied surfaced as an error from the gRPC stub is a
		// real deny (the AuthorizeService returns `allowed=false` with
		// reasons, but defensive code handles both shapes).
		if code := status.Code(err); code == codes.PermissionDenied {
			st, _ := status.FromError(err)
			m.metrics.RecordDeny()
			reasons := []string{st.Message()}
			m.cache.put(cacheKey, decisionCacheEntry{allowed: false, reasons: reasons})
			return decision{
				outcome:    outcomeDeny,
				reasons:    reasons,
				descriptor: descriptor,
				entry:      entry,
			}
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
		m.cache.put(cacheKey, decisionCacheEntry{allowed: true})
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
	m.cache.put(cacheKey, decisionCacheEntry{allowed: false, reasons: reasons})
	m.metrics.RecordDeny()
	m.cfg.Logger.Info("authz deny",
		"fqn", dr.FQN,
		"subject", subj.FGA,
		"action", entry.Permission,
		"resource", descriptor.ResourceType+":"+descriptor.ResourceID,
		"reasons", reasons,
		"risk", entry.RiskLevel,
	)
	return decision{
		outcome:    outcomeDeny,
		reasons:    reasons,
		descriptor: descriptor,
		entry:      entry,
	}
}

// ---- helpers ----

// normalizeFQN strips the leading `/` from gRPC FullMethod and turns the
// `pkg.Service/Method` portion into the canonical FQN shape used by the
// catalog ("kacho.cloud.iam.v1.AuthorizeService/Check").
func normalizeFQN(full string) string {
	return strings.TrimPrefix(full, "/")
}

// peerAddr returns the client peer.Addr.String() from a gRPC context, or
// "" when no peer is attached.
func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// peerAddrToAddr — wraps a raw "ip:port" string in net.Addr (we use a thin
// shim because peer.Peer keeps the original net.Addr; the wrapper avoids
// re-parsing for the metric path).
func peerAddrToAddr(s string) addrShim {
	return addrShim(s)
}

type addrShim string

func (a addrShim) Network() string { return "tcp" }
func (a addrShim) String() string  { return string(a) }

// incomingMD returns the gRPC incoming metadata or nil.
func incomingMD(ctx context.Context) metadata.MD {
	md, _ := metadata.FromIncomingContext(ctx)
	return md
}

// grpcMetaForwardedFor extracts the X-Forwarded-For from grpc-gateway-
// rewritten metadata. Empty when absent.
func grpcMetaForwardedFor(md metadata.MD) string {
	if md == nil {
		return ""
	}
	// grpc-gateway rewrites incoming HTTP headers to `grpcgateway-<lower>`.
	if v := md.Get("grpcgateway-x-forwarded-for"); len(v) > 0 {
		return v[0]
	}
	if v := md.Get("x-forwarded-for"); len(v) > 0 {
		return v[0]
	}
	if v := md.Get("grpcgateway-x-real-ip"); len(v) > 0 {
		return v[0]
	}
	return ""
}

// verifiedTokenFromCtxOrHTTP — Phase 2 stores the verified token in the
// request headers (X-Kacho-Token-Acr / Jti / Scope / Exp) and in the
// gRPC metadata after the DPoP middleware ran. We reconstruct a thin
// VerifiedToken from the headers when needed. When the HTTP request is
// nil we fall back to gRPC metadata.
//
// This is a best-effort reconstruction — Phase 2 propagates principal
// + ACR + JTI + scope + exp; ext_claims would need a richer payload
// (KAC-127 Phase 2 spec). For Phase 3 we accept the limited view; the
// extractor degrades gracefully (empty AMR slices, missing mfa_at).
func verifiedTokenFromCtxOrHTTP(ctx context.Context, r *http.Request) (*VerifiedToken, bool) {
	var (
		acr   string
		jti   string
		scope string
		sub   string
		pType string
		extID string
	)
	if r != nil {
		acr = r.Header.Get("X-Kacho-Token-Acr")
		jti = r.Header.Get("X-Kacho-Token-Jti")
		scope = r.Header.Get("X-Kacho-Token-Scope")
		pType = r.Header.Get("X-Kacho-Principal-Type")
		sub = r.Header.Get("X-Kacho-Principal-Id")
	}
	if sub == "" || acr == "" {
		md := incomingMD(ctx)
		if md != nil {
			if v := md.Get("x-kacho-token-acr"); len(v) > 0 {
				acr = v[0]
			}
			if v := md.Get("x-kacho-token-jti"); len(v) > 0 {
				jti = v[0]
			}
			if v := md.Get("x-kacho-token-scope"); len(v) > 0 {
				scope = v[0]
			}
			if v := md.Get("x-kacho-principal-id"); len(v) > 0 {
				sub = v[0]
			}
			if v := md.Get("x-kacho-principal-type"); len(v) > 0 {
				pType = v[0]
			}
		}
	}
	if sub == "" {
		return nil, false
	}
	extClaims := map[string]any{
		"kacho_principal_type": defaultIfEmptyStr(pType, "user"),
		"kacho_principal_id":   sub,
	}
	if extID != "" {
		extClaims["kacho_external_id"] = extID
	}
	return &VerifiedToken{
		Subject:   sub,
		JTI:       jti,
		ACR:       acr,
		Scope:     scope,
		ExtClaims: extClaims,
	}, true
}

// defaultIfEmptyStr — tiny helper.
func defaultIfEmptyStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// resolveRestFQN best-effort maps an incoming HTTP request to a gRPC FQN
// the catalog can look up. Uses the explicit RestRouteResolver first, then
// falls back to the path-prefix heuristic from dpop_http_middleware.
func (m *AuthzMiddleware) resolveRestFQN(r *http.Request) string {
	if m.cfg.RestRouter != nil {
		if fqn, ok := m.cfg.RestRouter.Resolve(r.Method, r.URL.Path); ok {
			return fqn
		}
	}
	return grpcMethodForPath(r.URL.Path)
}

// isPublicHTTPPath returns true for fixed public endpoints (healthz, readyz,
// oauth flows). Matches dpop_http_middleware's allow-list — duplicated here
// so this middleware works correctly even when mounted without Phase 2.
func isPublicHTTPPath(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/oauth/logout":
		return true
	}
	if strings.HasPrefix(path, "/iam/v1/auth/") {
		return true
	}
	return false
}

// traceFromContext extracts the request-id for correlation, prioritising
// metadata over the gRPC context-key.
func traceFromContext(ctx context.Context, r *http.Request, md metadata.MD) string {
	if r != nil {
		if v := r.Header.Get("X-Request-Id"); v != "" {
			return v
		}
	}
	if md != nil {
		if v := md.Get("x-request-id"); len(v) > 0 {
			return v[0]
		}
		if v := md.Get("grpcgateway-x-request-id"); len(v) > 0 {
			return v[0]
		}
	}
	return RequestIDFromContext(ctx)
}

// ---- decision cache ----

// decisionCacheEntry — cached outcome.
type decisionCacheEntry struct {
	allowed bool
	reasons []string
}

// decisionCache — LRU-with-TTL, safe for concurrent use.
type decisionCache struct {
	mu      sync.Mutex
	entries map[string]*cacheNode
	head    *cacheNode // most-recently-used
	tail    *cacheNode // least-recently-used
	maxSize int
	ttl     time.Duration
	now     func() time.Time
}

type cacheNode struct {
	key       string
	value     decisionCacheEntry
	expiresAt time.Time
	prev      *cacheNode
	next      *cacheNode
}

func newDecisionCache(maxSize int, ttl time.Duration, now func() time.Time) *decisionCache {
	if now == nil {
		now = time.Now
	}
	return &decisionCache{
		entries: make(map[string]*cacheNode, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
		now:     now,
	}
}

func (c *decisionCache) get(key string) (decisionCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.entries[key]
	if !ok {
		return decisionCacheEntry{}, false
	}
	if c.now().After(n.expiresAt) {
		c.removeNode(n)
		delete(c.entries, key)
		return decisionCacheEntry{}, false
	}
	c.moveToHead(n)
	return n.value, true
}

func (c *decisionCache) put(key string, v decisionCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		existing.value = v
		existing.expiresAt = c.now().Add(c.ttl)
		c.moveToHead(existing)
		return
	}
	n := &cacheNode{key: key, value: v, expiresAt: c.now().Add(c.ttl)}
	c.entries[key] = n
	c.addToHead(n)
	if len(c.entries) > c.maxSize {
		evict := c.tail
		if evict != nil {
			c.removeNode(evict)
			delete(c.entries, evict.key)
		}
	}
}

// Invalidate removes ALL cache entries — used by the LISTEN/NOTIFY
// session_revocations push (Phase 2). Implementation-side wiring may
// further offer per-subject invalidation (filter keys by FGA prefix); for
// Phase 3 a full flush on session-revoke is acceptable (decisions are
// short-TTL anyway).
func (c *decisionCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheNode, c.maxSize)
	c.head = nil
	c.tail = nil
}

// InvalidateSubject removes cache entries for the given FGA subject prefix
// ("user:usr_abc"). Subject is appended verbatim — must match the form used
// at insert time.
func (c *decisionCache) InvalidateSubject(subject string) int {
	if subject == "" {
		return 0
	}
	prefix := subject + "|"
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for key, n := range c.entries {
		if strings.HasPrefix(key, prefix) {
			c.removeNode(n)
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

func (c *decisionCache) moveToHead(n *cacheNode) {
	if n == c.head {
		return
	}
	c.removeNode(n)
	c.addToHead(n)
}

func (c *decisionCache) addToHead(n *cacheNode) {
	n.prev = nil
	n.next = c.head
	if c.head != nil {
		c.head.prev = n
	}
	c.head = n
	if c.tail == nil {
		c.tail = n
	}
}

func (c *decisionCache) removeNode(n *cacheNode) {
	if n.prev != nil {
		n.prev.next = n.next
	} else if c.head == n {
		c.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else if c.tail == n {
		c.tail = n.prev
	}
	n.prev = nil
	n.next = nil
}

// Size returns the number of live cache entries.
func (c *decisionCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// buildCacheKey — stable cache key over (subject, action, resource,
// principal-binding context). Including `acr`/`mfa_at`/`client_ip` ensures
// step-up changes invalidate naturally; excluding `current_time`/`jti`
// avoids per-request cache busts.
func buildCacheKey(subject, action, resourceType, resourceID string, contextMap map[string]any) string {
	// Use a canonical concatenation of the security-affecting context keys
	// so equivalent contexts collide cleanly. We pick a subset to keep keys
	// reasonable in length; full-context-hash would change on harmless
	// fields and obliterate the cache.
	parts := []string{subject, action, resourceType, resourceID}
	if contextMap != nil {
		keys := []string{"acr_value", "mfa_at", "client_ip", "device_id", "passkey_aaguid"}
		sort.Strings(keys) // deterministic
		for _, k := range keys {
			if v, ok := contextMap[k]; ok {
				parts = append(parts, k+"="+fmt.Sprint(v))
			}
		}
	}
	raw := strings.Join(parts, "|")
	// Compress with sha256 for stable length (the cache map handles
	// collisions naturally — sha256 collision probability is negligible).
	sum := sha256.Sum256([]byte(raw))
	// Encode prefix + subject-prefix so InvalidateSubject can match.
	// Format: "<subject>|<sha256-hex>".
	return subject + "|" + hex.EncodeToString(sum[:])
}
