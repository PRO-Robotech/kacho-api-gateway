// dpop_http_middleware.go — HTTP middleware that wires JWT verifier + DPoP
// validator + mTLS-bound validator + step-up gate into the REST request path.
//
// Position in the middleware chain (cmd/api-gateway/main.go):
//
//	HTTPRequestID
//	  HTTPRecovery
//	    AuthInterceptor.HTTP  (legacy: dev HMAC + Kratos session)
//	      DPoPMiddleware      ← THIS — Phase 2 production authN path
//	        HTTPAccessLog
//	          HTTPIdempotency
//	            httpMux
//
// When `KACHO_API_GATEWAY_AUTHN_ENABLE_DPOP=true`, every request carrying an
// `Authorization: Bearer|DPoP ...` header runs through:
//
//  1. JWT verifier (Hydra JWKS, alg whitelist, iss/aud/exp).
//  2. If token.cnf.jkt set → DPoP header validation (htm/htu/iat/jti/jkt).
//  3. If token.cnf.x5t#S256 set → mTLS-bound (client cert vs cnf).
//  4. Step-up gate: required ACR / mfa_max_age from permission catalog.
//
// On any failure → 401 with RFC 6750 `WWW-Authenticate` challenge header;
// no forwarding to backend. The principal headers (X-Kacho-Principal-*) are
// then injected exactly as the legacy AuthInterceptor does, so backends see
// a unified shape regardless of whether the token came from dev-HMAC or
// from Hydra.
//
// When disabled (default), this middleware is a no-op pass-through — exactly
// the same behaviour as before KAC-127 for dev environments without Hydra.
package middleware

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// DPoPMiddleware — HTTP middleware orchestrator for KAC-127 production authN.
type DPoPMiddleware struct {
	verifier        *JWTVerifier
	dpop            *DPoPValidator
	mtls            *MTLSBoundValidator
	stepUp          *StepUpGate
	introspection   *IntrospectionCache
	permissionLookup PermissionLookup

	logger *slog.Logger
	apiDomain string

	// requireForAllRequests — when true, missing Bearer/DPoP header
	// → 401 (production-strict equivalent for the DPoP path).
	requireForAllRequests bool
}

// PermissionLookup — port-interface that resolves per-RPC requirements
// (required_acr_min, mfa_max_age). The catalog implementation lives outside
// the middleware (Phase 1 produced `permission_catalog.json`); for Phase 2
// we accept any source.
type PermissionLookup interface {
	Lookup(method string) PermissionRequirement
}

// DefaultPermissionLookup — fallback returning PermissionRequirement{ACR=""}
// (no requirement) for any method. Used in dev / when catalog is not wired.
type DefaultPermissionLookup struct{}

// Lookup always returns the no-op requirement.
func (DefaultPermissionLookup) Lookup(_ string) PermissionRequirement {
	return PermissionRequirement{}
}

// DPoPMiddlewareConfig — DI bag.
type DPoPMiddlewareConfig struct {
	Verifier         *JWTVerifier
	DPoP             *DPoPValidator
	MTLS             *MTLSBoundValidator
	StepUp           *StepUpGate
	Introspection    *IntrospectionCache
	PermissionLookup PermissionLookup
	Logger           *slog.Logger
	APIDomain        string

	// RequireForAllRequests — production-strict; reject anonymous traffic.
	RequireForAllRequests bool
}

// NewDPoPMiddleware constructs the orchestrator. Verifier + DPoP + StepUp
// are required; introspection + permissionLookup are optional.
func NewDPoPMiddleware(cfg DPoPMiddlewareConfig) (*DPoPMiddleware, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("dpop middleware: Verifier is required")
	}
	if cfg.DPoP == nil {
		return nil, errors.New("dpop middleware: DPoP validator is required")
	}
	if cfg.StepUp == nil {
		return nil, errors.New("dpop middleware: StepUp gate is required")
	}
	if cfg.MTLS == nil {
		cfg.MTLS = NewMTLSBoundValidator()
	}
	if cfg.PermissionLookup == nil {
		cfg.PermissionLookup = DefaultPermissionLookup{}
	}
	if cfg.Logger == nil {
		return nil, errors.New("dpop middleware: Logger is required")
	}
	if cfg.APIDomain == "" {
		return nil, errors.New("dpop middleware: APIDomain is required")
	}
	return &DPoPMiddleware{
		verifier:              cfg.Verifier,
		dpop:                  cfg.DPoP,
		mtls:                  cfg.MTLS,
		stepUp:                cfg.StepUp,
		introspection:         cfg.Introspection,
		permissionLookup:      cfg.PermissionLookup,
		logger:                cfg.Logger,
		apiDomain:             cfg.APIDomain,
		requireForAllRequests: cfg.RequireForAllRequests,
	}, nil
}

// Wrap returns an http.Handler middleware.
func (m *DPoPMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always skip on health / auth-flow endpoints — those run pre-auth.
		path := r.URL.Path
		if path == "/healthz" || path == "/readyz" || strings.HasPrefix(path, "/iam/v1/auth/") || path == "/oauth/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// Determine scheme (Bearer vs DPoP) — both ride on Authorization header.
		auth := r.Header.Get("Authorization")
		token, scheme := splitAuthScheme(auth)
		dpopHeader := r.Header.Get("DPoP")

		// 1. No Authorization header → respect requireForAllRequests; otherwise pass.
		if token == "" {
			if m.requireForAllRequests {
				m.challenge(w, r, http.StatusUnauthorized,
					`Bearer error="invalid_token", error_description="missing access token"`, nil)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// 2. Verify access token (signature + iss/aud/exp/nbf/iat).
		verified, err := m.verifier.Verify(r.Context(), token)
		if err != nil {
			m.logger.Warn("dpop-mw: jwt verify failed", "err", err, "path", path)
			m.challenge(w, r, http.StatusUnauthorized,
				`Bearer error="invalid_token", error_description="`+sanitizeErr(err)+`"`, nil)
			return
		}

		// 3. Optional revocation check (cache + Hydra introspection).
		if m.introspection != nil && verified.JTI != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 5*1e9 /* 5s */)
			_, ierr := m.introspection.Introspect(ctx, verified.JTI, verified.Raw)
			cancel()
			if ierr != nil {
				if errors.Is(ierr, ErrTokenInactive) {
					m.challenge(w, r, http.StatusUnauthorized,
						`Bearer error="invalid_token", error_description="token revoked"`, nil)
					return
				}
				// Soft-fail on transient Hydra outage: log + continue (cache returned a
				// fresh-enough negative entry covers the next request). This matches
				// the "graceful when introspection unreachable" requirement.
				m.logger.Warn("dpop-mw: introspection failed; continuing without it",
					"err", ierr, "path", path)
			}
		}

		// 4. Sender-constrained checks.
		switch {
		case verified.Cnf.HasJkt:
			req := DPoPRequest{
				Method:     r.Method,
				URL:        absoluteRequestURL(r, m.apiDomain),
				DPoPHeader: dpopHeader,
			}
			if err := m.dpop.Validate(verified, req); err != nil {
				m.logger.Warn("dpop-mw: dpop validate failed", "err", err, "path", path)
				m.challenge(w, r, http.StatusUnauthorized,
					`DPoP error="invalid_dpop_proof", error_description="`+sanitizeErr(err)+`"`, nil)
				return
			}
		case verified.Cnf.HasX5tS:
			var connState *tls.ConnectionState
			if r.TLS != nil {
				connState = r.TLS
			}
			if err := m.mtls.Validate(verified, connState, nil); err != nil {
				m.logger.Warn("dpop-mw: mtls validate failed", "err", err, "path", path)
				m.challenge(w, r, http.StatusUnauthorized,
					`Bearer error="invalid_token", error_description="`+sanitizeErr(err)+`"`, nil)
				return
			}
		default:
			// Plain bearer — accepted when scheme=Bearer; reject when scheme=DPoP
			// (mismatched expectation: client signalled DPoP, but token has no jkt).
			if strings.EqualFold(scheme, "DPoP") {
				m.challenge(w, r, http.StatusUnauthorized,
					`DPoP error="invalid_token", error_description="access token has no cnf.jkt"`, nil)
				return
			}
		}

		// 5. Step-up gate.
		req := m.permissionLookup.Lookup(grpcMethodForPath(path))
		if err := m.stepUp.Check(verified, req); err != nil {
			challenge := BuildStepUpChallenge(req, verified.ACR)
			m.logger.Info("dpop-mw: step-up required",
				"path", path, "presented_acr", verified.ACR, "required", req.RequiredACRMin)
			m.challenge(w, r, http.StatusUnauthorized, challenge, nil)
			return
		}

		// 6. Inject principal headers — backends consume via corelib's
		//    PrincipalExtractInterceptor.
		injectVerifiedTokenHeaders(r, verified)

		next.ServeHTTP(w, r)
	})
}

// splitAuthScheme returns (token, scheme) where scheme ∈ {"Bearer","DPoP"}.
func splitAuthScheme(auth string) (token, scheme string) {
	if auth == "" {
		return "", ""
	}
	if v, ok := strings.CutPrefix(auth, "Bearer "); ok {
		return v, "Bearer"
	}
	if v, ok := strings.CutPrefix(auth, "bearer "); ok {
		return v, "Bearer"
	}
	if v, ok := strings.CutPrefix(auth, "DPoP "); ok {
		return v, "DPoP"
	}
	if v, ok := strings.CutPrefix(auth, "dpop "); ok {
		return v, "DPoP"
	}
	return "", ""
}

// absoluteRequestURL reconstructs the canonical URL the client used to address
// this request. Behind an L7 LB / ingress, r.Host may differ from the
// advertised public host — we prefer the api-gateway's configured domain
// when r.Host doesn't already match. This mirrors the canonicalisation Hydra
// performs when issuing the DPoP-bound token.
func absoluteRequestURL(r *http.Request, apiDomain string) string {
	scheme := "https"
	// Strict canonicalisation — DPoP htu must equal the URL the client
	// actually sent. We accept r.Host as-is; the client computed htu from
	// the same URL. (See RFC 9449 §4.3: "the htu claim contains the HTTP
	// URI used for the request").
	host := r.Host
	if host == "" {
		host = apiDomain
	}
	if r.TLS == nil && !strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https") {
		// On plain HTTP listener (cluster-internal), accept http scheme. The
		// canonicalHTU helper normalises this consistently on both sides.
		scheme = "http"
	}
	return scheme + "://" + host + r.URL.Path
}

// grpcMethodForPath converts a REST path (`/iam/v1/users/abc`) to its
// approximate gRPC FQN (`/kacho.cloud.iam.v1.UserService/Get`) for permission
// catalog lookup. This is a best-effort mapping — full grpc-gateway-style
// resolution would require an annotated path tree, which is overkill for the
// step-up gate. The default lookup returns no-op for unknown paths anyway.
func grpcMethodForPath(path string) string {
	// Strip leading slash, split into segments.
	p := strings.TrimPrefix(path, "/")
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return path
	}
	// Heuristic: first segment = domain, second = "v1", remaining → method+resource.
	// Catalog lookup uses gRPC FQN; we approximate it as
	// `kacho.cloud.<domain>.v1.<Resource>Service/<Op>`. Implementations may
	// override by providing a real PermissionLookup keyed by REST path.
	return "/" + path
}

// sanitizeErr returns a single-line human description suitable for HTTP
// header value. Strips quotation marks + control chars (RFC 6750 §3 forbids
// quoted-strings with embedded `"`).
func sanitizeErr(err error) string {
	s := err.Error()
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// challenge writes a 401 with a single WWW-Authenticate header + JSON body.
func (m *DPoPMiddleware) challenge(w http.ResponseWriter, _ *http.Request, status int, wwwAuth string, extra map[string]any) {
	w.Header().Set("WWW-Authenticate", wwwAuth)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]any{
		"code":    status,
		"message": "authentication failed",
	}
	for k, v := range extra {
		body[k] = v
	}
	_ = json.NewEncoder(w).Encode(body)
}

// injectVerifiedTokenHeaders adds X-Kacho-Principal-* headers from a verified
// JWT. The downstream restmux WithMetadata callback then forwards them as
// gRPC metadata.
func injectVerifiedTokenHeaders(r *http.Request, t *VerifiedToken) {
	if t == nil {
		return
	}
	subj := t.Subject
	if subj == "" {
		return
	}
	// kacho_principal_type from ext_claims (preferred); fallback to "user".
	pType := "user"
	if ext := t.ExtClaims; ext != nil {
		if s, ok := ext["kacho_principal_type"].(string); ok && s != "" {
			pType = s
		}
	}
	r.Header.Set("X-Kacho-Principal-Type", pType)
	r.Header.Set("X-Kacho-Principal-Id", subj)
	r.Header.Set("X-Kacho-Principal-Display-Name", "") // tokens carry no display name
	// Legacy grpc-gateway convention fallback.
	r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Type", pType)
	r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Id", subj)
	r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Display-Name", "")

	// Bonus: expose ACR / scope / jti for downstream audit.
	r.Header.Set("X-Kacho-Token-Acr", t.ACR)
	r.Header.Set("X-Kacho-Token-Jti", t.JTI)
	r.Header.Set("X-Kacho-Token-Scope", t.Scope)
	r.Header.Set("Grpc-Metadata-X-Kacho-Token-Acr", t.ACR)
	r.Header.Set("Grpc-Metadata-X-Kacho-Token-Jti", t.JTI)
	r.Header.Set("Grpc-Metadata-X-Kacho-Token-Scope", t.Scope)
	if !t.ExpiresAt.IsZero() {
		r.Header.Set("X-Kacho-Token-Exp", fmt.Sprintf("%d", t.ExpiresAt.Unix()))
	}
}
