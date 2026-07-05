// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_util.go — transport/FQN/token helper functions extracted from the
// authz.go god-file. Pure movement, no behaviour change: these are the free
// functions the decision path calls (FQN normalisation, peer-addr + forwarded
// -for extraction, verified-token reconstruction from headers/metadata, trace
// correlation, public-path predicate, REST→FQN resolution, scope classification).
package middleware

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// isConcreteResourceScope reports whether the catalog entry's scope is a
// CONCRETE per-resource id — i.e. `from_request_field` names a real resource-id
// field (e.g. `network_id`, `access_binding_id`) rather than one of the
// non-id forms the resource-extractor recognises:
//
//   - ""        — no scope field (gateway-default scope);
//   - "*"       — wildcard (List/Search catch-all);
//   - "subject" — the subject is its own scope (AuthorizeService.Check);
//   - "resource"— a ResourceRef{type,id} wrapper (scope id is foreign-typed).
//
// It also excludes the scope-polymorphic path (`object_type_from_request_field`
// set): there the extracted `resource_id` is a scope id of an arbitrary family
// (project / account / cluster) carried for a ListByScope-style RPC, so the
// per-resource-id syntax check does not apply.
func isConcreteResourceScope(entry CatalogEntry) bool {
	if strings.TrimSpace(entry.ScopeExtractor.ObjectTypeFromRequestField) != "" {
		return false
	}
	switch strings.TrimSpace(entry.ScopeExtractor.FromRequestField) {
	case "", "*", "subject", "resource":
		return false
	default:
		return true
	}
}

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

// verifiedTokenFromCtxOrHTTP — the DPoP middleware stores the verified token in
// the request headers (X-Kacho-Token-Acr / Jti / Scope / Exp) and in the
// gRPC metadata after it ran. We reconstruct a thin
// VerifiedToken from the headers when needed. When the HTTP request is
// nil we fall back to gRPC metadata.
//
// This is a best-effort reconstruction — the upstream middleware propagates
// principal + ACR + JTI + scope + exp; ext_claims would need a richer payload.
// We accept the limited view; the
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
		acr = r.Header.Get(principalmeta.HeaderTokenACR)
		jti = r.Header.Get("X-Kacho-Token-Jti")
		scope = r.Header.Get("X-Kacho-Token-Scope")
		pType = r.Header.Get(principalmeta.HeaderPrincipalType)
		sub = r.Header.Get(principalmeta.HeaderPrincipalID)
	}
	if sub == "" || acr == "" {
		md := incomingMD(ctx)
		if md != nil {
			if v := md.Get(principalmeta.MetaTokenACR); len(v) > 0 {
				acr = v[0]
			}
			if v := md.Get("x-kacho-token-jti"); len(v) > 0 {
				jti = v[0]
			}
			if v := md.Get("x-kacho-token-scope"); len(v) > 0 {
				scope = v[0]
			}
			if v := md.Get(principalmeta.MetaPrincipalID); len(v) > 0 {
				sub = v[0]
			}
			if v := md.Get(principalmeta.MetaPrincipalType); len(v) > 0 {
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
// so this middleware works correctly even when mounted without the DPoP middleware.
func isPublicHTTPPath(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/oauth/logout":
		return true
	}
	return strings.HasPrefix(path, "/iam/v1/auth/")
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
