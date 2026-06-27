// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rest_router.go — RestRouteResolver implementation for the per-RPC authz
// middleware.
//
// The authz middleware's HTTP path must translate an incoming REST request
// into the canonical gRPC FQN so it can look the method up in the embedded
// permission catalog.
//
// This router matches the incoming `(method, path)` against the generated
// `generatedRestRoutes` table (built from `google.api.http` annotations in
// kacho-proto). Templates carry `{field}` placeholders and an optional
// grpc-gateway `:verb` suffix-action segment (e.g.
// `/iam/v1/users:invite`, `/vpc/v1/addressPools/{pool_id}:check`).
//
// Matching is O(routes) per request; the route table is ~322 entries and
// the decision cache (5s TTL) absorbs repeat lookups, so this is well within
// the per-RPC latency budget.
package middleware

import (
	"strings"
)

// RestRouter resolves REST (method, path) pairs to gRPC FQNs and exposes the
// reverse path-template map used by the ResourceExtractor's HTTP path
// strategy. It implements RestRouteResolver.
type RestRouter struct {
	// byMethod groups routes by HTTP method for a slightly tighter scan.
	byMethod map[string][]restRoute
	// fqnTemplate maps FQN -> path template (for ResourceExtractor).
	fqnTemplate map[string]string
}

// NewRestRouter builds a router from the build-time generated route table.
func NewRestRouter() *RestRouter {
	r := &RestRouter{
		byMethod:    make(map[string][]restRoute, 8),
		fqnTemplate: make(map[string]string, len(generatedRestRoutes)),
	}
	for _, rt := range generatedRestRoutes {
		r.byMethod[rt.Method] = append(r.byMethod[rt.Method], rt)
		// First binding wins for the reverse map — the primary binding is
		// emitted before additional_bindings by the extractor.
		if _, ok := r.fqnTemplate[rt.FQN]; !ok {
			r.fqnTemplate[rt.FQN] = rt.Template
		}
	}
	return r
}

// Resolve maps an HTTP (method, path) to a gRPC FQN. Returns ok=false when
// no route matches (unknown path) — the middleware then applies its public
// allowlist / deny-by-default policy.
func (r *RestRouter) Resolve(httpMethod, httpPath string) (string, bool) {
	httpMethod = strings.ToUpper(httpMethod)
	// Drop any query string.
	if i := strings.IndexByte(httpPath, '?'); i >= 0 {
		httpPath = httpPath[:i]
	}
	for _, rt := range r.byMethod[httpMethod] {
		if matchTemplate(rt.Template, httpPath) {
			return rt.FQN, true
		}
	}
	return "", false
}

// PathTemplates returns the FQN -> path-template map, suitable for wiring
// into NewResourceExtractor so the HTTP path strategy can pluck `{field}`
// placeholders out of the URL.
func (r *RestRouter) PathTemplates() map[string]string {
	out := make(map[string]string, len(r.fqnTemplate))
	for k, v := range r.fqnTemplate {
		out[k] = v
	}
	return out
}

// matchTemplate reports whether reqPath matches a grpc-gateway path template.
//
// Template grammar handled:
//   - literal segments               `/iam/v1/accounts`
//   - `{field}` placeholders         `/iam/v1/accounts/{account_id}`
//   - `{field=**}` deep placeholders  (rare; treated as single placeholder)
//   - `:verb` suffix action on the last segment `/iam/v1/users:invite`
func matchTemplate(template, reqPath string) bool {
	tSeg, tVerb := splitVerb(template)
	pSeg, pVerb := splitVerb(reqPath)
	if tVerb != pVerb {
		return false
	}
	tparts := splitPath(tSeg)
	pparts := splitPath(pSeg)
	if len(tparts) != len(pparts) {
		return false
	}
	for i, t := range tparts {
		if isPlaceholder(t) {
			// A placeholder matches any single, non-empty segment.
			if pparts[i] == "" {
				return false
			}
			continue
		}
		if t != pparts[i] {
			return false
		}
	}
	return true
}

// splitVerb separates an optional grpc-gateway `:verb` suffix-action from the
// last path segment. `/iam/v1/users:invite` -> ("/iam/v1/users", "invite").
func splitVerb(p string) (string, string) {
	// The `:verb` action only ever appears on the final segment.
	slash := strings.LastIndexByte(p, '/')
	last := p
	if slash >= 0 {
		last = p[slash+1:]
	}
	if colon := strings.IndexByte(last, ':'); colon >= 0 {
		verb := last[colon+1:]
		base := p[:len(p)-len(last)] + last[:colon]
		return base, verb
	}
	return p, ""
}

// splitPath tokenizes a path into its non-empty slash-separated segments.
func splitPath(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// isPlaceholder reports whether a template segment is a `{field}` capture.
func isPlaceholder(seg string) bool {
	return len(seg) >= 2 && seg[0] == '{' && seg[len(seg)-1] == '}'
}

// Ensure RestRouter satisfies the interface at compile time.
var _ RestRouteResolver = (*RestRouter)(nil)
