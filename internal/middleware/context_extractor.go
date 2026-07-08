// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// context_extractor.go — Build the OpenFGA Condition-evaluation context map
// from the verified JWT + HTTP request.
//
// OpenFGA `CheckRequest.Context` is a `google.protobuf.Struct` of arbitrary
// keys consumed by predicate-conditions:
//
//	mfa_fresh(amr_claims, acr_value, current_time, mfa_at)
//	non_expired(current_time, valid_until)
//	source_ip_in_range(client_ip, allowed_cidrs)
//	business_hours(current_time, tz, start_h, end_h)
//	device_compliant(device_attestation, allowed_attestations)
//	jit_window(current_time, activated_at, ttl_seconds)
//
// This extractor builds the *caller-side* half of those keys — the ones
// derivable from the JWT and the incoming HTTP request. Predicate-side
// parameters (`allowed_cidrs`, `valid_until`, `expires_at`, `tz`, ...) live
// in the FGA tuple's `condition.context` and are merged FGA-side.
//
// Reserved keys this extractor emits:
//
//	current_time        timestamp (seconds since epoch) — always
//	client_ip           string (canonical IP literal)   — when resolvable
//	acr_value           string ("0".."3")               — from token.ACR
//	amr_claims          []string                        — from token.AMR
//	mfa_at              timestamp                       — from ext_claims.kacho_mfa_at
//	device_attestation  string                          — from ext_claims.kacho_device_compliance
//	passkey_aaguid      string                          — from ext_claims.kacho_passkey_aaguid
//	device_id           string                          — from ext_claims.kacho_device_id
//	dpop_jkt            string                          — from token.Cnf.Jkt
//	auth_time           timestamp                       — from token.AuthTime
//	jti                 string                          — from token.JTI (for replay-trace correlation)
//	subject_kind        string ("user"/"service_account"/"workload"/"external")
//
// Beyond the reserved keys above, any remaining `kacho_*`-prefixed ext_claims
// are forwarded verbatim under their ORIGINAL key name (no prefix rewrite), so
// future Conditions can read them without an extractor change. Non-`kacho_*`
// ext_claims keys are dropped entirely. The FGA Conditions whitelist means
// tenant-supplied junk never participates in actual condition evaluation.
package middleware

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// ContextExtractor — stateless builder.
type ContextExtractor struct {
	// now — injectable clock for tests; defaults to time.Now.
	now func() time.Time

	// trustedXForwardedFor controls whether `X-Forwarded-For` / `X-Real-IP`
	// headers are honoured when computing `client_ip`. In production we sit
	// behind an L7 LB that strips client-supplied values and inserts the
	// trusted peer; on a misconfigured deploy a tenant could spoof
	// `source_ip_in_range` via a forged X-Forwarded-For. Default = true
	// (typical k8s ingress topology); operators can flip to false when
	// running api-gateway directly on the wire.
	trustedXForwardedFor bool

	// trustedProxyCount is the number of trusted reverse-proxy hops in front of
	// the gateway. X-Forwarded-For is read from the RIGHT — the client IP is the
	// entry the OUTERMOST trusted proxy recorded (parts[len-trustedProxyCount]).
	// A client can only forge entries to the LEFT of that trusted block, which we
	// never select, so a spoofed leftmost XFF can no longer drive `client_ip`.
	// 0 disables forwarded-header trust entirely (TCP peer is authoritative).
	// Default 1 (single k8s ingress).
	trustedProxyCount int
}

// ExtractorOption configures a ContextExtractor at construction.
type ExtractorOption func(*ContextExtractor)

// WithTrustedProxyHops sets the number of trusted reverse-proxy hops in front of
// the gateway (see ContextExtractor.trustedProxyCount). 0 disables
// forwarded-header trust; the TCP peer becomes authoritative.
func WithTrustedProxyHops(n int) ExtractorOption {
	return func(e *ContextExtractor) {
		if n < 0 {
			n = 0
		}
		e.trustedProxyCount = n
	}
}

// NewContextExtractor constructs an extractor. now=nil falls back to
// time.Now; trustedXForwardedFor toggles X-Forwarded-For honour (see field
// comment). The number of trusted proxy hops defaults to 1 and can be overridden
// with WithTrustedProxyHops.
func NewContextExtractor(now func() time.Time, trustedXForwardedFor bool, opts ...ExtractorOption) *ContextExtractor {
	if now == nil {
		now = time.Now
	}
	e := &ContextExtractor{now: now, trustedXForwardedFor: trustedXForwardedFor, trustedProxyCount: 1}
	for _, o := range opts {
		o(e)
	}
	return e
}

// BuildHTTP composes the context map for an HTTP request path.
//
// `subject` may be empty when the caller is anonymous; the function still
// builds a map (with `current_time` always present) so the FGA Check can run
// over `<exempt>`-like cases consistently.
func (e *ContextExtractor) BuildHTTP(t *VerifiedToken, r *http.Request, subj ResolvedSubject) map[string]any {
	out := map[string]any{
		// truncated to seconds to match OpenFGA Condition timestamps.
		"current_time": e.now().UTC().Truncate(time.Second).Unix(),
	}
	if r != nil {
		if ip := e.resolveClientIP(r); ip != "" {
			out["client_ip"] = ip
		}
	}
	e.fillFromToken(out, t)
	if subj.FGA != "" {
		out["subject_kind"] = subjectKindString(subj.Kind)
	}
	return out
}

// BuildPeerAddr is the gRPC counterpart of BuildHTTP — when there is no
// http.Request, only a `net.Addr` from the peer.
func (e *ContextExtractor) BuildPeerAddr(t *VerifiedToken, peerAddr net.Addr, headerFwd string, subj ResolvedSubject) map[string]any {
	out := map[string]any{
		"current_time": e.now().UTC().Truncate(time.Second).Unix(),
	}
	if ip := e.resolveIPFromPeer(peerAddr, headerFwd); ip != "" {
		out["client_ip"] = ip
	}
	e.fillFromToken(out, t)
	if subj.FGA != "" {
		out["subject_kind"] = subjectKindString(subj.Kind)
	}
	return out
}

func (e *ContextExtractor) fillFromToken(out map[string]any, t *VerifiedToken) {
	if t == nil {
		return
	}
	if t.ACR != "" {
		out["acr_value"] = t.ACR
	}
	if len(t.AMR) > 0 {
		// Copy to avoid the caller mutating shared slice.
		cp := make([]string, len(t.AMR))
		copy(cp, t.AMR)
		out["amr_claims"] = cp
	}
	if !t.AuthTime.IsZero() {
		out["auth_time"] = t.AuthTime.UTC().Truncate(time.Second).Unix()
	}
	if t.JTI != "" {
		out["jti"] = t.JTI
	}
	if t.Cnf.HasJkt {
		out["dpop_jkt"] = t.Cnf.Jkt
	}
	if ext := t.ExtClaims; ext != nil {
		// Recognised kacho_* claims — extracted with the canonical condition
		// key.
		if v, ok := ext["kacho_mfa_at"]; ok {
			if ts, ok := coerceUnixSeconds(v); ok {
				out["mfa_at"] = ts
			}
		}
		if v, ok := ext["kacho_device_compliance"].(string); ok && v != "" {
			out["device_attestation"] = v
		}
		if v, ok := ext["kacho_passkey_aaguid"].(string); ok && v != "" {
			out["passkey_aaguid"] = v
		}
		if v, ok := ext["kacho_device_id"].(string); ok && v != "" {
			out["device_id"] = v
		}
		// Forward any other kacho_* claims under their original name so
		// future Conditions can read them without an extractor change.
		for k, v := range ext {
			if !strings.HasPrefix(k, "kacho_") {
				continue
			}
			// Already extracted above.
			switch k {
			case "kacho_mfa_at", "kacho_device_compliance", "kacho_passkey_aaguid",
				"kacho_device_id", "kacho_principal_type", "kacho_principal_id",
				"kacho_user_id", "kacho_sa_id", "kacho_workload_id":
				continue
			}
			out[k] = v
		}
	}
}

// resolveClientIP returns the canonical client IP literal for an HTTP request.
// Forwarded headers are consulted only via clientIPFromForwardHeaders (trusted,
// hop-indexed); otherwise the authoritative TCP peer (RemoteAddr) is used.
func (e *ContextExtractor) resolveClientIP(r *http.Request) string {
	if ip := e.clientIPFromForwardHeaders(r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if validIP(host) {
		return canonicaliseIP(host)
	}
	return ""
}

// resolveIPFromPeer is the gRPC peer.Addr equivalent of resolveClientIP.
func (e *ContextExtractor) resolveIPFromPeer(peerAddr net.Addr, headerFwd string) string {
	if ip := e.clientIPFromForwardHeaders("", headerFwd); ip != "" {
		return ip
	}
	if peerAddr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(peerAddr.String())
	if err != nil {
		host = peerAddr.String()
	}
	if validIP(host) {
		return canonicaliseIP(host)
	}
	return ""
}

// clientIPFromForwardHeaders returns the client IP asserted by trusted reverse
// proxies, or "" when forwarded headers must not be trusted (so the caller falls
// back to the TCP peer). Only honoured when trustedXForwardedFor is set AND at
// least one trusted proxy hop is configured.
//
// X-Forwarded-For is parsed from the RIGHT: with N trusted hops the client IP is
// parts[len-N] — the entry the outermost trusted proxy recorded. A client can
// only prepend forged entries to the LEFT of that block (never selected), so a
// spoofed leftmost XFF can no longer drive `client_ip` / `source_ip_in_range`.
// X-Real-IP (a single value a trusted proxy computed) is honoured only as a
// fallback and only when a trusted proxy is present.
func (e *ContextExtractor) clientIPFromForwardHeaders(xRealIP, xff string) string {
	if !e.trustedXForwardedFor || e.trustedProxyCount <= 0 {
		return ""
	}
	if xff != "" {
		parts := strings.Split(xff, ",")
		if idx := len(parts) - e.trustedProxyCount; idx >= 0 && idx < len(parts) {
			if ip := strings.TrimSpace(parts[idx]); validIP(ip) {
				return canonicaliseIP(ip)
			}
		}
	}
	if v := strings.TrimSpace(xRealIP); v != "" && validIP(v) {
		return canonicaliseIP(v)
	}
	return ""
}

// canonicaliseIP normalises an IP literal (trims, lowercases IPv6) so cache
// keys derived from it are stable.
func canonicaliseIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// validIP reports whether s parses as an IP literal.
func validIP(s string) bool {
	return net.ParseIP(s) != nil
}

// subjectKindString — stable string label for SubjectKind. Used as
// `subject_kind` context key.
func subjectKindString(k SubjectKind) string {
	switch k {
	case SubjectKindUser:
		return "user"
	case SubjectKindServiceAccount:
		return "service_account"
	case SubjectKindWorkload:
		return "workload"
	case SubjectKindExternal:
		return "external"
	default:
		return ""
	}
}

// coerceUnixSeconds reads a JSON-decoded value (likely float64 from JWT
// claims) into a Unix-seconds int64. Returns false on type mismatch.
func coerceUnixSeconds(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case string:
		// Try parse as RFC3339 first, then unix-seconds string.
		if ts, err := time.Parse(time.RFC3339, n); err == nil {
			return ts.UTC().Truncate(time.Second).Unix(), true
		}
	}
	return 0, false
}
