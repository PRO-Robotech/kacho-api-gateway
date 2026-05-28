// context_extractor.go — Build the OpenFGA Condition-evaluation context map
// from the verified Phase 2 JWT + HTTP request (KAC-127 Phase 3).
//
// OpenFGA `CheckRequest.Context` is a `google.protobuf.Struct` of arbitrary
// keys consumed by predicate-conditions (acceptance §4.5):
//
//	mfa_fresh(amr_claims, acr_value, current_time, mfa_at)
//	non_expired(current_time, valid_until)
//	source_ip_in_range(client_ip, allowed_cidrs)
//	business_hours(current_time, tz, start_h, end_h)
//	device_compliant(device_attestation, allowed_attestations)
//	jit_window(current_time, activated_at, ttl_seconds)
//	(break_glass_window removed in KAC-214 / RBAC v2)
//
// This extractor builds the *caller-side* half of those keys — the ones
// derivable from the JWT and the incoming HTTP request. Predicate-side
// parameters (`allowed_cidrs`, `valid_until`, `expires_at`, `tz`, ...) live
// in the FGA tuple's `condition.context` and are merged FGA-side.
//
// Reserved keys this extractor emits (acceptance §4.5 + AuthorizeCheckRequest
// proto comment):
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
// Unknown ext_claims keys pass through verbatim under `ext_*` prefix; the
// FGA Conditions whitelist (acceptance D-5) means tenant-supplied junk never
// participates in actual condition evaluation.
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
}

// NewContextExtractor constructs an extractor. now=nil falls back to
// time.Now; trustedXForwardedFor toggles X-Forwarded-For honour (see field
// comment).
func NewContextExtractor(now func() time.Time, trustedXForwardedFor bool) *ContextExtractor {
	if now == nil {
		now = time.Now
	}
	return &ContextExtractor{now: now, trustedXForwardedFor: trustedXForwardedFor}
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
		// key (acceptance §4.5).
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

// resolveClientIP returns the canonical client IP literal for an HTTP request,
// honouring X-Forwarded-For / X-Real-IP only when trustedXForwardedFor is set.
// Empty string when unresolvable.
func (e *ContextExtractor) resolveClientIP(r *http.Request) string {
	if e.trustedXForwardedFor {
		if v := r.Header.Get("X-Real-IP"); v != "" {
			if ip := strings.TrimSpace(v); validIP(ip) {
				return canonicaliseIP(ip)
			}
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			// XFF is comma-separated; the leftmost entry is the original
			// client (per the proxy convention all reverse-proxies follow).
			parts := strings.Split(v, ",")
			if len(parts) > 0 {
				if ip := strings.TrimSpace(parts[0]); validIP(ip) {
					return canonicaliseIP(ip)
				}
			}
		}
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
	if e.trustedXForwardedFor && headerFwd != "" {
		parts := strings.Split(headerFwd, ",")
		if len(parts) > 0 {
			if ip := strings.TrimSpace(parts[0]); validIP(ip) {
				return canonicaliseIP(ip)
			}
		}
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
