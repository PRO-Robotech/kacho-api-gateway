// permission_denied_response.go — shape Permission-Denied responses for both
// gRPC and HTTP/REST entry points (KAC-127 Phase 3).
//
// gRPC: returns a `status.Status{Code: PermissionDenied}` enriched with
// `google.rpc.PreconditionFailure` violations — one per deny reason. UI
// clients introspect the violations to render actionable error messages
// (e.g. "step up your session" vs "no permission").
//
// HTTP: returns 403 Forbidden with a JSON body shaped like the gRPC-gateway
// default (`{code, message, details}`) plus a `WWW-Authenticate` header when
// the deny reason indicates step-up is needed (mfa_fresh / non-CRITICAL
// freshness violation). The WWW-Authenticate value follows RFC 9470 §3:
// `Bearer error="insufficient_user_authentication", acr_values="3"`.
//
// The catalog dictates the WWW-Authenticate construction (required_acr_min);
// runtime deny-reasons inform `error_description` for diagnostics.
package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// permissionDeniedDescriptor — common subject/action/resource tuple included
// in every deny violation (forensic correlation).
type permissionDeniedDescriptor struct {
	Subject      string
	Action       string
	ResourceType string
	ResourceID   string
	FQN          string
}

// buildGRPCDenyStatus constructs a *status.Status with attached
// PreconditionFailure violations. The message argument is the headline shown
// to clients; reasons populate violation.Subject for machine-readable triage.
func buildGRPCDenyStatus(desc permissionDeniedDescriptor, reasons []string) *status.Status {
	msg := "permission denied"
	if desc.Action != "" {
		msg = "permission denied: " + desc.Action
	}
	st := status.New(codes.PermissionDenied, msg)

	pf := &errdetails.PreconditionFailure{}
	if len(reasons) == 0 {
		pf.Violations = append(pf.Violations, &errdetails.PreconditionFailure_Violation{
			Type:        "authz.no_path",
			Subject:     resourceLabel(desc),
			Description: "no authorization path to the resource",
		})
	} else {
		for _, r := range reasons {
			pf.Violations = append(pf.Violations, &errdetails.PreconditionFailure_Violation{
				Type:        classifyDenyReasonType(r),
				Subject:     resourceLabel(desc),
				Description: r,
			})
		}
	}

	info := &errdetails.ErrorInfo{
		Reason: "AUTHZ_DENIED",
		Domain: "kacho.cloud.iam.v1",
		Metadata: map[string]string{
			"subject":      desc.Subject,
			"action":       desc.Action,
			"resource":     resourceLabel(desc),
			"fqn":          desc.FQN,
			"deny_reasons": strings.Join(reasons, "; "),
		},
	}

	stWithDetails, derr := st.WithDetails(pf, info)
	if derr != nil {
		// Should not happen — PreconditionFailure + ErrorInfo are
		// well-known. Fall back to the bare status.
		return st
	}
	return stWithDetails
}

// buildGRPCUnauthStatus constructs a *status.Status for missing/invalid
// credentials. Returns Unauthenticated (16) with attached ErrorInfo so the
// client can distinguish "no credentials" from "authenticated but denied".
// KAC-130 BUG-2: must be code 16, not 7.
func buildGRPCUnauthStatus(desc permissionDeniedDescriptor, reasons []string) *status.Status {
	msg := "unauthenticated: credentials required"
	st := status.New(codes.Unauthenticated, msg)

	info := &errdetails.ErrorInfo{
		Reason: "AUTHN_REQUIRED",
		Domain: "kacho.cloud.iam.v1",
		Metadata: map[string]string{
			"fqn":          desc.FQN,
			"deny_reasons": strings.Join(reasons, "; "),
		},
	}

	stWithDetails, derr := st.WithDetails(info)
	if derr != nil {
		return st
	}
	return stWithDetails
}

// writeHTTPUnauth renders a 401 Unauthorized response for missing/invalid
// credentials. The JSON body uses code 16 (gRPC Unauthenticated) so that
// REST clients receive a machine-readable status consistent with the gRPC
// surface. Also sets WWW-Authenticate: Bearer per RFC 7235.
// KAC-130 BUG-2: must be 401 + code 16, not 403 + code 7.
func writeHTTPUnauth(w http.ResponseWriter, desc permissionDeniedDescriptor, reasons []string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kacho"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	body := map[string]any{
		"code":    16, // gRPC code Unauthenticated
		"message": "unauthenticated: credentials required",
		"details": []map[string]any{
			{
				"@type":  "type.googleapis.com/google.rpc.ErrorInfo",
				"reason": "AUTHN_REQUIRED",
				"domain": "kacho.cloud.iam.v1",
				"metadata": map[string]string{
					"fqn":          desc.FQN,
					"deny_reasons": strings.Join(reasons, "; "),
				},
			},
		},
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeHTTPDeny renders a 403 response with the same descriptor / reasons.
// `acrChallenge` — when non-empty, sets WWW-Authenticate per RFC 9470 §3.
func writeHTTPDeny(w http.ResponseWriter, desc permissionDeniedDescriptor, reasons []string, acrChallenge string) {
	if acrChallenge != "" {
		w.Header().Set("WWW-Authenticate", acrChallenge)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	details := make([]map[string]any, 0, len(reasons)+1)
	if len(reasons) == 0 {
		details = append(details, map[string]any{
			"@type":   "type.googleapis.com/google.rpc.PreconditionFailure",
			"violations": []map[string]any{{
				"type":        "authz.no_path",
				"subject":     resourceLabel(desc),
				"description": "no authorization path to the resource",
			}},
		})
	} else {
		viol := make([]map[string]any, 0, len(reasons))
		for _, r := range reasons {
			viol = append(viol, map[string]any{
				"type":        classifyDenyReasonType(r),
				"subject":     resourceLabel(desc),
				"description": r,
			})
		}
		details = append(details, map[string]any{
			"@type":      "type.googleapis.com/google.rpc.PreconditionFailure",
			"violations": viol,
		})
	}
	details = append(details, map[string]any{
		"@type":  "type.googleapis.com/google.rpc.ErrorInfo",
		"reason": "AUTHZ_DENIED",
		"domain": "kacho.cloud.iam.v1",
		"metadata": map[string]string{
			"subject":      desc.Subject,
			"action":       desc.Action,
			"resource":     resourceLabel(desc),
			"fqn":          desc.FQN,
			"deny_reasons": strings.Join(reasons, "; "),
		},
	})

	body := map[string]any{
		"code":    7, // gRPC code PermissionDenied
		"message": "permission denied: " + desc.Action,
		"details": details,
	}
	_ = json.NewEncoder(w).Encode(body)
}

// classifyDenyReasonType inspects a deny reason string and assigns it a
// machine-readable type. The leftmost token (before ':') is the convention
// the IAM service uses ("mfa_fresh: acr=2 (need 3)" → "mfa_fresh").
func classifyDenyReasonType(reason string) string {
	if reason == "" {
		return "authz.unspecified"
	}
	idx := strings.IndexByte(reason, ':')
	if idx <= 0 {
		return "authz." + sanitizeReasonToken(reason)
	}
	return "authz." + sanitizeReasonToken(reason[:idx])
}

// sanitizeReasonToken — stable lower-case identifier (alnum + underscore).
// Anything else collapses to "unspecified".
func sanitizeReasonToken(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "unspecified"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	out = strings.Trim(out, "_")
	if out == "" {
		return "unspecified"
	}
	return out
}

// resourceLabel returns the canonical "<type>:<id>" string used as the
// violation Subject.
func resourceLabel(d permissionDeniedDescriptor) string {
	if d.ResourceType == "" {
		return d.ResourceID
	}
	if d.ResourceID == "" {
		return d.ResourceType + ":*"
	}
	return d.ResourceType + ":" + d.ResourceID
}

// shouldStepUpChallenge reports whether the deny reasons indicate the client
// can satisfy the gate by re-authenticating with a stronger ACR. Used to
// decide whether to attach WWW-Authenticate.
func shouldStepUpChallenge(reasons []string) bool {
	for _, r := range reasons {
		lr := strings.ToLower(r)
		if strings.HasPrefix(lr, "mfa_fresh") {
			return true
		}
		if strings.HasPrefix(lr, "non_expired") {
			// Token-related — refreshing the token will help; recommend
			// re-auth.
			return true
		}
	}
	return false
}
