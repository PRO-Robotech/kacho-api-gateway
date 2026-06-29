// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_extractor.go — Subject extraction from verified JWT claims.
//
// The api-gateway authz middleware needs an FGA-shaped subject id
// ("user:<usr_xxx>" / "service_account:<sva_xxx>" / "workload:<wid_xxx>")
// for every per-RPC Check. The verified token's `sub` claim is the external
// Hydra subject; the `ext_claims.kacho_*` fields (filled by the Hydra
// token_hook) carry the kacho-native principal id.
//
// Resolution priority:
//
//  1. `ext_claims.kacho_principal_type` + `ext_claims.kacho_principal_id`
//     — explicit unified shape, populated by token_hook for both User and
//     ServiceAccount flows.
//  2. `ext_claims.kacho_user_id` (User flow).
//  3. `ext_claims.kacho_sa_id` (ServiceAccount flow).
//  4. `ext_claims.kacho_workload_id` (federated Workload identity).
//  5. Hydra `sub` claim as the final fallback when none of the above are
//     present — yields a `external:<sub>` subject for diagnostic purposes
//     but is **rejected** by the middleware in production-strict mode.
//
// Empty / structurally-invalid claims return ok=false; the middleware then
// treats this as "no subject" (denied / pass-through per its policy).
package middleware

import (
	"strings"
)

// Subject FGA-prefix vocabulary. Mirrors the OpenFGA Authorization Model
// types: user / service_account / workload.
const (
	subjectPrefixUser           = "user"
	subjectPrefixServiceAccount = "service_account"
	subjectPrefixWorkload       = "workload"
	// subjectPrefixExternal is a diagnostic fallback when the token has no
	// kacho-native identity in ext_claims. Not a real FGA type — Check will
	// always deny these.
	subjectPrefixExternal = "external"
)

// SubjectKind classifies a resolved subject — convenience for callers that
// want to gate on type without parsing the prefix.
type SubjectKind int

const (
	// SubjectKindUnknown — empty / unresolvable.
	SubjectKindUnknown SubjectKind = iota
	// SubjectKindUser — natural-person User (`usr_*`).
	SubjectKindUser
	// SubjectKindServiceAccount — ServiceAccount (`sva_*`).
	SubjectKindServiceAccount
	// SubjectKindWorkload — federated Workload identity.
	SubjectKindWorkload
	// SubjectKindExternal — diagnostic fallback (`external:<sub>`); fails
	// FGA Check by construction.
	SubjectKindExternal
)

// ResolvedSubject — the output of SubjectExtractor.Extract.
type ResolvedSubject struct {
	// FGA — FGA-shaped subject string ("user:usr_abc"). Empty when ok=false.
	FGA string
	// Kind — classification of the subject.
	Kind SubjectKind
	// ID — bare id (no prefix).
	ID string
	// Source — which ext_claims field (or `sub`) the value came from.
	// Used in audit logs to diagnose unexpected fallbacks.
	Source string
}

// String makes ResolvedSubject stringer-friendly for log fields.
func (r ResolvedSubject) String() string {
	if r.FGA == "" {
		return "<unknown>"
	}
	return r.FGA
}

// SubjectExtractor — stateless extractor; constructed once and shared.
type SubjectExtractor struct {
	// allowExternalFallback controls whether a raw `sub`-only token resolves
	// to `external:<sub>` (true; production-strict gates this further at the
	// middleware layer) or to ok=false (false; pre-emptively reject).
	allowExternalFallback bool
}

// NewSubjectExtractor constructs an extractor. allowExternalFallback=true
// matches production-non-strict behaviour where unknown tokens get a
// `external:<sub>` shape that always FGA-denies — useful so the access log
// records a stable identifier for forensics.
func NewSubjectExtractor(allowExternalFallback bool) *SubjectExtractor {
	return &SubjectExtractor{allowExternalFallback: allowExternalFallback}
}

// Extract reads kacho_principal_* / kacho_user_id / kacho_sa_id /
// kacho_workload_id from the verified token's ext_claims and returns the
// most-specific resolution. Returns ok=false when nothing matches and
// allowExternalFallback=false.
func (e *SubjectExtractor) Extract(t *VerifiedToken) (ResolvedSubject, bool) {
	if t == nil {
		return ResolvedSubject{}, false
	}
	ext := t.ExtClaims

	// 1. Unified ext_claims.kacho_principal_*.
	if ext != nil {
		pType, _ := ext["kacho_principal_type"].(string)
		pID, _ := ext["kacho_principal_id"].(string)
		pType = strings.TrimSpace(pType)
		pID = strings.TrimSpace(pID)
		if pType != "" && pID != "" {
			kind, prefix := classifyPrincipal(pType)
			if kind != SubjectKindUnknown {
				return ResolvedSubject{
					FGA:    prefix + ":" + pID,
					Kind:   kind,
					ID:     pID,
					Source: "ext_claims.kacho_principal_*",
				}, true
			}
		}
	}

	// 2. ext_claims.kacho_user_id.
	if ext != nil {
		if uid, ok := ext["kacho_user_id"].(string); ok && uid != "" {
			return ResolvedSubject{
				FGA:    subjectPrefixUser + ":" + uid,
				Kind:   SubjectKindUser,
				ID:     uid,
				Source: "ext_claims.kacho_user_id",
			}, true
		}
	}

	// 3. ext_claims.kacho_sa_id.
	if ext != nil {
		if said, ok := ext["kacho_sa_id"].(string); ok && said != "" {
			return ResolvedSubject{
				FGA:    subjectPrefixServiceAccount + ":" + said,
				Kind:   SubjectKindServiceAccount,
				ID:     said,
				Source: "ext_claims.kacho_sa_id",
			}, true
		}
	}

	// 4. ext_claims.kacho_workload_id (federated Workload identity).
	if ext != nil {
		if wid, ok := ext["kacho_workload_id"].(string); ok && wid != "" {
			return ResolvedSubject{
				FGA:    subjectPrefixWorkload + ":" + wid,
				Kind:   SubjectKindWorkload,
				ID:     wid,
				Source: "ext_claims.kacho_workload_id",
			}, true
		}
	}

	// 5. Hydra `sub` fallback — diagnostic only.
	if e.allowExternalFallback && t.Subject != "" {
		return ResolvedSubject{
			FGA:    subjectPrefixExternal + ":" + t.Subject,
			Kind:   SubjectKindExternal,
			ID:     t.Subject,
			Source: "jwt.sub",
		}, true
	}

	return ResolvedSubject{}, false
}

// classifyPrincipal maps the kacho-native principal-type string to a Kind
// and the matching FGA prefix. Unknown types return SubjectKindUnknown +
// empty string — callers fall through to the next resolution rule.
func classifyPrincipal(t string) (SubjectKind, string) {
	switch strings.ToLower(t) {
	case "user", "usr":
		return SubjectKindUser, subjectPrefixUser
	case "service_account", "service-account", "serviceaccount", "sva":
		return SubjectKindServiceAccount, subjectPrefixServiceAccount
	case "workload", "wid":
		return SubjectKindWorkload, subjectPrefixWorkload
	default:
		return SubjectKindUnknown, ""
	}
}
