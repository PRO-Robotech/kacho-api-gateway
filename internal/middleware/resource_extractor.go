// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// resource_extractor.go — Resolve the scope/resource id of an in-flight
// request using catalog metadata (`scope_extractor.from_request_field`) +
// proto reflection.
//
// The middleware drives FGA `Check(subject, action, resource_type:resource_id,
// context)`. `resource_type` comes from the catalog directly; `resource_id`
// must be plucked out of the request payload.
//
// Strategies, in order:
//
//  1. **proto reflection** — when the request is a proto.Message we can walk
//     the message looking up the named field. This is the canonical path for
//     gRPC server-interceptors where the request is already typed.
//
//  2. **HTTP path/query parsing** — when called from the HTTP path (REST
//     gateway), the request body has not yet been decoded into a typed proto
//     message. For grpc-gateway-style endpoints the resource id is in the
//     URL path (`/iam/v1/projects/{project_id}`) — we accept a precompiled
//     `PathTemplate` registry keyed by the FQN as a forward-extension point.
//     For now we fall back to a query-string lookup ("?resource_id=X") and
//     finally to wildcard.
//
//  3. **wildcard fallback** — for List/Search RPCs (no specific resource_id)
//     OR when extraction fails, we return the FGA wildcard "*". The FGA
//     Authorization Model contains a "viewer" relation on the `cluster` /
//     `organization` root that resolves wildcards correctly.
//
// Special-case keys recognised in `scope_extractor.from_request_field`:
//
//	"*"       — always wildcard (declared in catalog for catch-all RPCs).
//	"subject" — the subject id is its own scope (AuthorizeService.Check).
//	"resource"— a `ResourceRef{type,id}` message-field — extracts the id.
package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// ResourceID — the scope identifier the middleware passes to FGA. Wildcard
// ("*") is permitted and indicates a List/Search-style RPC.
type ResourceID string

// IsWildcard reports whether the id is the FGA wildcard.
func (r ResourceID) IsWildcard() bool { return r == "*" }

// String renders the id as a plain string (no prefix).
func (r ResourceID) String() string { return string(r) }

// ResourceExtractor — stateless lookup driven by CatalogEntry metadata.
type ResourceExtractor struct {
	// httpFallbackPaths maps FQN → a URL-template (grpc-gateway style
	// `/iam/v1/projects/{project_id}`) for the HTTP fallback. Optional; an
	// empty map disables HTTP-path extraction.
	httpFallbackPaths map[string]string
}

// NewResourceExtractor constructs an extractor. The optional fallbackPaths
// map enables HTTP-path-style resource extraction.
func NewResourceExtractor(httpFallbackPaths map[string]string) *ResourceExtractor {
	cp := make(map[string]string, len(httpFallbackPaths))
	for k, v := range httpFallbackPaths {
		cp[k] = v
	}
	return &ResourceExtractor{httpFallbackPaths: cp}
}

// ExtractFromProto applies the catalog `from_request_field` directive to a
// typed proto request, returning the resolved ResourceID + ok.
//
// Returns ok=true even for wildcard results — the boolean signals "no error",
// not "specific id". Callers distinguish with ResourceID.IsWildcard.
func (e *ResourceExtractor) ExtractFromProto(req any, entry CatalogEntry) (ResourceID, bool) {
	field := strings.TrimSpace(entry.ScopeExtractor.FromRequestField)
	if field == "" || field == "*" {
		return ResourceID("*"), true
	}
	if req == nil {
		return ResourceID("*"), true
	}
	msg, ok := protoMessageFromAny(req)
	if !ok {
		// Non-proto request. On the production authz path the intercepted gRPC
		// request is always a proto.Message (authz.decisionRequest.ProtoReq),
		// so this is unreachable in prod; fail closed to the wildcard scope.
		return ResourceID("*"), true
	}
	return extractByProtoReflect(msg, field), true
}

// ExtractFromHTTP extracts the resource id from an HTTP request when the
// proto body hasn't been decoded yet. Strategy:
//
//  1. Recognised path template (e.g. `/iam/v1/projects/{project_id}` →
//     parse {project_id}). The template registry is supplied via
//     `httpFallbackPaths` keyed by FQN.
//  2. Query string `?resource_id=…` (admin-UI helper).
//  3. Wildcard.
func (e *ResourceExtractor) ExtractFromHTTP(r *http.Request, fqn string, entry CatalogEntry) (ResourceID, bool) {
	if r == nil {
		return ResourceID("*"), true
	}
	field := strings.TrimSpace(entry.ScopeExtractor.FromRequestField)
	if field == "" || field == "*" {
		return ResourceID("*"), true
	}
	// 1. Template-aware extraction. We accept simple `{name}` placeholders.
	if tmpl, ok := e.httpFallbackPaths[fqn]; ok && tmpl != "" {
		if id, ok := extractByPathTemplate(r.URL.Path, tmpl, field); ok && id != "" {
			return ResourceID(id), true
		}
	}
	// 2. Query string fallback — also accepted on POST bodies because
	// admin-UI might append `?scope=...` for explicit gating. grpc-gateway
	// REST query params are camelCase (`?accountId=`), while the catalog
	// `from_request_field` is the snake_case proto field (`account_id`) — so
	// we try both spellings (List RPCs scoped by an `account_id` query param
	// would otherwise produce a spurious `account:*` wildcard → no-path DENY).
	for _, key := range []string{field, snakeToCamel(field)} {
		if q := r.URL.Query().Get(key); q != "" {
			return ResourceID(q), true
		}
	}
	if q := r.URL.Query().Get("scope_id"); q != "" {
		return ResourceID(q), true
	}
	// 3. JSON body extraction — Create/Update RPCs carry
	// the scope id (`account_id` / `project_id` / `resource_id`) in the
	// request body, not the URL. The middleware runs before grpc-gateway
	// decodes the body, so we read + RESTORE it here so the downstream
	// handler still sees an intact body. REST JSON is camelCase, so we look
	// the snake_case catalog field up under its camelCase spelling too.
	if id := extractFromJSONBody(r, field); id != "" {
		return ResourceID(id), true
	}
	return ResourceID("*"), true
}

// ScopeTypeFromProto reads the named top-level string field off a typed proto
// request and returns its raw value, or "" when the field is absent/empty.
//
// Unlike ExtractFromProto it does NOT wildcard-default: an empty result means
// "no dynamic object type present, use the catalog's static object_type". Used
// for scope-polymorphic RPCs whose FGA object type is carried by a request
// field (catalog `object_type_from_request_field`).
func (e *ResourceExtractor) ScopeTypeFromProto(req any, field string) string {
	field = strings.TrimSpace(field)
	if field == "" || req == nil {
		return ""
	}
	msg, ok := protoMessageFromAny(req)
	if !ok {
		// Non-proto request — unreachable on the production authz path (see
		// ExtractFromProto). No dynamic object type available.
		return ""
	}
	id := extractByProtoReflect(msg, field)
	if id.IsWildcard() {
		return ""
	}
	return id.String()
}

// ScopeTypeFromHTTP reads the named field from an HTTP request's query string
// or JSON body (REST camelCase spelling tried too) and returns its raw value,
// or "" when absent. Like ScopeTypeFromProto it does NOT wildcard-default.
func (e *ResourceExtractor) ScopeTypeFromHTTP(r *http.Request, field string) string {
	field = strings.TrimSpace(field)
	if r == nil || field == "" {
		return ""
	}
	for _, key := range []string{field, snakeToCamel(field)} {
		if q := r.URL.Query().Get(key); q != "" {
			return q
		}
	}
	if v := extractFromJSONBody(r, field); v != "" {
		return v
	}
	return ""
}

// extractFromJSONBody reads a top-level string field out of the request's
// JSON body and restores the body for downstream consumers. Returns "" when
// the body is absent / not JSON / the field is missing.
func extractFromJSONBody(r *http.Request, snakeField string) string {
	if r.Body == nil || r.ContentLength == 0 {
		return ""
	}
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "json") {
		return ""
	}
	// Cap at 1 MiB — request bodies for control-plane RPCs are tiny; this
	// guards against a malicious oversized body.
	buf, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	// Always restore the body so the downstream handler can decode it.
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	if err != nil || len(buf) == 0 {
		return ""
	}
	var doc map[string]json.RawMessage
	if uerr := json.Unmarshal(buf, &doc); uerr != nil {
		return ""
	}
	for _, key := range []string{snakeField, snakeToCamel(snakeField)} {
		raw, ok := doc[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}

// snakeToCamel converts `account_id` -> `accountId` (REST JSON spelling).
func snakeToCamel(s string) string {
	var b strings.Builder
	up := false
	for _, r := range s {
		if r == '_' {
			up = true
			continue
		}
		if up && r >= 'a' && r <= 'z' {
			b.WriteRune(r - 'a' + 'A')
			up = false
			continue
		}
		up = false
		b.WriteRune(r)
	}
	return b.String()
}

// protoMessageFromAny tries to assert the supplied interface as a
// proto.Message. We use a tight `ProtoReflect()` interface check (every
// generated proto v1.27+ message implements it) so the resource extractor
// stays decoupled from the proto package import graph.
func protoMessageFromAny(req any) (protoreflect.Message, bool) {
	if pm, ok := req.(interface{ ProtoReflect() protoreflect.Message }); ok {
		return pm.ProtoReflect(), true
	}
	return nil, false
}

// extractByProtoReflect walks the message fields looking up the named field.
// Supports nested ResourceRef (`from_request_field:"resource"`
// where `resource` is a ResourceRef message → read `.id`).
func extractByProtoReflect(msg protoreflect.Message, field string) ResourceID {
	// Find the field descriptor matching the supplied name. We try direct
	// match first; common field aliases (snake_case vs camelCase) are
	// covered by protobuf's standard JSON marshalling so we don't need
	// special handling beyond ByName.
	fields := msg.Descriptor().Fields()
	fd := fields.ByName(protoreflect.Name(field))
	if fd == nil {
		// Some catalog entries use snake_case `resource_id` while the proto
		// might declare it as oneof/camelCase. Try a few normalised lookups.
		for _, alt := range []string{toSnakeCase(field), strings.ToLower(field)} {
			if alt == field {
				continue
			}
			fd = fields.ByName(protoreflect.Name(alt))
			if fd != nil {
				break
			}
		}
	}
	if fd == nil {
		return ResourceID("*")
	}
	val := msg.Get(fd)
	// Embedded ResourceRef → read `.id`.
	if fd.Kind() == protoreflect.MessageKind {
		sub := val.Message()
		if sub == nil || !sub.IsValid() {
			return ResourceID("*")
		}
		// Try .id (the canonical AuthorizeService ResourceRef shape) and
		// fall back to the first scalar string field.
		if idFD := sub.Descriptor().Fields().ByName("id"); idFD != nil {
			if s := sub.Get(idFD).String(); s != "" {
				return ResourceID(s)
			}
		}
		// Walk sub-fields for the first non-empty string.
		var found string
		sub.Range(func(_ protoreflect.FieldDescriptor, fv protoreflect.Value) bool {
			if s := fv.String(); s != "" {
				found = s
				return false
			}
			return true
		})
		if found != "" {
			return ResourceID(found)
		}
		return ResourceID("*")
	}
	// Scalar string / bytes — directly return.
	switch fd.Kind() {
	case protoreflect.StringKind, protoreflect.BytesKind:
		s := val.String()
		if s == "" {
			return ResourceID("*")
		}
		return ResourceID(s)
	}
	return ResourceID("*")
}

// extractByPathTemplate parses a grpc-gateway-style path template
// (`/iam/v1/projects/{project_id}`) against the incoming URL path and
// returns the value of the placeholder matching the catalog's
// `from_request_field` (`project_id` in this example). Empty string when
// the path does not match the template or the placeholder is missing.
//
// Handles grpc-gateway suffix-action segments where a `:verb` is glued to
// the final segment: template `{subnet_id}:add-cidr-blocks` against request
// segment `xyz:add-cidr-blocks` extracts `xyz` (the verb part is matched
// as a literal). Without this, suffix-action RPCs would fall through to
// wildcard `*` and surface as `no path: unscoped resource` 403 from the
// authz check.
func extractByPathTemplate(reqPath, template, field string) (string, bool) {
	// Tokenize both — slashed segments, very small templates only (no
	// wildcards / collections). This mirrors how grpc-gateway parses
	// `google.api.http` simple path bindings.
	tparts := strings.Split(strings.Trim(template, "/"), "/")
	pparts := strings.Split(strings.Trim(reqPath, "/"), "/")
	if len(tparts) != len(pparts) {
		return "", false
	}
	var found string
	for i, t := range tparts {
		p := pparts[i]

		// Suffix-action handling: split off optional `:verb` from BOTH
		// template and request, then compare the verbs as literals and
		// fall through to placeholder matching on the leading half.
		tBase, tVerb := splitVerbSuffix(t)
		pBase, pVerb := splitVerbSuffix(p)
		if tVerb != pVerb {
			return "", false
		}

		if isPlaceholder(tBase) {
			name := tBase[1 : len(tBase)-1]
			if name == field {
				found = pBase
			}
		} else if tBase != pBase {
			return "", false
		}
	}
	return found, found != ""
}

// splitVerbSuffix peels off an optional grpc-gateway `:verb` action from a
// path segment. `"x:add"` → ("x","add"); `"x"` → ("x",""). Only the final
// colon is treated as a separator (defensive against colon-in-id ids,
// which Kachō does not currently produce but cheap to guard against).
func splitVerbSuffix(seg string) (base, verb string) {
	if idx := strings.LastIndexByte(seg, ':'); idx > 0 {
		return seg[:idx], seg[idx+1:]
	}
	return seg, ""
}

// toSnakeCase — minimal CamelCase → snake_case for field-name normalisation.
func toSnakeCase(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r - 'A' + 'a')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
