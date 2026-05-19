// resource_extractor.go — Resolve the scope/resource id of an in-flight
// request using catalog metadata (`scope_extractor.from_request_field`) +
// proto reflection (KAC-127 Phase 3).
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
	"net/http"
	"reflect"
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
		// Non-proto request (e.g. handwritten Go struct) — fall back to
		// reflect-based field walking. This branch is exercised by tests
		// that pass plain structs rather than full proto messages.
		if id, ok := extractByReflect(req, field); ok {
			return id, true
		}
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
	// admin-UI might append `?scope=...` for explicit gating.
	if q := r.URL.Query().Get(field); q != "" {
		return ResourceID(q), true
	}
	if q := r.URL.Query().Get("scope_id"); q != "" {
		return ResourceID(q), true
	}
	return ResourceID("*"), true
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
// Supports nested ResourceRef (acceptance §5.4 — `from_request_field:"resource"`
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

// extractByReflect — non-proto fallback for tests / handwritten request
// types. Walks the struct using `reflect` looking for the named field
// (case-insensitive); returns the first non-empty string match.
func extractByReflect(req any, field string) (ResourceID, bool) {
	v := reflect.ValueOf(req)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "", false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return "", false
	}
	t := v.Type()
	target := strings.ToLower(field)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.ToLower(f.Name)
		// Match either the Go field name or its protobuf tag (`<name>,...`).
		if name == target || name == strings.ReplaceAll(target, "_", "") {
			return readStringField(v.Field(i)), true
		}
		if tag := f.Tag.Get("protobuf"); tag != "" {
			if strings.Contains(tag, "name="+target+",") || strings.HasSuffix(tag, "name="+target) {
				return readStringField(v.Field(i)), true
			}
		}
		if tag := f.Tag.Get("json"); tag != "" {
			if tagName := strings.SplitN(tag, ",", 2)[0]; tagName == field {
				return readStringField(v.Field(i)), true
			}
		}
	}
	return "", false
}

// readStringField extracts a string-typed field, recursing into pointers /
// nested structs (taking the first non-empty string field) so a
// `*ResourceRef{Id:"X"}` resolves to "X".
func readStringField(fv reflect.Value) ResourceID {
	for fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			return ""
		}
		fv = fv.Elem()
	}
	switch fv.Kind() {
	case reflect.String:
		s := fv.String()
		if s == "" {
			return ResourceID("*")
		}
		return ResourceID(s)
	case reflect.Struct:
		// Look for an "Id" / "ID" string field first.
		for _, name := range []string{"Id", "ID", "id"} {
			f := fv.FieldByName(name)
			if f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
				return ResourceID(f.String())
			}
		}
		// Walk for first non-empty string.
		for i := 0; i < fv.NumField(); i++ {
			if s := readStringField(fv.Field(i)); s != "" && s != "*" {
				return s
			}
		}
	}
	return ""
}

// extractByPathTemplate parses a grpc-gateway-style path template
// (`/iam/v1/projects/{project_id}`) against the incoming URL path and
// returns the value of the placeholder matching the catalog's
// `from_request_field` (`project_id` in this example). Empty string when
// the path does not match the template or the placeholder is missing.
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
		if len(t) >= 2 && t[0] == '{' && t[len(t)-1] == '}' {
			name := t[1 : len(t)-1]
			if name == field {
				found = p
			}
		} else if t != p {
			return "", false
		}
	}
	return found, found != ""
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
