package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// gh kacho-api-gateway#73 — the authz interceptor ran the FGA Check BEFORE the
// downstream handler validated the resource-id format. A malformed id
// (wrong-prefix / wrong-length) → FGA no-path → 403, instead of the
// Kachō-convention 400 InvalidArgument. These tests pin the fix: for catalog
// entries with a CONCRETE per-resource id scope, a syntactically-invalid id
// short-circuits to InvalidArgument (code 3 / HTTP 400) and the FGA Check is
// NEVER called. Well-formed-but-nonexistent ids still deny (403) — that is the
// existence-leak protection and must NOT be weakened.

// acbGetEntry — concrete per-resource id scope (from_request_field is the
// access_binding_id field, no object_type_from_request_field). Mirrors the
// embedded permission_catalog.json AccessBindingService/Get entry.
const acbGetEntry = `{"fqn":"kacho.cloud.iam.v1.AccessBindingService/Get","permission":"iam.access_bindings.get","required_relation":"viewer","scope_extractor":{"object_type":"iam_access_binding","from_request_field":"access_binding_id"},"required_acr_min":"2","risk_level":"LOW"}`

// acbListByScopeEntry — scope-polymorphic (object_type_from_request_field).
// MUST NOT be id-validated: resource_id may be an account/project/cluster id of
// a foreign family, and the malformed-id guard explicitly excludes this path.
const acbListByScopeEntry = `{"fqn":"kacho.cloud.iam.v1.AccessBindingService/ListByScope","permission":"iam.access_bindings_by_resources.listByScope","required_relation":"viewer","scope_extractor":{"object_type":"project","from_request_field":"resource_id","object_type_from_request_field":"resource_type"},"required_acr_min":"2"}`

const malformedACB = "not-a-valid-acb-id-at-all-verylongstring"
const wellFormedNonexistentACB = "acb00000000000notfnd"

// TestAuthz_GRPC_MalformedResourceId_InvalidArgument — malformed id on a
// concrete-scope RPC → InvalidArgument(3); the Checker is never called.
func TestAuthz_GRPC_MalformedResourceId_InvalidArgument(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, acbGetEntry), checker)
	req := &iamv1.GetAccessBindingRequest{AccessBindingId: malformedACB}
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), req,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccessBindingService/Get"},
		func(ctx context.Context, req any) (any, error) {
			t.Fatal("handler must not run for malformed id")
			return nil, nil
		})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"malformed resource id must map to InvalidArgument(3), not PermissionDenied(7)")
	assert.Contains(t, st.Message(), "invalid resource id")
	assert.Contains(t, st.Message(), malformedACB)
	assert.Zero(t, checker.calls.Load(), "FGA Check must NOT be called for a malformed id")
}

// TestAuthz_HTTP_MalformedResourceId_Returns400 — same on the REST surface:
// HTTP 400 with JSON {"code":3,...}; Checker never called.
func TestAuthz_HTTP_MalformedResourceId_Returns400(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accessBindings/" + malformedACB: "kacho.cloud.iam.v1.AccessBindingService/Get",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, acbGetEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
		c.Resources = middleware.NewResourceExtractor(map[string]string{
			"kacho.cloud.iam.v1.AccessBindingService/Get": "/iam/v1/accessBindings/{access_binding_id}",
		})
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run for malformed id")
	}))
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/accessBindings/"+malformedACB, nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code, "malformed id must produce HTTP 400")
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, float64(3), body["code"], "grpc code in JSON body must be 3 (INVALID_ARGUMENT)")
	assert.Zero(t, checker.calls.Load(), "FGA Check must NOT be called for a malformed id")
}

// TestAuthz_GRPC_WellFormedDeny_StillPermissionDenied — regression: a
// well-formed-but-nonexistent id with a deny Checker must STILL return
// PermissionDenied(7) (existence-leak protection by design). Authz is NOT
// weakened by the malformed-id short-circuit.
func TestAuthz_GRPC_WellFormedDeny_StillPermissionDenied(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, acbGetEntry), checker)
	req := &iamv1.GetAccessBindingRequest{AccessBindingId: wellFormedNonexistentACB}
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), req,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccessBindingService/Get"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"well-formed id denied by FGA must remain PermissionDenied(7)")
	assert.Equal(t, int64(1), checker.calls.Load(), "FGA Check MUST run for a well-formed id")
}

// TestAuthz_HTTP_WellFormedDeny_StillReturns403 — REST analogue of the
// regression above: well-formed-nonexistent id + deny → HTTP 403, Check runs.
func TestAuthz_HTTP_WellFormedDeny_StillReturns403(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accessBindings/" + wellFormedNonexistentACB: "kacho.cloud.iam.v1.AccessBindingService/Get",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, acbGetEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
		c.Resources = middleware.NewResourceExtractor(map[string]string{
			"kacho.cloud.iam.v1.AccessBindingService/Get": "/iam/v1/accessBindings/{access_binding_id}",
		})
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run for a denied request")
	}))
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/accessBindings/"+wellFormedNonexistentACB, nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code, "well-formed-nonexistent id must keep 403")
	assert.Equal(t, int64(1), checker.calls.Load(), "FGA Check MUST run for a well-formed id")
}

// TestAuthz_GRPC_ScopePolymorphicMalformed_NotShortCircuited — the
// scope-polymorphic path (object_type_from_request_field) is explicitly
// EXCLUDED from id-validation: resource_id there is a foreign-family scope id.
// A "malformed-looking" value must reach the FGA Check (not 400).
func TestAuthz_GRPC_ScopePolymorphicMalformed_NotShortCircuited(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, acbListByScopeEntry), checker)
	req := &iamv1.ListAccessBindingsByScopeRequest{
		ResourceType: "project",
		ResourceId:   malformedACB,
	}
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), req,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccessBindingService/ListByScope"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"scope-polymorphic RPC must NOT be id-validated; it goes to the FGA Check")
	assert.Equal(t, int64(1), checker.calls.Load(),
		"scope-polymorphic RPC must still call the FGA Check")
}
