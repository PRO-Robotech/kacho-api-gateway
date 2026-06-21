package middleware_test

// authz_dynamic_object_type_test.go — Bug A regression.
//
// AccessBindingService/ListByScope (renamed from ListByResource in RBAC
// rules-model F) is scope-polymorphic: the FGA object type is NOT fixed — it
// is carried by the request's `resource_type` field (project|account|cluster).
// The catalog entry therefore declares
// `scope_extractor.object_type_from_request_field = "resource_type"`. When the
// gateway authz middleware sees that directive it MUST derive the FGA Check
// object_type from the request value, not from the static `object_type`.
//
// Before the fix the static `object_type:"project"` was used unconditionally,
// so an account-scoped ListByScope checked `project:<accountId>` → 403 for
// the account owner. These tests pin the request→object_type derivation on
// both the HTTP (REST query-param) and gRPC (proto reflection) paths.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// listByScopeEntry — catalog row for ListByScope with the dynamic
// object-type directive. `from_request_field` still carries the scope id
// (resource_id); `object_type_from_request_field` carries the scope TYPE.
const listByScopeEntry = `{"fqn":"kacho.cloud.iam.v1.AccessBindingService/ListByScope","permission":"iam.access_bindings_by_resources.listByScope","required_relation":"viewer","scope_extractor":{"object_type":"project","from_request_field":"resource_id","object_type_from_request_field":"resource_type"},"required_acr_min":"2","risk_level":"LOW"}`

func TestAuthz_HTTP_ListByScope_AccountScope_DerivesObjectType(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accessBindings:listByScope": "kacho.cloud.iam.v1.AccessBindingService/ListByScope",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, listByScopeEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet,
		"/iam/v1/accessBindings:listByScope?resourceType=account&resourceId=acc_A", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_owner")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	in := checker.lastInput.Load()
	require.NotNil(t, in, "checker must be called")
	assert.Equal(t, "account", in.ResourceType,
		"FGA object_type must be derived from request resource_type=account (Bug A)")
	assert.Equal(t, "acc_A", in.ResourceID,
		"FGA object id must still come from resource_id")
}

func TestAuthz_HTTP_ListByScope_ClusterScope_DerivesObjectType(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accessBindings:listByScope": "kacho.cloud.iam.v1.AccessBindingService/ListByScope",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, listByScopeEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet,
		"/iam/v1/accessBindings:listByScope?resourceType=cluster&resourceId=cluster_kacho_root", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_boot")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	in := checker.lastInput.Load()
	require.NotNil(t, in)
	assert.Equal(t, "cluster", in.ResourceType,
		"FGA object_type must be derived from request resource_type=cluster (Bug A)")
	assert.Equal(t, "cluster_kacho_root", in.ResourceID)
}

func TestAuthz_GRPC_ListByScope_AccountScope_DerivesObjectType(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, listByScopeEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_owner", "user"),
		&iamv1.ListAccessBindingsByScopeRequest{ResourceType: "account", ResourceId: "acc_A"},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccessBindingService/ListByScope"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.NoError(t, err)

	in := checker.lastInput.Load()
	require.NotNil(t, in)
	assert.Equal(t, "account", in.ResourceType,
		"FGA object_type must be derived from proto resource_type=account (Bug A)")
	assert.Equal(t, "acc_A", in.ResourceID)
}

// listAssignableRolesEntry — sub-phase 1.5 catalog row. ListAssignableRoles
// is scope-polymorphic exactly like ListByScope: the FGA object type is
// carried by the request's `resource_type` field (account|project|cluster), so
// the entry MUST declare `object_type_from_request_field = "resource_type"`.
// A static `object_type:"project"` would make an account/cluster-scoped read
// check `project:<id>` → 403 for the account owner / cluster-admin (Bug A).
const listAssignableRolesEntry = `{"fqn":"kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles","permission":"iam.access_bindings_by_resources.listAssignableRoles","required_relation":"viewer","scope_extractor":{"object_type":"project","from_request_field":"resource_id","object_type_from_request_field":"resource_type"},"required_acr_min":"2","risk_level":"LOW"}`

func TestAuthz_HTTP_ListAssignableRoles_AccountScope_DerivesObjectType(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accessBindings:listAssignableRoles": "kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, listAssignableRolesEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet,
		"/iam/v1/accessBindings:listAssignableRoles?resourceType=account&resourceId=acc_A", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_owner")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	in := checker.lastInput.Load()
	require.NotNil(t, in, "checker must be called")
	assert.Equal(t, "account", in.ResourceType,
		"FGA object_type must be derived from request resource_type=account (scope-polymorphic, D-5)")
	assert.Equal(t, "acc_A", in.ResourceID,
		"FGA object id must still come from resource_id")
}

func TestAuthz_HTTP_ListAssignableRoles_ClusterScope_DerivesObjectType(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accessBindings:listAssignableRoles": "kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, listAssignableRolesEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet,
		"/iam/v1/accessBindings:listAssignableRoles?resourceType=cluster&resourceId=cluster_kacho_root", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_boot")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	in := checker.lastInput.Load()
	require.NotNil(t, in)
	assert.Equal(t, "cluster", in.ResourceType,
		"FGA object_type must be derived from request resource_type=cluster (scope-polymorphic, D-5)")
	assert.Equal(t, "cluster_kacho_root", in.ResourceID)
}

func TestAuthz_GRPC_ListAssignableRoles_AccountScope_DerivesObjectType(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, listAssignableRolesEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_owner", "user"),
		&iamv1.ListAssignableRolesRequest{ResourceType: "account", ResourceId: "acc_A"},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccessBindingService/ListAssignableRoles"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.NoError(t, err)

	in := checker.lastInput.Load()
	require.NotNil(t, in)
	assert.Equal(t, "account", in.ResourceType,
		"FGA object_type must be derived from proto resource_type=account (scope-polymorphic, D-5)")
	assert.Equal(t, "acc_A", in.ResourceID)
}

// TestAuthz_HTTP_StaticObjectType_Unaffected — a catalog entry WITHOUT the
// dynamic directive keeps the static object_type (no regression for the 99%
// of fixed-scope RPCs).
func TestAuthz_HTTP_StaticObjectType_Unaffected(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"GET /vpc/v1/networks/enp_x": "kacho.cloud.vpc.v1.NetworkService/Get",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet, "/vpc/v1/networks/enp_x", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	in := checker.lastInput.Load()
	require.NotNil(t, in)
	assert.Equal(t, "vpc_network", in.ResourceType,
		"static object_type must be preserved when no dynamic directive is set")
}
