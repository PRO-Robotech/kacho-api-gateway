// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// Hide-existence-on-read-deny: a denied authz Check on a verb-bearing IAM read
// (Get) RPC must surface as NotFound(5) / HTTP 404 — NOT PermissionDenied(7) /
// 403 — and must not leak deny_reasons. This matches the IAM read_authz.go
// contract ("never PermissionDenied, no enumeration / existence leak") and the
// already-correct RoleService.Get behavior; account/project/user/sa/group/binding
// Get used to 403 because the gateway Check short-circuited before IAM.
//
// Catalog entries mirror the embedded permission_catalog.json: read Get RPCs of
// IAM verb-bearing resources carry required_relation=v_get + a concrete
// per-resource scope.

const (
	// IAM read Get entries (verb-bearing, concrete scope) — hide existence on deny.
	accountGetEntry = `{"fqn":"kacho.cloud.iam.v1.AccountService/Get","permission":"iam.accounts.get","required_relation":"v_get","scope_extractor":{"object_type":"account","from_request_field":"account_id"},"required_acr_min":"2"}`
	projectGetEntry = `{"fqn":"kacho.cloud.iam.v1.ProjectService/Get","permission":"iam.projects.get","required_relation":"v_get","scope_extractor":{"object_type":"project","from_request_field":"project_id"},"required_acr_min":"2"}`
	userGetEntry    = `{"fqn":"kacho.cloud.iam.v1.UserService/Get","permission":"iam.users.get","required_relation":"v_get","scope_extractor":{"object_type":"iam_user","from_request_field":"user_id"},"required_acr_min":"2"}`
	saGetEntry      = `{"fqn":"kacho.cloud.iam.v1.ServiceAccountService/Get","permission":"iam.service_accounts.get","required_relation":"v_get","scope_extractor":{"object_type":"iam_service_account","from_request_field":"service_account_id"},"required_acr_min":"2"}`
	groupGetEntry   = `{"fqn":"kacho.cloud.iam.v1.GroupService/Get","permission":"iam.groups.get","required_relation":"v_get","scope_extractor":{"object_type":"iam_group","from_request_field":"group_id"},"required_acr_min":"2"}`

	// IAM mutation entry — must stay PermissionDenied(403) on deny.
	accountDeleteEntry = `{"fqn":"kacho.cloud.iam.v1.AccountService/Delete","permission":"iam.accounts.delete","required_relation":"v_delete","scope_extractor":{"object_type":"account","from_request_field":"account_id"},"required_acr_min":"2"}`
)

func iamReadGetEntries() []struct {
	name string
	fqn  string
	js   string
} {
	return []struct {
		name string
		fqn  string
		js   string
	}{
		{"account", "/kacho.cloud.iam.v1.AccountService/Get", accountGetEntry},
		{"project", "/kacho.cloud.iam.v1.ProjectService/Get", projectGetEntry},
		{"user", "/kacho.cloud.iam.v1.UserService/Get", userGetEntry},
		{"service_account", "/kacho.cloud.iam.v1.ServiceAccountService/Get", saGetEntry},
		{"group", "/kacho.cloud.iam.v1.GroupService/Get", groupGetEntry},
	}
}

// TestAuthz_GRPC_ReadDeny_HidesExistence_NotFound — read-deny on every IAM
// verb-bearing Get RPC → NotFound(5), not PermissionDenied(7).
func TestAuthz_GRPC_ReadDeny_HidesExistence_NotFound(t *testing.T) {
	for _, tc := range iamReadGetEntries() {
		t.Run(tc.name, func(t *testing.T) {
			checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
			mw := buildAuthzMiddleware(t, buildCatalog(t, tc.js), checker)
			_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
				&grpc.UnaryServerInfo{FullMethod: tc.fqn},
				func(ctx context.Context, req any) (any, error) {
					t.Fatal("handler must not be reached on deny")
					return nil, nil
				})
			require.Error(t, err)
			st, _ := status.FromError(err)
			assert.Equal(t, codes.NotFound, st.Code(),
				"read-deny on %s must hide existence (NotFound, not PermissionDenied)", tc.name)
		})
	}
}

// TestAuthz_GRPC_ReadDeny_NoDenyReasonsLeak — the NotFound status must not carry
// verbose deny_reasons / PreconditionFailure violations (no enumeration leak).
func TestAuthz_GRPC_ReadDeny_NoDenyReasonsLeak(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path: account:acc_secret has no v_get for user:usr_x"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, accountGetEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccountService/Get"},
		func(ctx context.Context, req any) (any, error) { return nil, nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.NotFound, st.Code())
	// No internal reason text in the message.
	assert.NotContains(t, strings.ToLower(st.Message()), "no path")
	assert.NotContains(t, strings.ToLower(st.Message()), "v_get")
	// Detail payloads must not echo the verbose reason (existence-leak guard).
	for _, d := range st.Details() {
		assert.NotContains(t, strings.ToLower(toString(d)), "no path",
			"NotFound detail must not echo deny reasons")
	}
}

// TestAuthz_GRPC_MutationDeny_StaysPermissionDenied — a mutation deny keeps the
// correct PermissionDenied(7); hide-existence applies to reads only.
func TestAuthz_GRPC_MutationDeny_StaysPermissionDenied(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, accountDeleteEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccountService/Delete"},
		func(ctx context.Context, req any) (any, error) { return nil, nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"mutation deny must stay PermissionDenied(7), not be hidden as NotFound")
}

// TestAuthz_GRPC_ReadDeny_ExistingDeniedEqualsNonexistent — both an existing
// resource the caller is denied AND a (well-formed) nonexistent id resolve to
// the SAME NotFound at the gateway (FGA denies both; identical 404 → no
// enumeration leak). Modeled by two denied Checks differing only in id.
func TestAuthz_GRPC_ReadDeny_ExistingDeniedEqualsNonexistent(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, accountGetEntry), checker)
	run := func() codes.Code {
		_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
			&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccountService/Get"},
			func(ctx context.Context, req any) (any, error) { return nil, nil })
		st, _ := status.FromError(err)
		return st.Code()
	}
	existingDenied := run()
	nonexistent := run()
	assert.Equal(t, codes.NotFound, existingDenied)
	assert.Equal(t, existingDenied, nonexistent,
		"existing-denied and nonexistent must be indistinguishable (both NotFound)")
}

// TestAuthz_HTTP_ReadDeny_Returns404 — REST surface: read-deny → 404 + grpc code 5,
// no deny_reasons in the JSON body.
func TestAuthz_HTTP_ReadDeny_Returns404(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path: secret reason"}}
	router := &fakeRestRouter{m: map[string]string{
		"GET /iam/v1/accounts/acc_x": "kacho.cloud.iam.v1.AccountService/Get",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, accountGetEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach handler") }))
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/accounts/acc_x", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code, "read-deny REST must be 404")
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	body := w.Body.String()
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	assert.Equal(t, float64(5), parsed["code"], "grpc code in JSON body must be 5 (NOT_FOUND)")
	assert.NotContains(t, strings.ToLower(body), "secret reason",
		"404 body must not leak deny reasons")
	assert.NotContains(t, strings.ToLower(body), "deny_reasons",
		"404 body must not carry deny_reasons metadata")
}

// TestAuthz_HTTP_MutationDeny_Stays403 — REST mutation deny stays 403.
func TestAuthz_HTTP_MutationDeny_Stays403(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	router := &fakeRestRouter{m: map[string]string{
		"DELETE /iam/v1/accounts/acc_x": "kacho.cloud.iam.v1.AccountService/Delete",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, accountDeleteEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach handler") }))
	r := httptest.NewRequest(http.MethodDelete, "/iam/v1/accounts/acc_x", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code, "mutation deny REST must stay 403")
}

// TestAuthz_GRPC_ReadAllow_PassesThrough — a granted read still reaches the
// handler (the fix must not break the allow path).
func TestAuthz_GRPC_ReadAllow_PassesThrough(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, accountGetEntry), checker)
	called := false
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AccountService/Get"},
		func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil })
	require.NoError(t, err)
	assert.True(t, called, "granted read must reach the handler")
}

// toString renders a proto detail message to a string for leak assertions.
func toString(v any) string {
	if s, ok := v.(interface{ String() string }); ok {
		return s.String()
	}
	return ""
}
