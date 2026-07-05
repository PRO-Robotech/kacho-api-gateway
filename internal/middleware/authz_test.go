// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

// fakeChecker — programmable mock implementing middleware.AuthorizeChecker.
type fakeChecker struct {
	calls     atomic.Int64
	allowed   bool
	reasons   []string
	returnErr error
	delay     time.Duration
	lastInput atomic.Pointer[middleware.AuthzCheckInput]
}

func (f *fakeChecker) Check(ctx context.Context, in middleware.AuthzCheckInput) (middleware.AuthzCheckResult, error) {
	f.calls.Add(1)
	cp := in
	f.lastInput.Store(&cp)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return middleware.AuthzCheckResult{}, ctx.Err()
		}
	}
	if f.returnErr != nil {
		return middleware.AuthzCheckResult{}, f.returnErr
	}
	return middleware.AuthzCheckResult{
		Allowed:              f.allowed,
		DenyReasons:          f.reasons,
		AuthorizationModelID: "model_test",
		CheckedAt:            time.Now(),
	}, nil
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func buildCatalog(t *testing.T, entries ...string) *middleware.PermissionCatalog {
	t.Helper()
	c := middleware.NewPermissionCatalog()
	raw := "["
	for i, e := range entries {
		if i > 0 {
			raw += ","
		}
		raw += e
	}
	raw += "]"
	require.NoError(t, c.LoadFromBytes([]byte(raw)))
	return c
}

func buildAuthzMiddleware(t *testing.T, catalog *middleware.PermissionCatalog, checker middleware.AuthorizeChecker, opts ...func(*middleware.AuthzMiddlewareConfig)) *middleware.AuthzMiddleware {
	t.Helper()
	cfg := middleware.AuthzMiddlewareConfig{
		Enabled:         true,
		Catalog:         catalog,
		Subjects:        middleware.NewSubjectExtractor(true),
		Context:         middleware.NewContextExtractor(time.Now, true),
		Resources:       middleware.NewResourceExtractor(nil),
		Checker:         checker,
		Logger:          silentLogger(),
		CacheTTL:        5 * time.Second,
		CacheMaxEntries: 100,
		PublicAllowlist: middleware.DefaultPublicAllowlist(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	mw, err := middleware.NewAuthzMiddleware(cfg)
	require.NoError(t, err)
	return mw
}

// withTokenMD — gRPC ctx with principal metadata simulating an authenticated request.
func withTokenMD(subj string, ptype string) context.Context {
	md := metadata.New(map[string]string{
		"x-kacho-principal-id":   subj,
		"x-kacho-principal-type": ptype,
		"x-kacho-token-acr":      "2",
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

const (
	createEntry = `{"fqn":"kacho.cloud.vpc.v1.NetworkService/Create","permission":"vpc.networks.create","required_relation":"editor","scope_extractor":{"object_type":"vpc_network","from_request_field":"folder_id"},"required_acr_min":"2","risk_level":"MEDIUM"}`
	getEntry    = `{"fqn":"kacho.cloud.vpc.v1.NetworkService/Get","permission":"vpc.networks.get","required_relation":"viewer","scope_extractor":{"object_type":"vpc_network","from_request_field":"network_id"},"required_acr_min":"2","risk_level":"LOW"}`
	deleteEntry = `{"fqn":"kacho.cloud.vpc.v1.NetworkService/Delete","permission":"vpc.networks.delete","required_relation":"editor","scope_extractor":{"object_type":"vpc_network","from_request_field":"network_id"},"required_acr_min":"3","requires_mfa_fresh":true,"risk_level":"HIGH"}`
	exemptEntry = `{"fqn":"kacho.cloud.iam.v1.AuthService/Login","permission":"<exempt>"}`
)

func TestAuthz_GRPC_NoEnabled_PassThrough(t *testing.T) {
	mw, err := middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{Enabled: false})
	require.NoError(t, err)
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}
	_, err = mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		handler)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAuthz_GRPC_Allowlist_BypassesChecker(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.NoError(t, err)
	assert.Zero(t, checker.calls.Load())
}

func TestAuthz_GRPC_CatalogMiss_Denies(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.unknown.v1.X/Y"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Zero(t, checker.calls.Load())
}

func TestAuthz_GRPC_ExemptEntry_Allows(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	mw := buildAuthzMiddleware(t, buildCatalog(t, exemptEntry), checker)
	called := false
	_, err := mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AuthService/Login"},
		func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil })
	require.NoError(t, err)
	assert.True(t, called)
	assert.Zero(t, checker.calls.Load())
}

func TestAuthz_GRPC_NoSubject_Denies(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	// missing credentials → UNAUTHENTICATED (16), not PermissionDenied (7).
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Zero(t, checker.calls.Load())
}

// TestAuthz_GRPC_NoSubject_Unauthenticated verifies an anonymous request
// (no JWT metadata) on a catalogued RPC returns Unauthenticated (16) so the
// caller knows credentials are required. PermissionDenied (7) is reserved for
// authenticated-but-denied.
func TestAuthz_GRPC_NoSubject_Unauthenticated(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code(),
		"missing credentials must map to UNAUTHENTICATED(16), not PermissionDenied(7)")
	// Checker must never be called — we never reach the IAM Check phase.
	assert.Zero(t, checker.calls.Load())
}

// TestAuthz_GRPC_ExemptEntry_NoSubject_Unauthenticated verifies an anonymous
// request on an exempt (scope-filter) RPC also returns Unauthenticated (16) —
// the exempt gate still requires authentication.
func TestAuthz_GRPC_ExemptEntry_NoSubject_Unauthenticated(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	// Use the exempt catalog entry — Login is on the allowlist; build a
	// non-allowlisted exempt entry for this test.
	listExemptEntry := `{"fqn":"kacho.cloud.iam.v1.UserService/List","permission":"<exempt>"}`
	mw := buildAuthzMiddleware(t, buildCatalog(t, listExemptEntry), checker)
	_, err := mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.UserService/List"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code(),
		"anonymous on exempt RPC must return UNAUTHENTICATED(16), not PermissionDenied(7)")
	assert.Zero(t, checker.calls.Load())
}

// TestAuthz_HTTP_NoSubject_Returns401 verifies the HTTP path for missing
// credentials returns 401 (not 403).
func TestAuthz_HTTP_NoSubject_Returns401(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"POST /vpc/v1/networks": "kacho.cloud.vpc.v1.NetworkService/Create",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach handler") }))
	// No Authorization / principal headers — anonymous request.
	r := httptest.NewRequest(http.MethodPost, "/vpc/v1/networks", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"missing credentials must produce 401, not 403")
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, float64(16), body["code"],
		"grpc code in JSON body must be 16 (UNAUTHENTICATED)")
}

// TestAuthz_GRPC_AuthenticatedDeny_StillPermissionDenied verifies an
// authenticated subject rejected by FGA keeps returning PermissionDenied (7),
// not Unauthenticated.
func TestAuthz_GRPC_AuthenticatedDeny_StillPermissionDenied(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"authenticated subject denied by FGA must remain PermissionDenied(7)")
}

func TestAuthz_GRPC_Allow(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	called := false
	req := &iamv1.AuthorizeCheckRequest{Subject: "user:usr_x"}
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), req,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil })
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, int64(1), checker.calls.Load())
	last := checker.lastInput.Load()
	require.NotNil(t, last)
	assert.Equal(t, "user:usr_x", last.Subject)
	assert.Equal(t, "vpc.networks.create", last.Action)
}

func TestAuthz_GRPC_Deny_ReturnsPermissionDenied(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"mfa_fresh: acr=2 (need 3)"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, deleteEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Delete"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "vpc.networks.delete")
	// Details should contain a PreconditionFailure.
	require.NotEmpty(t, st.Details())
}

func TestAuthz_GRPC_CacheHit_NoSecondCall(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker)
	ctx := withTokenMD("usr_x", "user")
	handler := func(ctx context.Context, req any) (any, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"}

	for i := 0; i < 3; i++ {
		_, err := mw.Unary()(ctx, nil, info, handler)
		require.NoError(t, err)
	}
	assert.Equal(t, int64(1), checker.calls.Load(), "second/third calls must hit cache")
}

func TestAuthz_GRPC_CheckerError_FailClosed(t *testing.T) {
	checker := &fakeChecker{returnErr: errors.New("backend down")}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestAuthz_GRPC_CheckerError_FailOpen(t *testing.T) {
	checker := &fakeChecker{returnErr: errors.New("backend down")}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.FailOpen = true
	})
	called := false
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil })
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAuthz_GRPC_CheckerPermissionDeniedFromServer(t *testing.T) {
	checker := &fakeChecker{returnErr: status.Error(codes.PermissionDenied, "denied by FGA")}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// fakeRestRouter — explicit path→FQN mapping for HTTP tests.
type fakeRestRouter struct{ m map[string]string }

func (f *fakeRestRouter) Resolve(method, path string) (string, bool) {
	if fqn, ok := f.m[method+" "+path]; ok {
		return fqn, true
	}
	// Also try wildcard suffix /<id> stripping.
	return "", false
}

func TestAuthz_HTTP_Allow(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	router := &fakeRestRouter{m: map[string]string{
		"GET /vpc/v1/networks/enp_x": "kacho.cloud.vpc.v1.NetworkService/Get",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	called := false
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/vpc/v1/networks/enp_x", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthz_HTTP_Deny_ReturnsJSON403(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	router := &fakeRestRouter{m: map[string]string{
		"DELETE /vpc/v1/networks/enp_x": "kacho.cloud.vpc.v1.NetworkService/Delete",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, deleteEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach handler") }))
	r := httptest.NewRequest(http.MethodDelete, "/vpc/v1/networks/enp_x", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestAuthz_HTTP_StepUpDeny_AddsWWWAuthenticate(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"mfa_fresh: acr=2 (need 3)"}}
	router := &fakeRestRouter{m: map[string]string{
		"DELETE /vpc/v1/networks/enp_x": "kacho.cloud.vpc.v1.NetworkService/Delete",
	}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, deleteEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.RestRouter = router
	})
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach handler") }))
	r := httptest.NewRequest(http.MethodDelete, "/vpc/v1/networks/enp_x", nil)
	r.Header.Set("X-Kacho-Principal-Id", "usr_x")
	r.Header.Set("X-Kacho-Principal-Type", "user")
	r.Header.Set("X-Kacho-Token-Acr", "2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	chal := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, chal, "insufficient_user_authentication")
	assert.Contains(t, chal, `acr_values="3"`)
}

func TestAuthz_HTTP_Public_BypassesPipeline(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	called := false
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthz_Override_Allow(t *testing.T) {
	checker := &fakeChecker{allowed: false}
	overrides := middleware.NewAuthzOverrides()
	require.NoError(t, overrides.LoadFromBytes([]byte(`
overrides:
  - fqn: "kacho.cloud.vpc.v1.NetworkService/Create"
    decision: "allow"
`)))
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.Overrides = overrides
	})
	called := false
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil })
	require.NoError(t, err)
	assert.True(t, called)
	assert.Zero(t, checker.calls.Load(), "override.allow must bypass IAM Check")
}

func TestAuthz_Override_Deny(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	overrides := middleware.NewAuthzOverrides()
	require.NoError(t, overrides.LoadFromBytes([]byte(`
overrides:
  - fqn: "kacho.cloud.vpc.v1.NetworkService/Get"
    decision: "deny"
    reason: "emergency lock"
`)))
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker, func(c *middleware.AuthzMiddlewareConfig) {
		c.Overrides = overrides
	})
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Zero(t, checker.calls.Load())
}

func TestAuthz_Metrics_RecordAllowDenyError(t *testing.T) {
	checkerAllow := &fakeChecker{allowed: true}
	mwAllow := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checkerAllow)
	_, _ = mwAllow.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	snap := mwAllow.Metrics().Snapshot()
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_total{result="allowed"}`])

	checkerDeny := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mwDeny := buildAuthzMiddleware(t, buildCatalog(t, deleteEntry), checkerDeny)
	_, _ = mwDeny.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Delete"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	snap = mwDeny.Metrics().Snapshot()
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_total{result="denied"}`])

	checkerErr := &fakeChecker{returnErr: errors.New("boom")}
	mwErr := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checkerErr)
	_, _ = mwErr.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Create"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	snap = mwErr.Metrics().Snapshot()
	assert.Equal(t, float64(1), snap[`kacho_api_gateway_authz_check_total{result="error"}`])
}

func TestAuthz_Metrics_CacheHitRatio(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker)
	ctx := withTokenMD("usr_x", "user")
	info := &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"}
	h := func(ctx context.Context, req any) (any, error) { return "ok", nil }
	for i := 0; i < 5; i++ {
		_, _ = mw.Unary()(ctx, nil, info, h)
	}
	// First call → miss, next 4 → hit. Ratio 4/(4+1) = 0.8.
	assert.InDelta(t, 0.8, mw.Metrics().CacheHitRatio(), 0.0001)
}

func TestAuthz_Constructor_RequiresFields(t *testing.T) {
	_, err := middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{Enabled: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Catalog")
}

func TestAuthz_Constructor_NoOpWhenDisabled(t *testing.T) {
	mw, err := middleware.NewAuthzMiddleware(middleware.AuthzMiddlewareConfig{Enabled: false})
	require.NoError(t, err)
	require.NotNil(t, mw)
	// HTTP should be a pass-through.
	called := false
	h := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodGet, "/any", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.True(t, called)
}

// ---- regression tests ----

// TestAuthz_EmbeddedCatalog_OperationServiceFQNsCorrect проверяет, что
// встроенный каталог содержит OperationService записи с корректными FQN
// (без ".v1." — proto package "kacho.cloud.operation"). Это гарантирует, что
// allowlist-чек (который тоже использует FQN без v1) совпадет с маршрутной
// таблицей.
func TestAuthz_EmbeddedCatalog_OperationServiceFQNsCorrect(t *testing.T) {
	cat, err := middleware.LoadEmbeddedPermissionCatalog("")
	require.NoError(t, err)

	// OperationService.Get — must be present with <exempt> permission.
	get, ok := cat.Lookup("kacho.cloud.operation.OperationService/Get")
	require.True(t, ok, "catalog must have kacho.cloud.operation.OperationService/Get (no .v1.)")
	assert.True(t, get.IsExempt(), "OperationService/Get must be <exempt>")

	// OperationService.Cancel — must be present with <exempt> permission.
	cancel, ok := cat.Lookup("kacho.cloud.operation.OperationService/Cancel")
	require.True(t, ok, "catalog must have kacho.cloud.operation.OperationService/Cancel (no .v1.)")
	assert.True(t, cancel.IsExempt(), "OperationService/Cancel must be <exempt>")

	// Wrong FQN (with .v1.) must NOT be in catalog.
	_, badGet := cat.Lookup("kacho.cloud.operation.v1.OperationService/Get")
	assert.False(t, badGet, "catalog must NOT have the wrong v1-suffixed FQN")

	// AccessBindingService listBy* entries must exist. The scope-based listing
	// is exposed as ListByScope.
	_, okListByScope := cat.Lookup("kacho.cloud.iam.v1.AccessBindingService/ListByScope")
	assert.True(t, okListByScope, "catalog must have AccessBindingService/ListByScope")

	_, okListBySubject := cat.Lookup("kacho.cloud.iam.v1.AccessBindingService/ListBySubject")
	assert.True(t, okListBySubject, "catalog must have AccessBindingService/ListBySubject")

	// ListSubjectPrivileges — public read, mirrors ListBySubject (viewer
	// relation, cluster scope-floor, ACR>=2). Catalog entry must exist so the
	// per-RPC authz middleware applies the anti-anon + ACR floor (the precise
	// self/account-admin policy is enforced in the iam handler).
	lsp, okListSubjectPrivileges := cat.Lookup("kacho.cloud.iam.v1.AccessBindingService/ListSubjectPrivileges")
	require.True(t, okListSubjectPrivileges, "catalog must have AccessBindingService/ListSubjectPrivileges")
	assert.False(t, lsp.IsExempt(), "ListSubjectPrivileges must NOT be <exempt> — it carries a real viewer permission gate")
}

// TestAuthz_DefaultPublicAllowlist_NoOperationV1FQN проверяет, что allowlist
// НЕ содержит ".v1." FQN для OperationService (они никогда не совпали бы с
// маршрутной таблицей, из-за чего каталог обрабатывал бы запрос и мог давать
// "unauthenticated request" ошибку).
func TestAuthz_DefaultPublicAllowlist_NoOperationV1FQN(t *testing.T) {
	for _, fqn := range middleware.DefaultPublicAllowlist() {
		assert.NotContains(t, fqn, "operation.v1.",
			"allowlist must not contain wrong v1-namespaced OperationService FQN: %s", fqn)
		assert.NotContains(t, fqn, "OperationService/List",
			"allowlist must not contain non-existent OperationService/List: %s", fqn)
	}
}

// TestAuthz_GRPC_CatalogMiss_AuthenticatedReason проверяет, что authenticated
// caller на uncatalogued метод получает PermissionDenied с PreconditionFailure
// violation, description которого НЕ содержит "unauthenticated". Это
// подтверждает, что authenticated caller не классифицируется как анонимный.
func TestAuthz_GRPC_CatalogMiss_AuthenticatedReason(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	_, err := mw.Unary()(withTokenMD("usr_x", "user"), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.unknown.v1.X/Y"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	// Детали ошибки — PreconditionFailure violations с описанием причины.
	allDescs := collectViolationDescriptions(t, st)
	for _, d := range allDescs {
		assert.NotContains(t, d, "unauthenticated",
			"authenticated caller on catalog-miss violation description must NOT contain 'unauthenticated': %s", d)
	}
	assert.Zero(t, checker.calls.Load())
}

// TestAuthz_GRPC_CatalogMiss_UnauthenticatedReason проверяет, что
// unauthenticated caller на uncatalogued метод тоже получает PermissionDenied,
// но violation description содержит "unauthenticated" для observability.
func TestAuthz_GRPC_CatalogMiss_UnauthenticatedReason(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, createEntry), checker)
	// Нет principal-метаданных → анонимный caller.
	_, err := mw.Unary()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.unknown.v1.X/Y"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	allDescs := collectViolationDescriptions(t, st)
	found := false
	for _, d := range allDescs {
		if strings.Contains(d, "unauthenticated") {
			found = true
		}
	}
	assert.True(t, found,
		"unauthenticated caller on catalog-miss must have 'unauthenticated' in some violation description; got: %v", allDescs)
	assert.Zero(t, checker.calls.Load())
}

// collectViolationDescriptions extracts Description strings from PreconditionFailure
// details attached to a gRPC status (used by the catalog-miss tests).
func collectViolationDescriptions(t *testing.T, st *status.Status) []string {
	t.Helper()
	var descs []string
	for _, d := range st.Details() {
		// Assert on the Any-typed detail without importing errdetails: the
		// concrete type is *errdetails.PreconditionFailure; fmt.Sprint renders
		// its violation descriptions, which is all the assertions below need.
		str := fmt.Sprint(d)
		descs = append(descs, str)
	}
	return descs
}

func TestAuthz_CheckInputCarriesContext(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker)
	ctx := withTokenMD("usr_x", "user")
	_, err := mw.Unary()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"},
		func(ctx context.Context, req any) (any, error) { return "ok", nil })
	require.NoError(t, err)
	last := checker.lastInput.Load()
	require.NotNil(t, last)
	assert.Equal(t, "vpc.networks.get", last.Action)
	assert.Equal(t, "vpc_network", last.ResourceType)
	// Context should always contain current_time.
	_, hasNow := last.Context["current_time"]
	assert.True(t, hasNow)
	// And acr_value because metadata sets X-Kacho-Token-Acr=2.
	assert.Equal(t, "2", last.Context["acr_value"])
}

func TestAuthz_Stream_Allow(t *testing.T) {
	checker := &fakeChecker{allowed: true}
	mw := buildAuthzMiddleware(t, buildCatalog(t, getEntry), checker)
	// Build a fake server stream context.
	ss := &fakeServerStream{ctx: withTokenMD("usr_x", "user")}
	called := false
	err := mw.Stream()(nil, ss, &grpc.StreamServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Get"},
		func(srv any, ss grpc.ServerStream) error { called = true; return nil })
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAuthz_Stream_Deny(t *testing.T) {
	checker := &fakeChecker{allowed: false, reasons: []string{"no path"}}
	mw := buildAuthzMiddleware(t, buildCatalog(t, deleteEntry), checker)
	ss := &fakeServerStream{ctx: withTokenMD("usr_x", "user")}
	err := mw.Stream()(nil, ss, &grpc.StreamServerInfo{FullMethod: "/kacho.cloud.vpc.v1.NetworkService/Delete"},
		func(srv any, ss grpc.ServerStream) error { return nil })
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// fakeServerStream — minimal grpc.ServerStream impl for stream tests.
type fakeServerStream struct {
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context     { return f.ctx }
func (f *fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeServerStream) SetTrailer(metadata.MD)       {}
func (f *fakeServerStream) SendMsg(m any) error          { return nil }
func (f *fakeServerStream) RecvMsg(m any) error          { return io.EOF }
