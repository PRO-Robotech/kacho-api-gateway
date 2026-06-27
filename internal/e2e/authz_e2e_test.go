// authz_e2e_test.go — End-to-end test for the KAC-127 Phase 3 AuthZ
// middleware. Composes:
//
//   - in-process AuthorizeService stub (single Check implementation)
//   - clients.IAMAuthorizeClient dialled at the stub address
//   - middleware.AuthzMiddleware mounted on a minimal HTTP handler
//
// Runs scenarios: allowed → 200, denied → 403, missing-subject → 403,
// catalog-miss → 403, override-allow → 200, override-deny → 403,
// step-up-deny → 403 + WWW-Authenticate, fail-open behaviour.
package e2e_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/clients"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

const authzCatalogJSON = `[
	{
		"fqn":"kacho.cloud.vpc.v1.NetworkService/Create",
		"permission":"vpc.networks.create",
		"required_relation":"editor",
		"scope_extractor":{"object_type":"vpc_network","from_request_field":"folder_id"},
		"required_acr_min":"2","risk_level":"MEDIUM"
	},
	{
		"fqn":"kacho.cloud.vpc.v1.NetworkService/Get",
		"permission":"vpc.networks.get",
		"required_relation":"viewer",
		"scope_extractor":{"object_type":"vpc_network","from_request_field":"network_id"},
		"required_acr_min":"2","risk_level":"LOW"
	},
	{
		"fqn":"kacho.cloud.vpc.v1.NetworkService/Delete",
		"permission":"vpc.networks.delete",
		"required_relation":"editor",
		"scope_extractor":{"object_type":"vpc_network","from_request_field":"network_id"},
		"required_acr_min":"3","requires_mfa_fresh":true,"risk_level":"HIGH"
	}
]`

// authzStub — programmable AuthorizeService for e2e.
type authzStub struct {
	iamv1.UnimplementedAuthorizeServiceServer
	calls atomic.Int64

	allow    atomic.Bool
	reasons  atomic.Pointer[[]string]
	delay    time.Duration
	failNext atomic.Int32
}

func (s *authzStub) Check(ctx context.Context, req *iamv1.AuthorizeCheckRequest) (*iamv1.AuthorizeCheckResponse, error) {
	s.calls.Add(1)
	if s.failNext.Load() > 0 {
		s.failNext.Add(-1)
		return nil, status.Error(codes.Unavailable, "stub down")
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	out := &iamv1.AuthorizeCheckResponse{
		Allowed:              s.allow.Load(),
		AuthorizationModelId: "model-e2e",
		CheckedAt:            timestamppb.Now(),
	}
	if rp := s.reasons.Load(); rp != nil {
		out.DenyReasons = *rp
	}
	return out, nil
}

func startAuthzStub(t *testing.T) (*authzStub, string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	stub := &authzStub{}
	iamv1.RegisterAuthorizeServiceServer(srv, stub)
	go func() { _ = srv.Serve(lis) }()
	return stub, lis.Addr().String(), func() {
		srv.GracefulStop()
		_ = lis.Close()
	}
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeRouter — minimal REST→FQN router for e2e tests.
type fakeRouter struct{ m map[string]string }

func (f *fakeRouter) Resolve(method, path string) (string, bool) {
	fqn, ok := f.m[method+" "+path]
	return fqn, ok
}

// buildE2E builds the middleware composition; returns (server URL, stub).
func buildE2E(t *testing.T, opts ...func(*middleware.AuthzMiddlewareConfig)) (*httptest.Server, *authzStub) {
	t.Helper()
	stub, addr, cleanup := startAuthzStub(t)
	t.Cleanup(cleanup)

	cat := middleware.NewPermissionCatalog()
	require.NoError(t, cat.LoadFromBytes([]byte(authzCatalogJSON)))

	rawClient, err := clients.NewIAMAuthorizeClient(clients.IAMAuthorizeClientConfig{
		Addr:    addr,
		Timeout: 2 * time.Second,
		Logger:  silentLogger(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawClient.Close() })
	checker := clients.NewAuthzChecker(rawClient)

	router := &fakeRouter{m: map[string]string{
		"POST /vpc/v1/networks":              "kacho.cloud.vpc.v1.NetworkService/Create",
		"GET /vpc/v1/networks/enp_x":         "kacho.cloud.vpc.v1.NetworkService/Get",
		"DELETE /vpc/v1/networks/enp_x":      "kacho.cloud.vpc.v1.NetworkService/Delete",
	}}

	cfg := middleware.AuthzMiddlewareConfig{
		Enabled:         true,
		Catalog:         cat,
		Subjects:        middleware.NewSubjectExtractor(true),
		Context:         middleware.NewContextExtractor(time.Now, true),
		Resources:       middleware.NewResourceExtractor(nil),
		Checker:         checker,
		Logger:          silentLogger(),
		CacheTTL:        500 * time.Millisecond,
		CacheMaxEntries: 100,
		PublicAllowlist: middleware.DefaultPublicAllowlist(),
		RestRouter:      router,
	}
	for _, o := range opts {
		o(&cfg)
	}
	mw, err := middleware.NewAuthzMiddleware(cfg)
	require.NoError(t, err)

	handler := mw.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, stub
}

func authedRequest(t *testing.T, ts *httptest.Server, method, path, acr string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("X-Kacho-Principal-Id", "usr_alice")
	req.Header.Set("X-Kacho-Principal-Type", "user")
	req.Header.Set("X-Kacho-Token-Acr", acr)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

func TestE2E_AuthZ_AllowFlows(t *testing.T) {
	ts, stub := buildE2E(t)
	stub.allow.Store(true)

	resp, body := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"ok":true`)
	assert.GreaterOrEqual(t, stub.calls.Load(), int64(1))
}

func TestE2E_AuthZ_DenyFlows(t *testing.T) {
	ts, stub := buildE2E(t)
	stub.allow.Store(false)
	r := []string{"no path"}
	stub.reasons.Store(&r)

	resp, body := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "permission denied")
}

func TestE2E_AuthZ_StepUpDenyAddsChallenge(t *testing.T) {
	ts, stub := buildE2E(t)
	stub.allow.Store(false)
	r := []string{"mfa_fresh: acr=2 (need 3)"}
	stub.reasons.Store(&r)

	resp, _ := authedRequest(t, ts, http.MethodDelete, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	chal := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, chal, "insufficient_user_authentication")
	assert.Contains(t, chal, `acr_values="3"`)
}

// TestE2E_AuthZ_MissingSubject_401 — KAC-130 BUG-2 / KAC-179:
// missing credentials (no Bearer / no X-Kacho-Principal-*) →
// 401 Unauthorized + gRPC code 16 UNAUTHENTICATED, NOT 403 / 7 PERMISSION_DENIED.
//
// RFC 7235 / gRPC status-code guide: UNAUTHENTICATED means "caller is not
// identified"; PERMISSION_DENIED means "identified caller has no access".
// Mapping the missing-subject case to 403 would mislead clients into thinking
// they are authenticated but forbidden — they should instead be prompted to
// supply credentials.
//
// Originally named ..._403 under the old (pre-KAC-130) contract; renamed when
// the product behaviour was corrected, but the assertion was not updated until
// KAC-179. Test now matches the post-KAC-130 product behaviour exactly.
func TestE2E_AuthZ_MissingSubject_401(t *testing.T) {
	ts, _ := buildE2E(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/vpc/v1/networks/enp_x", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestE2E_AuthZ_HealthBypass(t *testing.T) {
	ts, stub := buildE2E(t)
	// No stub setup needed — should never be called.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Zero(t, stub.calls.Load())
}

func TestE2E_AuthZ_OverrideAllow(t *testing.T) {
	overrides := middleware.NewAuthzOverrides()
	require.NoError(t, overrides.LoadFromBytes([]byte(`
overrides:
  - fqn: "kacho.cloud.vpc.v1.NetworkService/Get"
    decision: "allow"
    reason: "e2e test"
`)))
	ts, stub := buildE2E(t, func(c *middleware.AuthzMiddlewareConfig) {
		c.Overrides = overrides
	})
	stub.allow.Store(false) // would normally deny

	resp, _ := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Zero(t, stub.calls.Load(), "override.allow must bypass IAM Check")
}

func TestE2E_AuthZ_OverrideDeny(t *testing.T) {
	overrides := middleware.NewAuthzOverrides()
	require.NoError(t, overrides.LoadFromBytes([]byte(`
overrides:
  - fqn: "kacho.cloud.vpc.v1.NetworkService/Get"
    decision: "deny"
    reason: "e2e lockdown"
`)))
	ts, stub := buildE2E(t, func(c *middleware.AuthzMiddlewareConfig) {
		c.Overrides = overrides
	})
	stub.allow.Store(true) // would normally allow

	resp, _ := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, stub.calls.Load())
}

func TestE2E_AuthZ_FailClosedOnIAMDown(t *testing.T) {
	ts, stub := buildE2E(t)
	stub.failNext.Store(10) // always returns Unavailable

	resp, _ := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestE2E_AuthZ_FailOpenOnIAMDown(t *testing.T) {
	ts, stub := buildE2E(t, func(c *middleware.AuthzMiddlewareConfig) {
		c.FailOpen = true
	})
	stub.failNext.Store(10)

	resp, _ := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestE2E_AuthZ_CacheReusedAcrossCalls(t *testing.T) {
	ts, stub := buildE2E(t)
	stub.allow.Store(true)

	for i := 0; i < 3; i++ {
		resp, _ := authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	// Only the first call should hit the stub — others come from cache.
	assert.LessOrEqual(t, stub.calls.Load(), int64(1))
}

func TestE2E_AuthZ_CacheExpiresAfterTTL(t *testing.T) {
	ts, stub := buildE2E(t, func(c *middleware.AuthzMiddlewareConfig) {
		c.CacheTTL = 50 * time.Millisecond
	})
	stub.allow.Store(true)

	authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")
	time.Sleep(80 * time.Millisecond)
	authedRequest(t, ts, http.MethodGet, "/vpc/v1/networks/enp_x", "2")

	// Two distinct uncached calls.
	assert.Equal(t, int64(2), stub.calls.Load())
}
