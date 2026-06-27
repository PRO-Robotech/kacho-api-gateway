// iam_authorize_client.go — gRPC-direct client adapter for
// `kacho.cloud.iam.v1.AuthorizeService.Check` (KAC-127 Phase 3).
//
// The api-gateway authz middleware fans out a Check call for every
// non-allowlisted RPC. Latency budget per acceptance §4.4: ≤ 5ms p95 on a
// cache hit, ≤ 15ms p95 on a miss (sum of all stages; the Check RPC itself
// budgets ≤ 10ms p95 server-side per NFR-2). We enforce a 200ms hard cap
// per the implementation brief; anything slower is treated as transient
// error and surfaces as `Unavailable` (fail-closed unless
// `KACHO_API_GATEWAY_AUTHZ_FAIL_OPEN=true`).
//
// Connection pooling: single `*grpc.ClientConn` with
// `loadBalancingConfig=round_robin` (matches the gateway's other backend
// dial pattern in main.go). Keepalives match the rest of the wiring.
//
// Retries: at most one retry on `Unavailable`, no retry on `PermissionDenied`
// or `InvalidArgument` (semantic errors — retrying would just thrash).
//
// Loop-prevention запрет #6: AuthorizeService is the **public** RPC
// (port 9090) per the proto (`option (google.api.http) = { post: ... }`);
// the per-RPC gating path is conceptually fine — the api-gateway calling
// IAM's public AuthorizeService is allowed. We do NOT route this through
// the api-gateway's own restmux (would infinite-loop); the adapter dials
// directly to the IAM backend cluster-internal address.
package clients

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"
)

// AuthorizeCheckInput — caller-friendly Check arguments. The adapter wraps
// these in the proto request shape internally.
type AuthorizeCheckInput struct {
	// Subject — FGA-shaped ("user:usr_abc"). Required.
	Subject string

	// Action — `<domain>.<resource>.<verb>` ("vpc.networks.create"). Required.
	Action string

	// RequiredRelation — KAC-198 follow-up: explicit FGA relation from the
	// permission catalog. When non-empty, IAM honors it verbatim instead
	// of deriving from action verb. Required for admin-only RPCs whose
	// `*.list`/`*.get` verb would otherwise resolve to `viewer` and slip
	// through the `cluster.viewer = user:*` cascade.
	RequiredRelation string

	// ResourceType — FGA object type ("vpc_network" / "project" / "*").
	// Required.
	ResourceType string

	// ResourceID — bare resource id (no prefix). "*" indicates wildcard
	// (List/Search RPCs); the adapter passes it through unchanged.
	ResourceID string

	// Context — Condition-evaluation map (see context_extractor.go).
	// Optional.
	Context map[string]any

	// TraceID — request-id correlation passed through to FGA / audit
	// pipeline. Optional.
	TraceID string
}

// AuthorizeCheckResult — caller-friendly Check result.
type AuthorizeCheckResult struct {
	// Allowed — true when authorization grants the action.
	Allowed bool

	// DenyReasons — ordered short-string reasons (acceptance §5.2). Empty
	// on Allowed=true.
	DenyReasons []string

	// AuthorizationModelID — pinned model id (for forensics).
	AuthorizationModelID string

	// CheckedAt — timestamp the IAM service stamped the decision.
	CheckedAt time.Time
}

// AuthorizeClient — interface the authz middleware depends on. Mock-able.
//
// The middleware uses its own `middleware.AuthzCheckInput` shape to avoid
// a clients ↔ middleware import cycle (the middleware package is imported
// by the gRPC subject client adapter, so it cannot itself depend on
// `clients`). The IAM client embeds an adapter that converts between
// shapes — see `IAMAuthorizeClient.AsAuthzChecker`.
type AuthorizeClient interface {
	Check(ctx context.Context, in AuthorizeCheckInput) (AuthorizeCheckResult, error)
	Close() error
}

// IAMAuthorizeClient — production implementation backed by gRPC.
type IAMAuthorizeClient struct {
	conn       *grpc.ClientConn
	stub       iamv1.AuthorizeServiceClient
	timeout    time.Duration
	maxRetries int
	logger     *slog.Logger

	// callsTotal — diagnostic counter (separate from the per-decision
	// metrics; this counts wire-level RPCs including retries).
	callsTotal atomic.Int64
}

// IAMAuthorizeClientConfig — DI bag.
type IAMAuthorizeClientConfig struct {
	// Addr — IAM AuthorizeService address ("iam.kacho.svc.cluster.local:9090").
	// Required.
	Addr string

	// Timeout — hard timeout per Check call. Default 200ms per impl brief.
	Timeout time.Duration

	// MaxRetries — retries on Unavailable. Default 1.
	MaxRetries int

	// Logger — slog. Required.
	Logger *slog.Logger

	// TransportCreds — SEC-E per-edge transport-credentials dial-option for the
	// gateway→iam edge (mTLS client-cert when KACHO_API_GATEWAY_MTLS_IAM_ENABLE=true,
	// assembled in cmd/api-gateway). nil ⇒ insecure (dev backward-compat). The
	// transport layer is orthogonal to the principal-metadata propagated per RPC
	// (epic invariant I2).
	TransportCreds grpc.DialOption
}

// NewIAMAuthorizeClient dials the IAM backend and returns a ready client.
func NewIAMAuthorizeClient(cfg IAMAuthorizeClientConfig) (*IAMAuthorizeClient, error) {
	if cfg.Addr == "" {
		return nil, errors.New("iam authorize client: addr is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("iam authorize client: logger is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 200 * time.Millisecond
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.MaxRetries == 0 {
		// Default 1 retry on Unavailable.
		cfg.MaxRetries = 1
	}
	transportCreds := cfg.TransportCreds
	if transportCreds == nil {
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	// KAC-244: Time=10s — authorize-conn (list-filter authz) реже используется и
	// успевает остыть в простое; 30s-ping слишком медленный для kind → первый
	// authz-check после простоя таймаутит (200ms) → список приходит пустым.
	kp := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}
	conn, err := grpc.NewClient(cfg.Addr,
		transportCreds,
		grpc.WithKeepaliveParams(kp),
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
	)
	if err != nil {
		return nil, fmt.Errorf("dial iam authorize %s: %w", cfg.Addr, err)
	}
	return &IAMAuthorizeClient{
		conn:       conn,
		stub:       iamv1.NewAuthorizeServiceClient(conn),
		timeout:    cfg.Timeout,
		maxRetries: cfg.MaxRetries,
		logger:     cfg.Logger,
	}, nil
}

// NewIAMAuthorizeClientFromConn — convenience for tests sharing an existing
// ClientConn (testcontainers / bufconn). Skips the dial.
func NewIAMAuthorizeClientFromConn(conn *grpc.ClientConn, logger *slog.Logger, timeout time.Duration, maxRetries int) *IAMAuthorizeClient {
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}
	if maxRetries <= 0 {
		maxRetries = 1
	}
	return &IAMAuthorizeClient{
		conn:       conn,
		stub:       iamv1.NewAuthorizeServiceClient(conn),
		timeout:    timeout,
		maxRetries: maxRetries,
		logger:     logger,
	}
}

// Check executes a single authorization decision with retry-on-Unavailable.
func (c *IAMAuthorizeClient) Check(ctx context.Context, in AuthorizeCheckInput) (AuthorizeCheckResult, error) {
	if in.Subject == "" {
		return AuthorizeCheckResult{}, errors.New("authorize check: empty subject")
	}
	if in.Action == "" {
		return AuthorizeCheckResult{}, errors.New("authorize check: empty action")
	}
	if in.ResourceType == "" {
		return AuthorizeCheckResult{}, errors.New("authorize check: empty resource_type")
	}
	if in.ResourceID == "" {
		// Wildcard resource — pass through as "*" so FGA does cluster-level
		// resolution. AuthorizeService validates ResourceRef.id length 1-64,
		// and "*" satisfies that.
		in.ResourceID = "*"
	}

	req := &iamv1.AuthorizeCheckRequest{
		Subject:          in.Subject,
		Resource:         &iamv1.ResourceRef{Type: in.ResourceType, Id: in.ResourceID},
		Action:           in.Action,
		RequiredRelation: in.RequiredRelation,
		TraceId:          truncateStr(in.TraceID, 64),
	}
	if ctxStruct, err := buildContextStruct(in.Context); err != nil {
		return AuthorizeCheckResult{}, fmt.Errorf("authorize check: build context: %w", err)
	} else if ctxStruct != nil {
		req.Context = ctxStruct
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, c.timeout)
		c.callsTotal.Add(1)
		resp, err := c.stub.Check(callCtx, req)
		cancel()
		if err == nil {
			return toResult(resp), nil
		}
		lastErr = err
		code := status.Code(err)
		// PermissionDenied / InvalidArgument / NotFound — terminal.
		switch code {
		case codes.PermissionDenied, codes.InvalidArgument, codes.NotFound,
			codes.Unauthenticated, codes.FailedPrecondition:
			return AuthorizeCheckResult{}, err
		}
		// Unavailable / DeadlineExceeded / ResourceExhausted — retry up to
		// maxRetries.
		if attempt < c.maxRetries && retryable(code) {
			c.logger.Warn("authorize check retrying",
				"attempt", attempt+1,
				"code", code.String(),
				"err", err)
			continue
		}
		return AuthorizeCheckResult{}, err
	}
	return AuthorizeCheckResult{}, lastErr
}

// Close releases the gRPC connection.
func (c *IAMAuthorizeClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// CallsTotal returns the lifetime count of wire RPCs (including retries).
// Exposed for tests + diagnostic readouts.
func (c *IAMAuthorizeClient) CallsTotal() int64 { return c.callsTotal.Load() }

// retryable returns true for transient gRPC codes that warrant a single
// retry. We deliberately exclude `Aborted` (typically a CAS conflict —
// retrying would just amplify the contention).
func retryable(code codes.Code) bool {
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

// buildContextStruct converts a Go context map into a *structpb.Struct.
// Returns nil when the map is empty.
func buildContextStruct(m map[string]any) (*structpb.Struct, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return structpb.NewStruct(coerceToProtoVals(m))
}

// coerceToProtoVals normalises Go types that structpb cannot directly
// encode (e.g. int64 → float64 because structpb only knows number/string/
// bool/list/struct/null).
func coerceToProtoVals(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = coerceProtoVal(v)
	}
	return out
}

// coerceProtoVal is the per-value variant of coerceToProtoVals; recurses
// into slices and maps.
func coerceProtoVal(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case uint:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case time.Time:
		return x.UTC().Truncate(time.Second).Unix()
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = coerceProtoVal(e)
		}
		return out
	case map[string]any:
		return coerceToProtoVals(x)
	default:
		return v
	}
}

// toResult converts proto response → caller-facing struct.
func toResult(resp *iamv1.AuthorizeCheckResponse) AuthorizeCheckResult {
	if resp == nil {
		return AuthorizeCheckResult{}
	}
	r := AuthorizeCheckResult{
		Allowed:              resp.GetAllowed(),
		AuthorizationModelID: resp.GetAuthorizationModelId(),
		DenyReasons:          append([]string(nil), resp.GetDenyReasons()...),
	}
	if ts := resp.GetCheckedAt(); ts != nil {
		r.CheckedAt = ts.AsTime()
	} else {
		r.CheckedAt = timestamppb.Now().AsTime()
	}
	return r
}

// truncateStr clamps a string to maxLen runes safely.
func truncateStr(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	// Truncate on a rune boundary so the result is still valid UTF-8.
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return strings.Clone(string(r[:maxLen]))
}
