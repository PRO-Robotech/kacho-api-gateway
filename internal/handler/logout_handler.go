// Package handler — HTTP handlers owned by api-gateway directly (not proxied
// to a backend). KAC-127 Phase 2 introduces the OAuth2 logout endpoint and
// (in this package) supporting back-channel logout propagation utilities.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

// SessionRevocationsClient — minimal port the logout handler needs to push
// revocations into kacho-iam. Implemented by an adapter around the generated
// gRPC stub `InternalSessionRevocationsServiceClient.Revoke`. Declared here
// so the handler is unit-testable without spinning up a gRPC server.
//
// The adapter discards the Operation envelope returned by the gRPC stub —
// the logout handler does not poll for completion (Revoke writes
// session_revocations row in the same TX as Operation insert, so by the time
// Revoke returns, downstream pods receiving LISTEN/NOTIFY will already
// invalidate the token).
type SessionRevocationsClient interface {
	Revoke(ctx context.Context, in *iamv1.RevokeRequest) error
}

// LogoutHandler — POST /oauth/logout
//
//	1. Parse access_token from `Authorization: Bearer|DPoP <token>` OR form-encoded
//	   `token` parameter (RFC 7009 §2.1).
//	2. Call kacho-iam `InternalSessionRevocationsService.Revoke` with
//	   revoke_all_user_tokens=false (single jti) or true (full force).
//	3. Call Hydra admin `DELETE /admin/oauth2/auth/sessions/login?subject=...`
//	   to invalidate the upstream SSO session — Hydra will then fan out
//	   back-channel logout notifications to all registered SPs (RFC 8254).
//	4. Clear client cookies (kacho_session, ory_kratos_session).
//	5. Respond `200 {}`.
//
// All Hydra/IAM calls are best-effort relative to clearing the user cookie —
// the user MUST see a successful logout from their side even if Hydra is
// momentarily unreachable. Failures are logged + included in the response
// `errors` array for debugging but do not surface as HTTP 5xx (that would
// leave the client uncertain whether to retry).
type LogoutHandler struct {
	logger          *slog.Logger
	revocations     SessionRevocationsClient
	hydraAdminURL   string
	httpClient      *http.Client
	hookSharedToken string
}

// LogoutHandlerConfig — DI bag.
type LogoutHandlerConfig struct {
	Logger          *slog.Logger
	Revocations     SessionRevocationsClient // optional — nil disables revocation
	HydraAdminURL   string                   // base URL of Hydra admin API; empty disables session-kill
	HTTPClient      *http.Client
	HookSharedToken string // bearer for Hydra admin endpoint (if Hydra requires)
}

// NewLogoutHandler constructs the handler. Logger is required (we never want
// silent failures on a security-critical path).
func NewLogoutHandler(cfg LogoutHandlerConfig) (*LogoutHandler, error) {
	if cfg.Logger == nil {
		return nil, errors.New("logout handler: logger is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &LogoutHandler{
		logger:          cfg.Logger,
		revocations:     cfg.Revocations,
		hydraAdminURL:   strings.TrimRight(cfg.HydraAdminURL, "/"),
		httpClient:      hc,
		hookSharedToken: cfg.HookSharedToken,
	}, nil
}

// ServeHTTP implements net/http.Handler.
func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
		return
	}

	// 1. Extract token (header OR form param `token`).
	rawToken := extractAccessToken(r)
	// Form parse — RFC 7009 allows `token=...` body.
	_ = r.ParseForm()
	if rawToken == "" {
		rawToken = strings.TrimSpace(r.Form.Get("token"))
	}

	// 2. Extract optional subject (e.g. UI passes it to bypass introspection).
	subject := strings.TrimSpace(r.Form.Get("subject"))
	jti := strings.TrimSpace(r.Form.Get("token_jti"))
	revokeAll := r.Form.Get("revoke_all") == "true"

	// 3. Try to call revocations. Errors are collected, not fatal.
	var revocErrs []string
	if h.revocations != nil && (jti != "" || subject != "") {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		req := &iamv1.RevokeRequest{
			TokenJti:            jti,
			UserId:              subject,
			Reason:              "user-logout",
			RevokeAllUserTokens: revokeAll,
			TtlExpiresAt:        timestamppb.New(time.Now().Add(30 * 24 * time.Hour)),
		}
		if err := h.revocations.Revoke(ctx, req); err != nil {
			h.logger.Warn("logout: revocations.Revoke failed", "err", err, "subject", subject)
			revocErrs = append(revocErrs, fmt.Sprintf("revocations: %v", err))
		}
		cancel()
	}

	// 4. Best-effort Hydra session kill.
	if h.hydraAdminURL != "" && subject != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		if err := h.killHydraSession(ctx, subject); err != nil {
			h.logger.Warn("logout: hydra admin session-kill failed", "err", err, "subject", subject)
			revocErrs = append(revocErrs, fmt.Sprintf("hydra: %v", err))
		}
		cancel()
	}

	// 5. Clear cookies — both legacy kacho_session and Ory Kratos.
	for _, c := range []string{"kacho_session", "ory_kratos_session"} {
		http.SetCookie(w, &http.Cookie{
			Name:     c,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	out := map[string]any{"ok": true}
	if len(revocErrs) > 0 {
		// 207-style multi-status; we keep 200 to not block the user.
		out["warnings"] = revocErrs
	}
	if rawToken == "" {
		out["note"] = "no access_token presented; cookies cleared"
	}
	writeJSON(w, http.StatusOK, out)
}

// killHydraSession invokes `DELETE /admin/oauth2/auth/sessions/login?subject={sub}`.
//
// Hydra returns 204 on success or 404 if no session existed — both are
// non-fatal from the logout's perspective.
func (h *LogoutHandler) killHydraSession(ctx context.Context, subject string) error {
	u, err := url.Parse(h.hydraAdminURL + "/admin/oauth2/auth/sessions/login")
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()
	q.Set("subject", subject)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build req: %w", err)
	}
	if h.hookSharedToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.hookSharedToken)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hydra delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("hydra unexpected status=%d body=%q", resp.StatusCode, string(body))
}

// extractAccessToken pulls the bearer/DPoP token from the Authorization header.
// Returns "" if absent.
func extractAccessToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	for _, scheme := range []string{"Bearer ", "DPoP ", "bearer ", "dpop "} {
		if strings.HasPrefix(auth, scheme) {
			return strings.TrimSpace(auth[len(scheme):])
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
