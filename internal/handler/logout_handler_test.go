// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
)

type recordingRevocations struct {
	calls atomic.Int32
	last  *iamv1.RevokeRequest
	err   error
}

func (r *recordingRevocations) Revoke(_ context.Context, in *iamv1.RevokeRequest) error {
	r.calls.Add(1)
	r.last = in
	return r.err
}

// fakeVerifier stands in for the gateway JWKS access-token verifier. It returns
// a fixed caller identity, or an error to simulate an invalid/expired token.
type fakeVerifier struct {
	caller *handler.VerifiedCaller
	err    error
}

func (f *fakeVerifier) Verify(_ context.Context, _ string) (*handler.VerifiedCaller, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.caller, nil
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestLogout_POSTOnly(t *testing.T) {
	h, err := handler.NewLogoutHandler(handler.LogoutHandlerConfig{Logger: newLogger()})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/oauth/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestLogout_ClearsCookies(t *testing.T) {
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{Logger: newLogger()})
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	var saw_kacho, saw_kratos bool
	for _, c := range cookies {
		if c.Name == "kacho_session" {
			saw_kacho = true
			assert.True(t, c.MaxAge < 0)
		}
		if c.Name == "ory_kratos_session" {
			saw_kratos = true
			assert.True(t, c.MaxAge < 0)
		}
	}
	assert.True(t, saw_kacho)
	assert.True(t, saw_kratos)
}

// TestLogout_RevokesOwnSubjectFromToken_IgnoresClientSubject — with a validated
// token the handler revokes the caller's own session, derived from the token's
// sub/jti, and IGNORES an attacker-supplied `subject`/`token_jti` in the body.
func TestLogout_RevokesOwnSubjectFromToken_IgnoresClientSubject(t *testing.T) {
	rev := &recordingRevocations{}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:      newLogger(),
		Revocations: rev,
		Verifier: &fakeVerifier{caller: &handler.VerifiedCaller{
			Subject: "usr_alice_acc_a1b2",
			JTI:     "01HZQ8M5J7QTAEXAMPLEUUIDV7",
		}},
	})
	form := url.Values{
		// Attacker-supplied targets — must be ignored in favour of the token.
		"subject":    {"usr_victim_acc_zzzz"},
		"token_jti":  {"attacker-chosen-jti"},
		"revoke_all": {"true"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "DPoP some-access-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(1), rev.calls.Load())
	require.NotNil(t, rev.last)
	assert.Equal(t, "usr_alice_acc_a1b2", rev.last.UserId, "subject must come from validated token, not request body")
	assert.Equal(t, "01HZQ8M5J7QTAEXAMPLEUUIDV7", rev.last.TokenJti, "jti must come from validated token, not request body")
	assert.Equal(t, "user-logout", rev.last.Reason)
	assert.True(t, rev.last.RevokeAllUserTokens)
}

// TestLogout_InvalidToken_401 — a presented token that fails verification is a
// hard 401, and no revocation is attempted (no silent fallthrough to the body).
func TestLogout_InvalidToken_401(t *testing.T) {
	rev := &recordingRevocations{}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:      newLogger(),
		Revocations: rev,
		Verifier:    &fakeVerifier{err: errors.New("bad signature")},
	})
	form := url.Values{"subject": {"usr_victim"}, "revoke_all": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer garbage.token.sig")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, int32(0), rev.calls.Load())
}

func TestLogout_RevocationFailure_DoesNotFailRequest(t *testing.T) {
	rev := &recordingRevocations{err: errors.New("iam unreachable")}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:      newLogger(),
		Revocations: rev,
		Verifier:    &fakeVerifier{caller: &handler.VerifiedCaller{Subject: "usr", JTI: "jti"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid.access.token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Still 200 — best-effort revocation; user must see successful logout.
	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(t, string(body), "warnings")
}

func TestLogout_HydraSessionKill(t *testing.T) {
	var hydraCalls atomic.Int32
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hydraCalls.Add(1)
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Contains(t, r.URL.Path, "/admin/oauth2/auth/sessions/login")
		assert.Equal(t, "usr_a", r.URL.Query().Get("subject"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hydra.Close()

	rev := &recordingRevocations{}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:        newLogger(),
		Revocations:   rev,
		HydraAdminURL: hydra.URL,
		Verifier:      &fakeVerifier{caller: &handler.VerifiedCaller{Subject: "usr_a"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid.access.token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(1), hydraCalls.Load())
}

func TestLogout_HydraReturns404_NoWarn(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer hydra.Close()
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:        newLogger(),
		HydraAdminURL: hydra.URL,
		Verifier:      &fakeVerifier{caller: &handler.VerifiedCaller{Subject: "usr_x"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid.access.token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	assert.NotContains(t, string(body), "warnings", "404 from Hydra is non-fatal — no warning should surface")
}

func TestLogout_NoSubject_NoRevocationCall(t *testing.T) {
	rev := &recordingRevocations{}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:      newLogger(),
		Revocations: rev,
	})
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(0), rev.calls.Load())
}

func TestLogout_Construction_RequiresLogger(t *testing.T) {
	_, err := handler.NewLogoutHandler(handler.LogoutHandlerConfig{})
	require.Error(t, err)
}

// TestLogout_UnauthenticatedRevokeRejected — an unauthenticated caller supplying
// an arbitrary victim `subject` must NOT be able to revoke that user's sessions
// or kill their SSO session. Without a validated access token the endpoint must
// refuse the server-side revocation (401) and never touch iam/Hydra.
func TestLogout_UnauthenticatedRevokeRejected(t *testing.T) {
	rev := &recordingRevocations{}
	var hydraCalls atomic.Int32
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hydraCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hydra.Close()

	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:        newLogger(),
		Revocations:   rev,
		HydraAdminURL: hydra.URL,
		// No Verifier wired ⇒ no credential can be authenticated ⇒ fail closed.
	})
	form := url.Values{
		"subject":    {"usr_victim_acc_zzzz"},
		"revoke_all": {"true"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "unauth revoke of arbitrary subject must be 401")
	assert.Equal(t, int32(0), rev.calls.Load(), "must not revoke another user's tokens without auth")
	assert.Equal(t, int32(0), hydraCalls.Load(), "must not kill another user's SSO session without auth")
}
