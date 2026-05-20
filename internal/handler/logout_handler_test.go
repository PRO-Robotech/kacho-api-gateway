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

func TestLogout_RevokesWhenSubjectPresent(t *testing.T) {
	rev := &recordingRevocations{}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:      newLogger(),
		Revocations: rev,
	})
	form := url.Values{
		"subject":    {"usr_alice_acc_a1b2"},
		"token_jti":  {"01HZQ8M5J7QTAEXAMPLEUUIDV7"},
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
	assert.Equal(t, "usr_alice_acc_a1b2", rev.last.UserId)
	assert.Equal(t, "01HZQ8M5J7QTAEXAMPLEUUIDV7", rev.last.TokenJti)
	assert.Equal(t, "user-logout", rev.last.Reason)
	assert.True(t, rev.last.RevokeAllUserTokens)
}

func TestLogout_RevocationFailure_DoesNotFailRequest(t *testing.T) {
	rev := &recordingRevocations{err: errors.New("iam unreachable")}
	h, _ := handler.NewLogoutHandler(handler.LogoutHandlerConfig{
		Logger:      newLogger(),
		Revocations: rev,
	})
	form := url.Values{
		"subject":   {"usr"},
		"token_jti": {"jti"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	})
	form := url.Values{"subject": {"usr_a"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	})
	form := url.Values{"subject": {"usr_x"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
