// Package middleware — OIDC HTTP handlers для UI auth-flow (KAC-107 closeout, KAC-109 DoD #1).
//
// Routes:
//
//	GET  /iam/v1/auth/login    → 302 на Zitadel /oauth/v2/authorize (с state-cookie)
//	GET  /iam/v1/auth/callback → exchange code на access_token + создаёт sessionCookie
//	GET  /iam/v1/auth/me       → возвращает текущего User (или 401 если cookie нет)
//	POST /iam/v1/auth/logout   → очищает sessionCookie
//
// Минимальная реализация для UI smoke. Полноценный OIDC RP (PKCE, refresh-tokens,
// JWKS-валидация JWT, full Subject lookup через InternalIamService) — KAC-107 v2.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCConfig — параметры из env / config.yaml.
type OIDCConfig struct {
	// Issuer — server-side endpoint для token exchange + userinfo.
	// Обычно cluster-internal (например http://kacho-umbrella-zitadel:8080).
	Issuer string
	// ExternalIssuer — endpoint используется в browser redirect.
	// Если пустой — Issuer. На k8s обычно: http://<public-host>.
	// /oauth/v2/* paths проксируются UI nginx до Zitadel Service.
	ExternalIssuer string
	ClientID       string // OIDC-client из Zitadel admin
	RedirectURI    string // напр. http://5.35.93.58/iam/v1/auth/callback
	// ClientSecret — confidential client; для PKCE/public — оставим пустым.
	ClientSecret string
	// Disabled — если true, login возвращает 503 (Zitadel ещё не настроен на стенде).
	Disabled bool
}

// externalIssuer возвращает endpoint для browser-redirect (или Issuer как fallback).
func (c OIDCConfig) externalIssuer() string {
	if c.ExternalIssuer != "" {
		return c.ExternalIssuer
	}
	return c.Issuer
}

const (
	stateCookieName   = "kacho_oauth_state"
	sessionCookieName = "kacho_session"
	stateCookieMaxAge = 600 // 10 минут на signin flow
	sessionMaxAge     = 3600
)

// AdminChecker — KAC-123: port для проверки system-admin (Keto kacho_system:root#admin).
type AdminChecker interface {
	IsSystemAdmin(ctx context.Context, subject string) (bool, error)
}

// OIDCHandler регистрирует 4 endpoint'а в http.ServeMux.
type OIDCHandler struct {
	cfg    OIDCConfig
	logger *slog.Logger
	// http client с timeout — для exchange и userinfo
	http *http.Client
	// kratos — KAC-116: если выставлен, /me читает Kratos session вместо Zitadel userinfo.
	kratos        *KratosClient
	subjectLookup SubjectLookuper // для резолва identity.id → User/SA из kacho-iam
	adminCheck    AdminChecker    // KAC-123: optional admin-tuple lookup
}

func NewOIDCHandler(cfg OIDCConfig, logger *slog.Logger) *OIDCHandler {
	return &OIDCHandler{
		cfg:    cfg,
		logger: logger,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// WithKratos подключает Kratos session client + SubjectLookup для /me.
func (h *OIDCHandler) WithKratos(c *KratosClient, lookup SubjectLookuper) *OIDCHandler {
	h.kratos = c
	h.subjectLookup = lookup
	return h
}

// WithAdminChecker — KAC-123: Keto-based system-admin tuple lookup для /me.
// Возвращает permissions:["*","admin"] если subject имеет kacho_system:root#admin.
func (h *OIDCHandler) WithAdminChecker(a AdminChecker) *OIDCHandler {
	h.adminCheck = a
	return h
}

// Register крепит handlers на http.ServeMux. Должен вызываться ДО общего `/`.
func (h *OIDCHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/iam/v1/auth/login", h.Login)
	mux.HandleFunc("/iam/v1/auth/callback", h.Callback)
	mux.HandleFunc("/iam/v1/auth/me", h.Me)
	mux.HandleFunc("/iam/v1/auth/logout", h.Logout)
}

// Login → 302 на Zitadel.
func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Disabled || h.cfg.Issuer == "" {
		http.Error(w, `{"error":"oidc not configured","detail":"set KACHO_API_GATEWAY_OIDC_ISSUER"}`, http.StatusServiceUnavailable)
		return
	}
	// ClientID — динамически читается из env на каждом request: bootstrap-Job
	// заполняет k8s Secret post-install, pod-restart может ещё не случиться, но
	// kubelet projection делает обновление файла, env-var остаётся empty до restart.
	// Fallback: если ClientID пустой — возвращаем 503 с конкретной причиной.
	if h.cfg.ClientID == "" {
		http.Error(w, `{"error":"oidc client_id not yet bootstrapped","detail":"zitadel-oidc-bootstrap Job не завершился. Проверьте: kubectl -n kacho get secret kacho-iam-oidc-client; rollout restart api-gateway после Job complete."}`, http.StatusServiceUnavailable)
		return
	}
	state, err := randomState()
	if err != nil {
		http.Error(w, `{"error":"failed to generate state"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   stateCookieMaxAge,
	})
	u, err := url.Parse(strings.TrimRight(h.cfg.externalIssuer(), "/") + "/oauth/v2/authorize")
	if err != nil {
		http.Error(w, `{"error":"bad issuer"}`, http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("client_id", h.cfg.ClientID)
	q.Set("redirect_uri", h.cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	h.logger.Info("oidc login redirect", "to", u.String())
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Callback ?code=&state= → exchange + set session.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, `{"error":"missing code or state"}`, http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(stateCookieName)
	if err != nil || c.Value != state {
		http.Error(w, `{"error":"state mismatch","detail":"start signin from /iam/v1/auth/login"}`, http.StatusBadRequest)
		return
	}
	// Exchange code for tokens
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", h.cfg.RedirectURI)
	form.Set("client_id", h.cfg.ClientID)
	if h.cfg.ClientSecret != "" {
		form.Set("client_secret", h.cfg.ClientSecret)
	}
	tokenURL := strings.TrimRight(h.cfg.Issuer, "/") + "/oauth/v2/token"
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.http.Do(req)
	if err != nil {
		h.logger.Error("oidc token exchange failed", "err", err)
		http.Error(w, `{"error":"token exchange failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		h.logger.Error("oidc token exchange non-200", "status", resp.StatusCode, "body", string(body))
		http.Error(w, `{"error":"token exchange non-200"}`, http.StatusBadGateway)
		return
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		http.Error(w, `{"error":"bad token response"}`, http.StatusBadGateway)
		return
	}
	// Минимальный session-cookie — храним access_token (NB: в проде нужно session_id +
	// server-side storage; для MVP-stage E2 — ok).
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok.AccessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   sessionMaxAge,
	})
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/", MaxAge: -1})
	// Redirect на UI root (или на ?next=)
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// Me — UI hook /me. Возвращает либо `{"user":null}` если не залогинен,
// либо `{"user":{...}}` с userinfo из Kratos (preferred, KAC-116) или Zitadel.
func (h *OIDCHandler) Me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// KAC-116: Kratos session-first path (Ory stack).
	if h.kratos != nil {
		cookieHdr := r.Header.Get("Cookie")
		if strings.Contains(cookieHdr, "ory_kratos_session") {
			res := h.kratos.Whoami(r.Context(), cookieHdr)
			if res.Active && res.IdentityID != "" {
				userObj := map[string]any{
					"id":          res.IdentityID,
					"email":       res.Email,
					"displayName": res.DisplayName,
					"subjectType": "user",
					"permissions": []string{},
				}
				// Если есть SubjectLookup — резолвим в Kachō User id (mirror).
				// KAC-116: если lookuper поддерживает lazy-upsert — используем (new Kratos user → Upsert).
				if h.subjectLookup != nil {
					var subj Subject
					var lerr error
					if kl, ok := h.subjectLookup.(KratosSubjectLookuper); ok {
						subj, lerr = kl.LookupOrUpsertFromKratos(r.Context(), res.IdentityID, res.Email, res.DisplayName)
					} else {
						subj, lerr = h.subjectLookup.LookupByExternalID(r.Context(), res.IdentityID)
					}
					if lerr == nil {
						userObj["id"] = subj.ID
						userObj["subjectType"] = subj.Type
						if subj.DisplayName != "" {
							userObj["displayName"] = subj.DisplayName
						}
						// KAC-123: проверка system-admin через AdminChecker (Keto LookupSubjects).
						// Если user имеет kacho_system:root#admin tuple → permissions = ["*","admin"].
						// UI ServiceSidebar показывает "Администрирование" tab по hasPermission("admin").
						if h.adminCheck != nil {
							ok, _ := h.adminCheck.IsSystemAdmin(r.Context(), subj.Type+":"+subj.ID)
							if ok {
								userObj["permissions"] = []string{"*", "admin"}
							}
						}
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"user": userObj})
				return
			}
		}
	}

	// KAC-127: Zitadel-cookie fallback удалён — auth-tier перешёл на Kratos
	// (KAC-116). Если выше не нашли Kratos-сессию, возвращаем anonymous.
	_, _ = w.Write([]byte(`{"user":null}`))
}

// Logout — clear cookies + 200.
func (h *OIDCHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/", MaxAge: -1})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
