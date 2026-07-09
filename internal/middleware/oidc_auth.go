// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package middleware — OIDC HTTP handlers для UI auth-flow.
//
// Routes:
//
//	GET  /iam/v1/auth/login    → 302 на Zitadel /oauth/v2/authorize (с state-cookie)
//	GET  /iam/v1/auth/callback → exchange code на access_token + создает sessionCookie
//	GET  /iam/v1/auth/me       → возвращает текущего User (или 401 если cookie нет)
//	POST /iam/v1/auth/logout   → очищает sessionCookie
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	RedirectURI    string // напр. http://<host>/iam/v1/auth/callback
	// ClientSecret — confidential client; для public-client оставляем пустым. В
	// обоих случаях code-exchange защищён PKCE (RFC 7636, S256) — см. Login/Callback.
	ClientSecret string
	// Disabled — если true, login возвращает 503 (Zitadel еще не настроен на стенде).
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
	pkceCookieName    = "kacho_oauth_pkce" // RFC 7636 code_verifier (HttpOnly, browser-bound)
	sessionCookieName = "kacho_session"
	stateCookieMaxAge = 600 // 10 минут на signin flow
	sessionMaxAge     = 3600
)

// AdminChecker — port для проверки system-admin (Keto kacho_system:root#admin).
type AdminChecker interface {
	IsSystemAdmin(ctx context.Context, subject string) (bool, error)
}

// OIDCHandler регистрирует 4 endpoint'а в http.ServeMux.
type OIDCHandler struct {
	cfg    OIDCConfig
	logger *slog.Logger
	// http client с timeout — для exchange и userinfo
	http *http.Client
	// kratos — если выставлен, /me читает Kratos session вместо Zitadel userinfo.
	kratos        *KratosClient
	subjectLookup SubjectLookuper // для резолва identity.id → User/SA из kacho-iam
	adminCheck    AdminChecker    // optional admin-tuple lookup
}

func NewOIDCHandler(cfg OIDCConfig, logger *slog.Logger) *OIDCHandler {
	return &OIDCHandler{
		cfg:    cfg,
		logger: logger,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// WithKratos — подключает Kratos session client + SubjectLookup для /me.
func (h *OIDCHandler) WithKratos(c *KratosClient, lookup SubjectLookuper) *OIDCHandler {
	h.kratos = c
	h.subjectLookup = lookup
	return h
}

// WithAdminChecker — Keto-based system-admin tuple lookup для /me.
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
	// заполняет k8s Secret post-install, pod-restart может еще не случиться, но
	// kubelet projection делает обновление файла, env-var остается empty до restart.
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
	// PKCE (RFC 7636): generate a per-request code_verifier and its S256
	// code_challenge. The verifier is stored in an HttpOnly, browser-bound cookie
	// (unreadable to JS) and the challenge travels in the front-channel authorize
	// redirect; an attacker who intercepts the authorization code cannot redeem it
	// without the verifier cookie. Emitted unconditionally — harmless for a
	// confidential client (which also sends client_secret), essential for the
	// public-client case (empty ClientSecret) where it is the ONLY code-binding.
	verifier, err := randomState()
	if err != nil {
		http.Error(w, `{"error":"failed to generate pkce verifier"}`, http.StatusInternalServerError)
		return
	}
	challengeSum := sha256.Sum256([]byte(verifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	secure := requestIsHTTPS(r)
	// #nosec G124 -- Secure is set conditionally via requestIsHTTPS(r) (gosec's
	// literal-only heuristic cannot evaluate it); HttpOnly+SameSite always present.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   stateCookieMaxAge,
	})
	// #nosec G124 -- Secure mirrors requestIsHTTPS(r); HttpOnly+SameSite always present.
	http.SetCookie(w, &http.Cookie{
		Name:     pkceCookieName,
		Value:    verifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
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
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
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
	// PKCE (RFC 7636): return the code_verifier stored at Login so the IdP can
	// verify it against the code_challenge it recorded with the authorization
	// code. Absence (cookie dropped/expired) fails the exchange closed at the IdP
	// — the code is not redeemable without the verifier, which is the point.
	if pk, perr := r.Cookie(pkceCookieName); perr == nil && pk.Value != "" {
		form.Set("code_verifier", pk.Value)
	}
	tokenURL := strings.TrimRight(h.cfg.Issuer, "/") + "/oauth/v2/token"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		// A malformed Issuer (invalid scheme/control char) makes url.Parse fail and
		// returns req==nil; guard here so the following Do does not deref nil and
		// panic (mirrors the sibling fetchHydra build-req check).
		h.logger.Error("oidc token exchange build request failed", "err", err)
		http.Error(w, `{"error":"token exchange failed"}`, http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.http.Do(req)
	if err != nil {
		h.logger.Error("oidc token exchange failed", "err", err)
		http.Error(w, `{"error":"token exchange failed"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		h.logger.Error("oidc token exchange non-200", "status", resp.StatusCode, "body", string(body))
		http.Error(w, `{"error":"token exchange non-200"}`, http.StatusBadGateway)
		return
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	// Cap the token-exchange body to 1 MiB before decoding — a compromised IdP
	// could otherwise force a multi-MB one-shot heap allocation. Mirrors the
	// sibling non-200 reader above and the introspection/JWKS readers.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		http.Error(w, `{"error":"bad token response"}`, http.StatusBadGateway)
		return
	}
	// Минимальный session-cookie — храним access_token (NB: в проде нужно session_id +
	// server-side storage).
	// #nosec G124 -- Secure is set conditionally via requestIsHTTPS(r) (gosec's
	// literal-only heuristic cannot evaluate it); HttpOnly+SameSite always present.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   sessionMaxAge,
	})
	// Clear state + PKCE cookies (mirror the set-form security attributes) —
	// single-use, must not linger past a completed exchange.
	clearCookie(w, stateCookieName, requestIsHTTPS(r))
	clearCookie(w, pkceCookieName, requestIsHTTPS(r))
	// Redirect на локальный путь. safeRelativePath отсекает open-redirect:
	// абсолютные и protocol-relative (`//host`) цели сворачиваются в "/".
	next := safeRelativePath(r.URL.Query().Get("next"))
	http.Redirect(w, r, next, http.StatusFound) // #nosec G710 -- next sanitised by safeRelativePath to a same-origin path
}

// Me — UI hook /me. Возвращает либо `{"user":null}` если не залогинен,
// либо `{"user":{...}}` с userinfo из Kratos (preferred) или Zitadel.
func (h *OIDCHandler) Me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Kratos session-first path (Ory stack).
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
				// Если lookuper поддерживает lazy-upsert — используем (new Kratos user → Upsert).
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
						// Проверка system-admin через AdminChecker (Keto LookupSubjects).
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

	// Zitadel-cookie fallback отсутствует — auth-tier работает через Kratos.
	// Если выше не нашли Kratos-сессию, возвращаем anonymous.
	_, _ = w.Write([]byte(`{"user":null}`))
}

// Logout — clear cookies + 200.
func (h *OIDCHandler) Logout(w http.ResponseWriter, r *http.Request) {
	secure := requestIsHTTPS(r)
	clearCookie(w, sessionCookieName, secure)
	clearCookie(w, stateCookieName, secure)
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

// clearCookie expires a cookie carrying the same security attributes as its
// set form (HttpOnly + SameSite + Secure-when-HTTPS), so a browser drops it
// rather than retaining a half-attributed leftover.
func clearCookie(w http.ResponseWriter, name string, secure bool) {
	// #nosec G124 -- Secure is the caller's requestIsHTTPS() result (gosec's
	// literal-only heuristic cannot evaluate it); HttpOnly+SameSite always present.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// requestIsHTTPS reports whether the request reached the gateway over TLS —
// either directly (r.TLS set) or via a TLS-terminating L7 ingress that forwards
// X-Forwarded-Proto=https. Drives the cookie Secure attribute so session/state
// cookies are not emitted Secure on the plain cluster-internal listener (which
// would silently drop them) yet ARE Secure on the advertised HTTPS edge.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// safeRelativePath constrains a post-login redirect target to a same-origin
// local path. It returns the input only when it is a single-slash-rooted path
// ("/dashboard"); everything else collapses to "/": absolute URLs,
// protocol-relative ("//host"), backslash-tricked targets ("/\\host"), and any
// value carrying an ASCII control byte (TAB/CR/LF/NUL) — browsers strip control
// chars before parsing, which can turn "/\t/host" into a protocol-relative
// "//host". This closes the open-redirect class on the OAuth callback's `next`.
func safeRelativePath(next string) string {
	if next == "" || next[0] != '/' {
		return "/"
	}
	// Reject "//host" and "/\host" — browsers resolve both as absolute.
	if len(next) > 1 && (next[1] == '/' || next[1] == '\\') {
		return "/"
	}
	// Reject any control byte (incl. TAB/CR/LF/NUL) or backslash anywhere: a
	// stripped control char can reopen the protocol-relative bypass, and a
	// backslash may be normalised to "/".
	for i := 0; i < len(next); i++ {
		if next[i] < 0x20 || next[i] == 0x7f || next[i] == '\\' {
			return "/"
		}
	}
	return next
}
