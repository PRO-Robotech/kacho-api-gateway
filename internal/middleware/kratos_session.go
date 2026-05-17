// Package middleware — Kratos session resolution.
//
// KAC-116 (Ory follow-up KAC-115): после миграции с Zitadel на Kratos,
// SPA пользователи аутентифицируются через cookie `ory_kratos_session` (не JWT).
// Этот helper обращается в Kratos /sessions/whoami, парсит identity.id +
// traits.email, и возвращает их как (subject_id, display_name).
//
// Subject_id используется как `external_id` для существующего SubjectLookup
// (User mirror в kacho-iam UPSERT'ится из Kratos identity по identity.id).
//
// Кэширование: TTL=30s positive, TTL=5s negative (см. corelib/authz/cache pattern).
// Без кэша каждый REST-запрос делал бы whoami call — недопустимо для hot-path.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// KratosWhoamiResult — извлечённые поля Kratos session.
type KratosWhoamiResult struct {
	IdentityID  string // session.identity.id — стабильный UUID
	Email       string // session.identity.traits.email
	DisplayName string // составное имя из traits.name.{first,last} либо email
	Active      bool   // session.active — false → ignore
}

// KratosClient — minimal HTTP-обёртка для GET /sessions/whoami.
type KratosClient struct {
	BaseURL string // например http://kacho-umbrella-kratos-public.kacho.svc.cluster.local:80
	HTTP    *http.Client

	mu          sync.RWMutex
	posCache    map[string]kratosCacheEntry // cookie-value → result
	negCache    map[string]time.Time        // cookie-value → expiry
	positiveTTL time.Duration
	negativeTTL time.Duration
}

type kratosCacheEntry struct {
	res    KratosWhoamiResult
	expiry time.Time
}

// NewKratosClient — endpoint обычно cluster-internal Kratos public service.
func NewKratosClient(baseURL string) *KratosClient {
	return &KratosClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		HTTP:        &http.Client{Timeout: 5 * time.Second},
		posCache:    make(map[string]kratosCacheEntry, 64),
		negCache:    make(map[string]time.Time, 64),
		positiveTTL: 30 * time.Second,
		negativeTTL: 5 * time.Second,
	}
}

// Whoami извлекает identity из Kratos session по cookie-string (целиком Cookie-header).
// Возвращает Active=false при любой неудаче (логированной caller'ом).
func (c *KratosClient) Whoami(ctx context.Context, cookieHeader string) KratosWhoamiResult {
	if cookieHeader == "" || c.BaseURL == "" {
		return KratosWhoamiResult{}
	}

	now := time.Now()

	// Cache check (positive).
	c.mu.RLock()
	if e, ok := c.posCache[cookieHeader]; ok && now.Before(e.expiry) {
		c.mu.RUnlock()
		return e.res
	}
	if exp, ok := c.negCache[cookieHeader]; ok && now.Before(exp) {
		c.mu.RUnlock()
		return KratosWhoamiResult{}
	}
	c.mu.RUnlock()

	res := c.fetch(ctx, cookieHeader)

	c.mu.Lock()
	if res.Active {
		c.posCache[cookieHeader] = kratosCacheEntry{res: res, expiry: now.Add(c.positiveTTL)}
	} else {
		c.negCache[cookieHeader] = now.Add(c.negativeTTL)
	}
	// Cleanup стайл (амортизируем O(1)) — выкидываем expired каждые ~256 записей.
	if len(c.posCache)+len(c.negCache) > 256 {
		c.evictLocked(now)
	}
	c.mu.Unlock()
	return res
}

func (c *KratosClient) fetch(ctx context.Context, cookieHeader string) KratosWhoamiResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/sessions/whoami", nil)
	if err != nil {
		return KratosWhoamiResult{}
	}
	req.Header.Set("Cookie", cookieHeader)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return KratosWhoamiResult{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return KratosWhoamiResult{}
	}
	var s kratosSession
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return KratosWhoamiResult{}
	}
	dn := s.Identity.Traits.Email
	first := strings.TrimSpace(s.Identity.Traits.Name.First)
	last := strings.TrimSpace(s.Identity.Traits.Name.Last)
	if first != "" || last != "" {
		dn = strings.TrimSpace(fmt.Sprintf("%s %s", first, last))
	}
	return KratosWhoamiResult{
		IdentityID:  s.Identity.ID,
		Email:       s.Identity.Traits.Email,
		DisplayName: dn,
		Active:      s.Active,
	}
}

func (c *KratosClient) evictLocked(now time.Time) {
	for k, e := range c.posCache {
		if now.After(e.expiry) {
			delete(c.posCache, k)
		}
	}
	for k, exp := range c.negCache {
		if now.After(exp) {
			delete(c.negCache, k)
		}
	}
}

// Kratos session JSON shape (минимальное подмножество).
type kratosSession struct {
	Active   bool           `json:"active"`
	Identity kratosIdentity `json:"identity"`
}

type kratosIdentity struct {
	ID     string       `json:"id"`
	Traits kratosTraits `json:"traits"`
}

type kratosTraits struct {
	Email string     `json:"email"`
	Name  kratosName `json:"name"`
}

type kratosName struct {
	First string `json:"first"`
	Last  string `json:"last"`
}
