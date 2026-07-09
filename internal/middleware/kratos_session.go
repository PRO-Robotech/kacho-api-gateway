// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package middleware — Kratos session resolution.
//
// SPA-пользователи аутентифицируются через cookie `ory_kratos_session` (не JWT).
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
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/lrucache"
)

// KratosWhoamiResult — извлеченные поля Kratos session.
type KratosWhoamiResult struct {
	IdentityID  string // session.identity.id — стабильный UUID
	Email       string // session.identity.traits.email
	DisplayName string // составное имя из traits.name.{first,last} либо email
	Active      bool   // session.active — false → ignore
}

// KratosClient — minimal HTTP-обертка для GET /sessions/whoami.
type KratosClient struct {
	BaseURL string // например http://kacho-umbrella-kratos-public.kacho.svc.cluster.local:80
	HTTP    *http.Client

	// cache — единый bounded TTL+LRU примитив (internal/lrucache), тот же, что у
	// decision/introspection/replay-кэшей: eviction/cap-логика реализована и
	// протестирована ровно один раз. Ключ — полный Cookie-header (контролируется
	// клиентом), поэтому cap примитива обязателен: одного TTL-вытеснения мало —
	// поток уникальных cookie в пределах TTL рос бы неограниченно. Positive и
	// negative записи различаются полем kratosCacheEntry.active и живут в одном
	// кэше с разными per-entry TTL (PutWithTTL).
	cache       *lrucache.Cache[string, kratosCacheEntry]
	positiveTTL time.Duration
	negativeTTL time.Duration
}

// kratosCacheMaxEntries — потолок числа записей кэша (см. cache выше).
const kratosCacheMaxEntries = 4096

type kratosCacheEntry struct {
	res    KratosWhoamiResult
	active bool // true → positive (session valid); false → negative (fail-closed)
}

// NewKratosClient — endpoint обычно cluster-internal Kratos public service.
func NewKratosClient(baseURL string) *KratosClient {
	return &KratosClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		HTTP:        &http.Client{Timeout: 5 * time.Second},
		cache:       lrucache.New[string, kratosCacheEntry](kratosCacheMaxEntries, 30*time.Second, nil),
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

	// Cache check — TTL/eviction/cap enforced inside the primitive; a negative
	// entry carries active=false and short-circuits to the fail-closed result
	// without a Kratos round-trip.
	if e, ok := c.cache.Get(cookieHeader); ok {
		if e.active {
			return e.res
		}
		return KratosWhoamiResult{}
	}

	res := c.fetch(ctx, cookieHeader)

	if res.Active {
		c.cache.PutWithTTL(cookieHeader, kratosCacheEntry{res: res, active: true}, c.positiveTTL)
	} else {
		c.cache.PutWithTTL(cookieHeader, kratosCacheEntry{active: false}, c.negativeTTL)
	}
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return KratosWhoamiResult{}
	}
	// Cap the body to 1 MiB before decoding — over the plaintext cluster-internal
	// hop a compromised/MITM'd Kratos peer could otherwise return an oversized
	// JSON scalar that json.Decode materialises whole in the heap on this hot
	// per-request path. Mirrors the sibling introspection/JWKS readers.
	var s kratosSession
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s); err != nil {
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
