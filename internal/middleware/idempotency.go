// Package middleware: HTTPIdempotency — HTTP middleware для Idempotency-Key.
//
// На каждом mutating-запросе (POST/PATCH/DELETE) если задан header
// `Idempotency-Key: <uuid>` — сохраняется ответ (status + body), и при
// повторном запросе с тем же ключом возвращается сохранённый ответ
// без вызова downstream.
//
// Реализация: in-memory store с TTL, периодический GC. Для текущей фазы
// (single api-gateway pod) этого достаточно. При horizontal scaling
// потребуется внешнее хранилище (Postgres / Redis).
//
// Соответствует YC API: тот же Idempotency-Key → тот же Operation.id.
package middleware

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"
)

// IdempotencyTTL — время жизни записи (24 часа в YC).
const IdempotencyTTL = 24 * time.Hour

// idempotencyEntry хранит сохранённый response.
type idempotencyEntry struct {
	statusCode int
	body       []byte
	headers    http.Header
	expiresAt  time.Time
}

// IdempotencyStore — in-memory store с TTL и GC.
type IdempotencyStore struct {
	mu      sync.Mutex
	entries map[string]idempotencyEntry
	ttl     time.Duration
}

// NewIdempotencyStore создаёт новый IdempotencyStore с фоновым GC.
// gc tick = ttl/24 (раз в час при ttl=24h).
func NewIdempotencyStore(ttl time.Duration) *IdempotencyStore {
	s := &IdempotencyStore{
		entries: make(map[string]idempotencyEntry),
		ttl:     ttl,
	}
	go s.gcLoop()
	return s
}

// gcLoop удаляет expired entries раз в ttl/24.
func (s *IdempotencyStore) gcLoop() {
	tick := s.ttl / 24
	if tick < time.Minute {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.entries {
			if now.After(v.expiresAt) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}

// get возвращает сохранённый entry или (zero, false) если ключа нет/expired.
func (s *IdempotencyStore) get(key string) (idempotencyEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return idempotencyEntry{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(s.entries, key)
		return idempotencyEntry{}, false
	}
	return e, true
}

// put сохраняет entry с TTL.
func (s *IdempotencyStore) put(key string, e idempotencyEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = e
}

// HTTPIdempotency — HTTP middleware: при наличии Idempotency-Key
// на mutating request — кэширует ответ или возвращает сохранённый.
//
// Применяется только к POST/PATCH/PUT/DELETE — read-only запросы (GET) пропускаются.
//
// Если ключ есть, но значения нет — выполняется downstream, ответ сохраняется.
// Если ключ есть и значение есть — отдаётся сохранённый response.
//
// Если downstream вернул не-2xx, ответ всё равно сохраняется (YC так делает —
// см. вопросы клиентам ретрая).
func HTTPIdempotency(store *IdempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// только для mutating
			if !isMutating(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get("Idempotency-Key")
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Lookup
			if e, ok := store.get(key); ok {
				for k, vs := range e.headers {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("X-Idempotent-Replayed", "true")
				w.WriteHeader(e.statusCode)
				_, _ = w.Write(e.body)
				return
			}
			// Wrap response writer to capture
			rec := &responseRecorder{ResponseWriter: w, body: &bytes.Buffer{}, statusCode: 200}
			next.ServeHTTP(rec, r)
			// Save the response (любой 2xx/4xx — кешируем; 5xx — НЕ кешируем для retry-safety).
			if rec.statusCode < 500 {
				headers := http.Header{}
				if ct := w.Header().Get("Content-Type"); ct != "" {
					headers.Set("Content-Type", ct)
				}
				store.put(key, idempotencyEntry{
					statusCode: rec.statusCode,
					body:       rec.body.Bytes(),
					headers:    headers,
					expiresAt:  time.Now().Add(store.ttl),
				})
			}
		})
	}
}

// isMutating — true если HTTP метод изменяет state.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

// responseRecorder перехватывает status + body для кеширования.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	wroteHdr   bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHdr {
		return
	}
	r.wroteHdr = true
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHdr {
		r.WriteHeader(http.StatusOK)
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// Read удовлетворяет io.Reader, на случай если кто-то вызовет на нём Read.
// Не используется в нашем случае, но nil-safe.
func (r *responseRecorder) Read(p []byte) (int, error) {
	return 0, io.EOF
}
