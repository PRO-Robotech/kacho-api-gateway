// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package middleware: HTTPIdempotency — HTTP middleware для Idempotency-Key.
//
// На каждом mutating-запросе (POST/PATCH/PUT/DELETE) если задан header
// `Idempotency-Key: <uuid>` — сохраняется ответ (status + body), и при
// повторном запросе с тем же ключом возвращается сохраненный ответ без вызова
// downstream: тот же Idempotency-Key → тот же Operation.id.
//
// Реализация: in-memory store с TTL, ограничением емкости (FIFO-вытеснение) и
// фоновым GC. Кэш-ключ привязан к (principal, method, path, Idempotency-Key),
// поэтому запись одного caller'а не может быть отдана другому principal'у или на
// другом маршруте. Для текущей фазы (single api-gateway pod) этого достаточно;
// при horizontal scaling потребуется внешнее хранилище (Postgres / Redis).
package middleware

import (
	"bytes"
	"container/list"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	// IdempotencyTTL — время жизни записи.
	IdempotencyTTL = 24 * time.Hour
	// idempotencyMaxEntries — потолок числа записей (FIFO-вытеснение). Защищает
	// от роста памяти, если caller шлет mutating-запросы с уникальным ключом.
	idempotencyMaxEntries = 10000
	// idempotencyMaxBodyBytes — ответы крупнее не кэшируются (control-plane
	// ответы — это маленький Operation/ресурс; крупное тело кэшировать незачем,
	// и это убирает amplification-вектор).
	idempotencyMaxBodyBytes = 256 * 1024
)

// idempotencyEntry хранит сохраненный response.
type idempotencyEntry struct {
	statusCode int
	body       []byte
	headers    http.Header
	expiresAt  time.Time
}

// idempotencyItem — значение элемента FIFO-списка: ключ + запись.
type idempotencyItem struct {
	key   string
	entry idempotencyEntry
}

// IdempotencyStore — in-memory store с TTL, ограничением емкости и GC.
type IdempotencyStore struct {
	mu         sync.Mutex
	elems      map[string]*list.Element // key → *list.Element{Value: *idempotencyItem}
	order      *list.List               // FIFO insertion order для вытеснения
	ttl        time.Duration
	maxEntries int
}

// NewIdempotencyStore создает store с фоновым GC и стандартной емкостью.
func NewIdempotencyStore(ttl time.Duration) *IdempotencyStore {
	return newIdempotencyStoreWithCap(ttl, idempotencyMaxEntries)
}

// newIdempotencyStoreWithCap — конструктор с явной емкостью (для тестов).
func newIdempotencyStoreWithCap(ttl time.Duration, maxEntries int) *IdempotencyStore {
	if maxEntries <= 0 {
		maxEntries = idempotencyMaxEntries
	}
	s := &IdempotencyStore{
		elems:      make(map[string]*list.Element),
		order:      list.New(),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
	go s.gcLoop()
	return s
}

// gcLoop удаляет expired entries раз в ttl/24 (но не реже минуты).
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
		for e := s.order.Front(); e != nil; {
			next := e.Next()
			if now.After(e.Value.(*idempotencyItem).entry.expiresAt) {
				s.removeElem(e)
			}
			e = next
		}
		s.mu.Unlock()
	}
}

// removeElem снимает элемент из списка и map. Caller держит s.mu.
func (s *IdempotencyStore) removeElem(e *list.Element) {
	it := e.Value.(*idempotencyItem)
	s.order.Remove(e)
	delete(s.elems, it.key)
}

// Len возвращает текущее число записей.
func (s *IdempotencyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.elems)
}

// get возвращает сохраненный entry или (zero, false) если ключа нет/expired.
func (s *IdempotencyStore) get(key string) (idempotencyEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.elems[key]
	if !ok {
		return idempotencyEntry{}, false
	}
	it := e.Value.(*idempotencyItem)
	if time.Now().After(it.entry.expiresAt) {
		s.removeElem(e)
		return idempotencyEntry{}, false
	}
	return it.entry, true
}

// put сохраняет entry с TTL, вытесняя самую старую запись при достижении лимита.
func (s *IdempotencyStore) put(key string, entry idempotencyEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.elems[key]; ok {
		e.Value.(*idempotencyItem).entry = entry
		s.order.MoveToBack(e)
		return
	}
	for len(s.elems) >= s.maxEntries {
		if front := s.order.Front(); front != nil {
			s.removeElem(front)
		} else {
			break
		}
	}
	s.elems[key] = s.order.PushBack(&idempotencyItem{key: key, entry: entry})
}

// HTTPIdempotency — HTTP middleware: при наличии Idempotency-Key на mutating
// request кэширует ответ или возвращает сохраненный. GET и запросы без ключа
// проходят насквозь. Ответ кэшируется при status < 500 (5xx не кэшируем —
// retry-safety) и теле не больше idempotencyMaxBodyBytes.
//
// Ключ кэша — fingerprint запроса (principal, method, path, Idempotency-Key):
// middleware смонтирован после authN/authZ, поэтому principal-заголовки уже
// проставлены, и запись одного caller'а не может быть отдана другому.
func HTTPIdempotency(store *IdempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isMutating(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			idemKey := r.Header.Get("Idempotency-Key")
			if idemKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := idempotencyCacheKey(r, idemKey)
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
			rec := &responseRecorder{ResponseWriter: w, body: &bytes.Buffer{}, statusCode: 200}
			next.ServeHTTP(rec, r)
			// Кэшируем только не-5xx и тело в пределах лимита.
			if rec.statusCode < 500 && rec.body.Len() <= idempotencyMaxBodyBytes {
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

// idempotencyCacheKey строит fingerprint запроса. NUL-разделитель исключает
// коллизии склейки между сегментами.
func idempotencyCacheKey(r *http.Request, idemKey string) string {
	principal := r.Header.Get("X-Kacho-Principal-Id")
	return principal + "\x00" + r.Method + "\x00" + r.URL.Path + "\x00" + idemKey
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

// Read удовлетворяет io.Reader на случай вызова Read на recorder'е. Nil-safe.
func (r *responseRecorder) Read(p []byte) (int, error) {
	return 0, io.EOF
}
