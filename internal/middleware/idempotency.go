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

// idempotencyFlight — an in-flight reservation for a key. The first (leader)
// caller for a key registers a flight; concurrent (follower) callers block on
// `done` and then replay the leader's captured response, so a mutating
// downstream runs exactly once per concurrent batch (single-flight — closes the
// check-then-act TOCTOU, project-rule #10 / CWE-362).
type idempotencyFlight struct {
	done       chan struct{}
	hasResult  bool
	statusCode int
	body       []byte
	headers    http.Header
}

// IdempotencyStore — in-memory store с TTL, ограничением емкости и GC.
type IdempotencyStore struct {
	mu         sync.Mutex
	elems      map[string]*list.Element      // key → *list.Element{Value: *idempotencyItem}
	order      *list.List                    // FIFO insertion order для вытеснения
	inflight   map[string]*idempotencyFlight // key → in-flight reservation
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
		inflight:   make(map[string]*idempotencyFlight),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
	go s.gcLoop()
	return s
}

// reserve is the single-flight admission point. Under the store lock it resolves
// one of three outcomes for the key:
//
//   - cached != nil  — a completed long-term entry exists; replay it and return.
//   - leader != nil  — no in-flight reservation existed; THIS caller owns the
//     downstream execution and MUST call finishLeader or abortLeader exactly once.
//   - follower != nil — another caller is already executing downstream; wait on
//     follower.done, then replay follower's captured result (or fall through when
//     the leader aborted without one).
func (s *IdempotencyStore) reserve(key string) (cached *idempotencyEntry, leader, follower *idempotencyFlight) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.elems[key]; ok {
		it := e.Value.(*idempotencyItem)
		if !time.Now().After(it.entry.expiresAt) {
			entry := it.entry
			return &entry, nil, nil
		}
		s.removeElem(e)
	}
	if fl, ok := s.inflight[key]; ok {
		return nil, nil, fl
	}
	fl := &idempotencyFlight{done: make(chan struct{})}
	s.inflight[key] = fl
	return nil, fl, nil
}

// finishLeader records the leader's response on the flight (so followers can
// replay it), optionally commits it to the long-term store, drops the in-flight
// reservation and wakes followers. Called exactly once by the leader.
func (s *IdempotencyStore) finishLeader(key string, fl *idempotencyFlight, entry idempotencyEntry, cache bool) {
	s.mu.Lock()
	fl.statusCode = entry.statusCode
	fl.body = entry.body
	fl.headers = entry.headers
	fl.hasResult = true
	if cache {
		s.putLocked(key, entry)
	}
	delete(s.inflight, key)
	s.mu.Unlock()
	close(fl.done)
}

// abortLeader drops the in-flight reservation without a result (downstream
// panicked / never produced a cacheable response). Followers wake and fall
// through to execute downstream themselves. Idempotent for the not-yet-finished
// flight.
func (s *IdempotencyStore) abortLeader(key string, fl *idempotencyFlight) {
	s.mu.Lock()
	if cur, ok := s.inflight[key]; ok && cur == fl {
		delete(s.inflight, key)
		s.mu.Unlock()
		close(fl.done)
		return
	}
	s.mu.Unlock()
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
	s.putLocked(key, entry)
}

// putLocked — общий insert-путь. Caller держит s.mu.
func (s *IdempotencyStore) putLocked(key string, entry idempotencyEntry) {
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

			// Single-flight admission. Atomically resolve to: an existing cached
			// entry (replay), a follower waiting on an in-flight leader, or the
			// leader that owns downstream execution. This closes the check-then-act
			// TOCTOU where two concurrent same-key double-submits both miss the
			// cache and both mutate downstream (project-rule #10 / CWE-362).
			cached, leader, follower := store.reserve(key)
			if cached != nil {
				replayIdempotent(w, *cached)
				return
			}
			if follower != nil {
				<-follower.done
				if follower.hasResult {
					replayIdempotent(w, idempotencyEntry{
						statusCode: follower.statusCode,
						body:       follower.body,
						headers:    follower.headers,
					})
					return
				}
				// Leader aborted without a result (panic / no cacheable response)
				// — fall through and execute downstream directly, best-effort.
				next.ServeHTTP(w, r)
				return
			}

			// Leader path. Guarantee the reservation is always released even if
			// downstream panics (followers must never block forever).
			finished := false
			defer func() {
				if !finished {
					store.abortLeader(key, leader)
				}
			}()
			rec := &responseRecorder{ResponseWriter: w, body: &bytes.Buffer{}, statusCode: 200}
			next.ServeHTTP(rec, r)
			headers := http.Header{}
			if ct := w.Header().Get("Content-Type"); ct != "" {
				headers.Set("Content-Type", ct)
			}
			// Cache long-term only non-5xx responses within the size cap (5xx are
			// retry-safe; oversized bodies would pin memory). Followers of this
			// concurrent batch still replay the leader's captured response either
			// way, so the batch shares one downstream execution.
			cache := rec.statusCode < 500 && rec.body.Len() <= idempotencyMaxBodyBytes
			store.finishLeader(key, leader, idempotencyEntry{
				statusCode: rec.statusCode,
				body:       rec.body.Bytes(),
				headers:    headers,
				expiresAt:  time.Now().Add(store.ttl),
			}, cache)
			finished = true
		})
	}
}

// replayIdempotent writes a stored/captured response to w with the
// X-Idempotent-Replayed marker.
func replayIdempotent(w http.ResponseWriter, e idempotencyEntry) {
	for k, vs := range e.headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Idempotent-Replayed", "true")
	w.WriteHeader(e.statusCode)
	_, _ = w.Write(e.body)
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
