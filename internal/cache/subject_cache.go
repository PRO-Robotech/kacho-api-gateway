// Package cache — in-process cache helpers для api-gateway.
// subject_cache.go — LRU-bounded + TTL cache для subject-резолва (acceptance §4.3).
package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

type SubjectCache struct {
	mu      sync.Mutex
	maxSize int
	ttl     time.Duration
	items   map[string]*list.Element
	order   *list.List
	now     func() time.Time
}

type subjectEntry struct {
	key       string
	value     middleware.Subject
	expiresAt time.Time
}

func NewSubjectCache(maxSize int, ttl time.Duration) *SubjectCache {
	if maxSize <= 0 {
		maxSize = 10_000
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &SubjectCache{
		maxSize: maxSize,
		ttl:     ttl,
		items:   make(map[string]*list.Element, maxSize),
		order:   list.New(),
		now:     time.Now,
	}
}

func (c *SubjectCache) Get(key string) (middleware.Subject, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return middleware.Subject{}, false
	}
	e := el.Value.(*subjectEntry)
	if c.now().After(e.expiresAt) {
		c.order.Remove(el)
		delete(c.items, key)
		return middleware.Subject{}, false
	}
	c.order.MoveToFront(el)
	return e.value, true
}

func (c *SubjectCache) Set(key string, v middleware.Subject) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*subjectEntry)
		e.value = v
		e.expiresAt = c.now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	e := &subjectEntry{key: key, value: v, expiresAt: c.now().Add(c.ttl)}
	el := c.order.PushFront(e)
	c.items[key] = el
	if c.order.Len() > c.maxSize {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*subjectEntry).key)
		}
	}
}

func (c *SubjectCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

func (c *SubjectCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element, c.maxSize)
	c.order = list.New()
}

func (c *SubjectCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
