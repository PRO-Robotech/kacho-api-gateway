package watcher_test

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/watcher"
)

// fakePoller returns configured batches one per call, then empty slices.
// headID is max(ids) for non-empty batches, 0 for empty ones.
type fakePoller struct {
	mu      sync.Mutex
	batches [][]int64 // ids per call; nil / empty = empty batch
	calls   int
	// advanced signals that the poller has been called enough times.
	advanced  chan struct{}
	threshold int // call-count at which to close advanced
}

func (f *fakePoller) PollSubjectChanges(ctx context.Context, since int64) (ids []int64, headID int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b []int64
	if f.calls < len(f.batches) {
		b = f.batches[f.calls]
	}
	f.calls++
	// compute headID as max(ids), or 0 for empty
	var h int64
	for _, id := range b {
		if id > h {
			h = id
		}
	}
	// signal once we've crossed the threshold
	if f.calls == f.threshold && f.advanced != nil {
		close(f.advanced)
	}
	return b, h, nil
}

// TestSubjectChangeWatcher_PrimingTickDoesNotFlush verifies:
//   - The FIRST (priming) tick — even if non-empty — does NOT flush.
//   - A LATER non-empty tick DOES flush (exactly once for a single non-empty batch).
func TestSubjectChangeWatcher_PrimingTickDoesNotFlush(t *testing.T) {
	// batches[0] = {} → priming tick (empty ids); batches[1] = {1,2,3} → flush tick.
	advanced := make(chan struct{})
	p := &fakePoller{
		batches:   [][]int64{{}, {1, 2, 3}},
		advanced:  advanced,
		threshold: 2, // closed after second call (flush tick) completes
	}

	var flushCount int32
	flushed := make(chan struct{}, 4)
	flushFn := func() {
		atomic.AddInt32(&flushCount, 1)
		flushed <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := watcher.New(p, flushFn, 10*time.Millisecond, slog.Default())
	go w.Run(ctx)

	// Wait until both ticks have fired (threshold=2 calls).
	select {
	case <-advanced:
	case <-time.After(2 * time.Second):
		t.Fatal("fakePoller was not called twice within timeout")
	}

	// Give the watcher a moment to complete the flush call if triggered.
	// We use a short extra wait then check the count.
	select {
	case <-flushed:
		// good — at least one flush happened
	case <-time.After(time.Second):
		t.Fatal("watcher did not flush after the second (non-priming) non-empty poll batch")
	}

	cancel() // stop watcher before the count assertion

	got := atomic.LoadInt32(&flushCount)
	if got != 1 {
		t.Errorf("expected exactly 1 flush (priming tick contributes 0), got %d", got)
	}
}

// TestSubjectChangeWatcher_PrimingNonEmptyStillDoesNotFlush verifies that even
// when the very first poll returns non-empty ids, priming suppresses the flush.
func TestSubjectChangeWatcher_PrimingNonEmptyStillDoesNotFlush(t *testing.T) {
	// batches[0] = {10,20} → priming tick (non-empty!); batches[1] = {30} → flush tick.
	advanced := make(chan struct{})
	p := &fakePoller{
		batches:   [][]int64{{10, 20}, {30}},
		advanced:  advanced,
		threshold: 2,
	}

	var flushCount int32
	flushed := make(chan struct{}, 4)
	flushFn := func() {
		atomic.AddInt32(&flushCount, 1)
		flushed <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := watcher.New(p, flushFn, 10*time.Millisecond, slog.Default())
	go w.Run(ctx)

	select {
	case <-advanced:
	case <-time.After(2 * time.Second):
		t.Fatal("fakePoller was not called twice within timeout")
	}

	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("watcher did not flush after the second (non-priming) non-empty poll batch")
	}

	cancel()

	got := atomic.LoadInt32(&flushCount)
	if got != 1 {
		t.Errorf("expected exactly 1 flush (non-empty priming tick must not flush), got %d", got)
	}
}

// TestSubjectChangeWatcher_NoFlushWhenAllEmpty verifies no flush when every tick is empty.
func TestSubjectChangeWatcher_NoFlushWhenAllEmpty(t *testing.T) {
	advanced := make(chan struct{})
	p := &fakePoller{
		batches:   [][]int64{{}, {}},
		advanced:  advanced,
		threshold: 3, // three empty calls: prime + two empty ticks
	}

	var flushCount int32
	flushFn := func() { atomic.AddInt32(&flushCount, 1) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := watcher.New(p, flushFn, 10*time.Millisecond, slog.Default())
	go w.Run(ctx)

	select {
	case <-advanced:
	case <-time.After(2 * time.Second):
		t.Fatal("fakePoller was not called 3 times within timeout")
	}

	// Small delay to let any erroneous flush complete before we assert.
	time.Sleep(30 * time.Millisecond)
	cancel()

	if got := atomic.LoadInt32(&flushCount); got != 0 {
		t.Errorf("expected 0 flushes for all-empty batches, got %d", got)
	}
}
