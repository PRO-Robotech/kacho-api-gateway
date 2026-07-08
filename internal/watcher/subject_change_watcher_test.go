// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package watcher_test

import (
	"context"
	"errors"
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
	errs    []error   // parallel to batches; errs[i] (if set) is returned on call i
	calls   int
	sinces  []int64 // records the `since` cursor observed on each call
	// advanced signals that the poller has been called enough times.
	advanced  chan struct{}
	threshold int // call-count at which to close advanced
}

func (f *fakePoller) PollSubjectChanges(ctx context.Context, since int64) (ids []int64, headID int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sinces = append(f.sinces, since)
	i := f.calls
	f.calls++
	var scriptedErr error
	if i < len(f.errs) {
		scriptedErr = f.errs[i]
	}
	// signal once we've crossed the threshold
	if f.calls == f.threshold && f.advanced != nil {
		close(f.advanced)
	}
	if scriptedErr != nil {
		return nil, 0, scriptedErr
	}
	var b []int64
	if i < len(f.batches) {
		b = f.batches[i]
	}
	// compute headID as max(ids), or 0 for empty
	var h int64
	for _, id := range b {
		if id > h {
			h = id
		}
	}
	return b, h, nil
}

// sinceAt returns the `since` cursor observed on the (0-indexed) n-th poll call.
func (f *fakePoller) sinceAt(n int) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n < 0 || n >= len(f.sinces) {
		return -1
	}
	return f.sinces[n]
}

// deadlinePoller records whether the ctx it was handed carries a deadline.
type deadlinePoller struct {
	seen chan bool // receives ctx.Deadline() ok on the first call
	once sync.Once
}

func (d *deadlinePoller) PollSubjectChanges(ctx context.Context, since int64) ([]int64, int64, error) {
	_, ok := ctx.Deadline()
	d.once.Do(func() { d.seen <- ok })
	return nil, 0, nil
}

// TestSubjectChangeWatcher_PollHasPerCallDeadline verifies that each
// PollSubjectChanges call is bounded by a per-call deadline, so a hung iam
// handler cannot stall the whole cross-replica invalidation loop forever.
func TestSubjectChangeWatcher_PollHasPerCallDeadline(t *testing.T) {
	seen := make(chan bool, 1)
	p := &deadlinePoller{seen: seen}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Parent ctx has NO deadline — any deadline observed by the poller must come
	// from the watcher's per-call context.WithTimeout.
	w := watcher.New(p, func() {}, 5*time.Millisecond, slog.Default())
	go w.Run(ctx)

	select {
	case ok := <-seen:
		if !ok {
			t.Fatal("PollSubjectChanges was called without a per-call deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poller was not called within timeout")
	}
	cancel()
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
	// advanced is closed after the 3rd poller call (prime + two empty ticks).
	// Because flush() is called synchronously inside tick(), the channel signal
	// already implies that any flush triggered by those ticks has completed —
	// no extra sleep is needed.
	advanced := make(chan struct{})
	p := &fakePoller{
		batches:   [][]int64{{}, {}, {}},
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

	// flush() is synchronous in tick(); advanced firing means all three tick
	// calls have returned — cancel and assert immediately, no sleep required.
	cancel()

	if got := atomic.LoadInt32(&flushCount); got != 0 {
		t.Errorf("expected 0 flushes for all-empty batches, got %d", got)
	}
}

// TestSubjectChangeWatcher_PollErrorPreservesCursorNoFlush verifies the
// security-relevant error branch: a poll error must NOT flush and must NOT
// advance the cursor, so the recovered connection replays the backlog missed
// during the outage (revocation propagation to sibling replicas, CWE-613).
//
// Script (cursor starts at 0):
//
//	call0: {}    -> priming tick, cursor := headID(=0), no flush
//	call1: {5}   -> flush #1, cursor := 5
//	call2: ERROR -> no flush, cursor preserved at 5
//	call3: {6}   -> flush #2, and MUST have been polled with since=5
func TestSubjectChangeWatcher_PollErrorPreservesCursorNoFlush(t *testing.T) {
	advanced := make(chan struct{})
	p := &fakePoller{
		batches:   [][]int64{{}, {5}, {}, {6}},
		errs:      []error{nil, nil, errors.New("iam blip"), nil},
		advanced:  advanced,
		threshold: 4,
	}

	var flushCount int32
	flushFn := func() { atomic.AddInt32(&flushCount, 1) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := watcher.New(p, flushFn, 5*time.Millisecond, slog.Default())
	go w.Run(ctx)

	select {
	case <-advanced:
	case <-time.After(2 * time.Second):
		t.Fatal("fakePoller was not called 4 times within timeout")
	}
	cancel()

	// The errored call2 was polled at cursor 5 (set by the call1 flush), and the
	// recovery call3 must STILL poll at 5 — the error did not advance the cursor.
	if got := p.sinceAt(2); got != 5 {
		t.Fatalf("errored poll observed since=%d, want 5 (cursor after call1 flush)", got)
	}
	if got := p.sinceAt(3); got != 5 {
		t.Fatalf("recovery poll observed since=%d, want 5 (cursor preserved across error)", got)
	}
	// prime(0) + flush(call1) + error(call2, 0) + flush(call3) == 2 flushes.
	if got := atomic.LoadInt32(&flushCount); got != 2 {
		t.Fatalf("expected exactly 2 flushes (error must not flush), got %d", got)
	}
}

// TestSubjectChangeWatcher_ErrorOnFirstPollDoesNotPrime verifies that an error
// on the very first poll does NOT prime: priming is deferred to the first
// SUCCESSFUL poll, so the first successful (even non-empty) batch is adopted as
// the cold-start cursor without flushing, and only the NEXT batch flushes.
//
// Script:
//
//	call0: ERROR -> not primed, cursor stays 0
//	call1: {7}   -> FIRST successful poll => priming tick, cursor := 7, NO flush
//	call2: {8}   -> primed now => flush #1, cursor := 8
func TestSubjectChangeWatcher_ErrorOnFirstPollDoesNotPrime(t *testing.T) {
	advanced := make(chan struct{})
	p := &fakePoller{
		batches:   [][]int64{{}, {7}, {8}},
		errs:      []error{errors.New("iam cold blip"), nil, nil},
		advanced:  advanced,
		threshold: 3,
	}

	var flushCount int32
	flushFn := func() { atomic.AddInt32(&flushCount, 1) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := watcher.New(p, flushFn, 5*time.Millisecond, slog.Default())
	go w.Run(ctx)

	select {
	case <-advanced:
	case <-time.After(2 * time.Second):
		t.Fatal("fakePoller was not called 3 times within timeout")
	}
	cancel()

	// The errored first poll must not have primed/advanced: call1 still polls at 0.
	if got := p.sinceAt(1); got != 0 {
		t.Fatalf("post-error poll observed since=%d, want 0 (error must not prime)", got)
	}
	// Only call2's {8} flushes; call1's {7} is the (deferred) priming tick.
	if got := atomic.LoadInt32(&flushCount); got != 1 {
		t.Fatalf("expected exactly 1 flush (error-first defers priming to call1), got %d", got)
	}
}
