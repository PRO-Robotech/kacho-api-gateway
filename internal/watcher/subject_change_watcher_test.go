package watcher_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/watcher"
)

// fakePoller returns one batch then empty forever.
type fakePoller struct {
	mu      sync.Mutex
	batches [][]int64 // ids per call
	calls   int
}

func (f *fakePoller) PollSubjectChanges(ctx context.Context, since int64) (ids []int64, headID int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls < len(f.batches) {
		b := f.batches[f.calls]
		f.calls++
		return b, 99, nil
	}
	f.calls++
	return nil, 99, nil
}

func TestSubjectChangeWatcher_FlushesOnChange(t *testing.T) {
	p := &fakePoller{batches: [][]int64{{1, 2, 3}}}
	flushed := make(chan struct{}, 4)
	w := watcher.New(p, func() { flushed <- struct{}{} }, 10*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("watcher did not flush after a non-empty poll batch")
	}
}
