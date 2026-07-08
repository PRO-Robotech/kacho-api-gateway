// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package watcher — cross-replica authz-cache invalidation.
// Polls kacho-iam InternalIAMService.PollSubjectChanges by ascending-id cursor;
// on any non-empty batch, flushes this replica's authz decision cache. The
// request-path replica already self-flushed (see authz.MaybeFlushOnMutation);
// this loop converges sibling replicas within one interval.
package watcher

import (
	"context"
	"log/slog"
	"time"
)

// Poller — narrow port over the PollSubjectChanges RPC.
type Poller interface {
	PollSubjectChanges(ctx context.Context, since int64) (ids []int64, headID int64, err error)
}

// minPollTimeout floors the per-call PollSubjectChanges deadline so a fast poll
// interval cannot make the deadline unreasonably tight.
const minPollTimeout = 5 * time.Second

// SubjectChangeWatcher polls IAM for subject-change events and flushes the
// authz decision cache on this gateway replica when new events appear.
type SubjectChangeWatcher struct {
	poller      Poller
	flush       func()
	interval    time.Duration
	pollTimeout time.Duration
	logger      *slog.Logger
	cursor      int64
	primed      bool
}

// New constructs a SubjectChangeWatcher. interval ≤ 0 defaults to 2s.
func New(p Poller, flush func(), interval time.Duration, logger *slog.Logger) *SubjectChangeWatcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	// Bound a single PollSubjectChanges call: a hung iam handler must not stall
	// the whole cross-replica invalidation loop forever. The deadline scales
	// with the interval (a few ticks' worth) but never drops below a floor, so
	// the loop self-recovers on the next tick instead of blocking indefinitely.
	pollTimeout := interval * 4
	if pollTimeout < minPollTimeout {
		pollTimeout = minPollTimeout
	}
	return &SubjectChangeWatcher{poller: p, flush: flush, interval: interval, pollTimeout: pollTimeout, logger: logger}
}

// Run blocks until ctx is cancelled. Call in a goroutine.
func (w *SubjectChangeWatcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *SubjectChangeWatcher) tick(ctx context.Context) {
	// Per-call deadline: a stalled iam handler must not wedge the loop forever.
	pollCtx, cancel := context.WithTimeout(ctx, w.pollTimeout)
	defer cancel()
	ids, headID, err := w.poller.PollSubjectChanges(pollCtx, w.cursor)
	if err != nil {
		w.logger.Warn("subject-change poll failed", "err", err)
		return
	}
	// First successful poll on a fresh gateway: adopt headID as the cursor and
	// do NOT flush. The cache is cold at startup, and jumping straight to headID
	// skips replaying the historical backlog in subject_change_outbox.
	if !w.primed {
		w.primed = true
		w.cursor = headID
		return
	}
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		if id > w.cursor {
			w.cursor = id
		}
	}
	if headID > w.cursor {
		w.cursor = headID
	}
	w.flush()
	w.logger.Info("authz decision-cache flushed by subject-change poll", "cursor", w.cursor)
}
