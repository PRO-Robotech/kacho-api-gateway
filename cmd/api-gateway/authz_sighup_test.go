// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Tests for installAuthzSIGHUP: the SIGHUP handler must drive a real reload of
// the authz config (permission catalog + overrides), not silently log a
// no-op success. See main.go.
package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type fakeReloader struct {
	calls atomic.Int64
	err   error
	done  chan struct{}
}

func (f *fakeReloader) Reload() error {
	f.calls.Add(1)
	f.done <- struct{}{}
	return f.err
}

func silentSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func waitSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reload to be invoked")
	}
}

// TestInstallAuthzSIGHUP_ReloadsOnSignal proves the handler invokes the
// reloader on each SIGHUP rather than being a pure no-op.
func TestInstallAuthzSIGHUP_ReloadsOnSignal(t *testing.T) {
	hupCh := make(chan os.Signal, 1)
	r := &fakeReloader{done: make(chan struct{}, 4)}
	installAuthzSIGHUP(hupCh, r, silentSlog())

	hupCh <- syscall.SIGHUP
	waitSignal(t, r.done)

	if got := r.calls.Load(); got != 1 {
		t.Fatalf("Reload calls = %d, want 1", got)
	}
}

// TestInstallAuthzSIGHUP_ContinuesOnReloadError proves a failed reload is
// logged but the loop keeps serving subsequent signals (previous-good config
// preserved inside Reload; the handler does not wedge).
func TestInstallAuthzSIGHUP_ContinuesOnReloadError(t *testing.T) {
	hupCh := make(chan os.Signal, 2)
	r := &fakeReloader{done: make(chan struct{}, 4), err: errors.New("reload boom")}
	installAuthzSIGHUP(hupCh, r, silentSlog())

	hupCh <- syscall.SIGHUP
	waitSignal(t, r.done)
	hupCh <- syscall.SIGHUP
	waitSignal(t, r.done)

	if got := r.calls.Load(); got != 2 {
		t.Fatalf("Reload calls = %d, want 2 (loop must survive a reload error)", got)
	}
}
