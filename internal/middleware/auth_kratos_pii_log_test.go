// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// piiLookup implements SubjectLookuper WITHOUT the KratosSubjectLookuper
// extension, so tryKratosSession takes the plain LookupByExternalID branch and
// reaches the "Principal injected (Kratos)" log line.
type piiLookup struct{ subj Subject }

func (p piiLookup) LookupByExternalID(context.Context, string) (Subject, error) {
	return p.subj, nil
}

// TestTryKratosSession_DoesNotLogEmail locks the behaviour that resolving a
// Kratos SPA session must NOT emit the end-user email into the structured log
// (security.md hardening-invariant #2 — PII is never logged; correlate by the
// non-PII external_id/identity_id). Observed at the log-sink level, not just the
// gRPC code: a refactor that re-introduces the email field must turn this red.
func TestTryKratosSession_DoesNotLogEmail(t *testing.T) {
	const email = "secret-user@example.com"
	const identityID = "id-123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"active":true,"identity":{"id":"`+identityID+
			`","traits":{"email":"`+email+`","name":{"first":"Ann","last":"Lee"}}}}`)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	a := NewAuthInterceptor(AuthModeDev, "",
		piiLookup{subj: Subject{Type: "user", ID: "usr_1", DisplayName: "Ann Lee"}},
		logger).WithKratos(NewKratosClient(srv.URL))

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Cookie", "ory_kratos_session=abc")

	if ok := a.tryKratosSession(req); !ok {
		t.Fatal("expected principal to be injected from the active Kratos session")
	}

	logged := buf.String()
	if strings.Contains(logged, email) {
		t.Fatalf("end-user email PII leaked into the log: %s", logged)
	}
	// The log line must still fire and correlate by the non-PII identity id.
	if !strings.Contains(logged, identityID) {
		t.Fatalf("expected non-PII identity_id %q in the injection log, got: %s", identityID, logged)
	}
}
