// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestGateway_F1_RequestIDPreservedFromClient проверяет сценарий F1.
func TestGateway_F1_RequestIDPreservedFromClient(t *testing.T) {
	const clientID = "test-req-001"
	md := metadata.Pairs("x-request-id", clientID)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var capturedID string
	handler := func(ctx context.Context, req any) (any, error) {
		capturedID = middleware.RequestIDFromContext(ctx)
		return nil, nil
	}

	interceptor := middleware.UnaryRequestID
	_, _ = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)

	if capturedID != clientID {
		t.Errorf("ожидали request_id=%q, получили %q", clientID, capturedID)
	}
}

// TestGateway_F2_RequestIDGeneratedWhenMissing проверяет сценарий F2: UUID генерируется.
func TestGateway_F2_RequestIDGeneratedWhenMissing(t *testing.T) {
	ctx := context.Background()

	var capturedID string
	handler := func(ctx context.Context, req any) (any, error) {
		capturedID = middleware.RequestIDFromContext(ctx)
		return nil, nil
	}

	_, _ = middleware.UnaryRequestID(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)

	if capturedID == "" {
		t.Error("request_id должен быть сгенерирован, если отсутствует")
	}
	if len(capturedID) != 36 { // UUID v4: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		t.Errorf("сгенерированный request_id должен быть UUID v4, получили: %q", capturedID)
	}
}

// TestGateway_F3_PanicRecoveryReturnsInternal проверяет сценарий F3.
func TestGateway_F3_PanicRecoveryReturnsInternal(t *testing.T) {
	logger := testLogger()
	panicHandler := func(ctx context.Context, req any) (any, error) {
		panic("test panic")
	}

	interceptor := middleware.UnaryRecovery(logger)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, panicHandler)
	if err == nil {
		t.Fatal("ожидали ошибку после panic")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Errorf("ожидали INTERNAL, получили %v", err)
	}
}

// TestGateway_F7_AuthDevModePassesThrough проверяет сценарий F7:
// в mode=dev запрос без Bearer проходит как anonymous (backwards-compat).
func TestGateway_F7_AuthDevModePassesThrough(t *testing.T) {
	logger := testLogger()
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return nil, nil
	}

	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", nil, logger)
	interceptor := auth.Unary()
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	if err != nil {
		t.Fatalf("dev mode без Bearer не должен возвращать ошибку: %v", err)
	}
	if !called {
		t.Error("handler должен быть вызван")
	}
}

// TestGateway_F6_HTTPRequestIDMiddleware проверяет HTTP X-Request-ID middleware.
func TestGateway_F6_HTTPRequestIDMiddleware(t *testing.T) {
	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.HTTPRequestID(inner)

	t.Run("клиентский X-Request-ID сохраняется", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Header.Set("X-Request-ID", "client-id-42")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if capturedID != "client-id-42" {
			t.Errorf("ожидали client-id-42, получили %q", capturedID)
		}
	})

	t.Run("X-Request-ID генерируется если отсутствует", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if capturedID == "" {
			t.Error("X-Request-ID должен быть сгенерирован")
		}
	})
}
