// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const requestIDKey = "x-request-id"

// requestIDFromIncoming извлекает x-request-id из входящих gRPC metadata.
// Если заголовок отсутствует — генерирует новый UUID v4.
func requestIDFromIncoming(ctx context.Context) (string, context.Context) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if vals := md.Get(requestIDKey); len(vals) > 0 && vals[0] != "" {
			return vals[0], ctx
		}
	}
	id := uuid.New().String()
	// Добавляем в incoming MD, чтобы директор мог пробросить его downstream
	if !ok {
		md = metadata.New(nil)
	} else {
		md = md.Copy()
	}
	md.Set(requestIDKey, id)
	return id, metadata.NewIncomingContext(ctx, md)
}

// requestIDKey в context
type ctxKey struct{}

// UnaryRequestID — unary gRPC interceptor: обеспечивает x-request-id в контексте
// и прокидывает его в trailing metadata ответа.
func UnaryRequestID(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	id, ctx := requestIDFromIncoming(ctx)
	ctx = context.WithValue(ctx, ctxKey{}, id)
	// Добавляем к исходящим заголовкам для возврата клиенту
	_ = grpc.SetHeader(ctx, metadata.Pairs(requestIDKey, id))
	resp, err := handler(ctx, req)
	_ = grpc.SetTrailer(ctx, metadata.Pairs(requestIDKey, id))
	return resp, err
}

// StreamRequestID — streaming gRPC interceptor.
func StreamRequestID(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	id, ctx := requestIDFromIncoming(ctx)
	ctx = context.WithValue(ctx, ctxKey{}, id)
	wrapped := &wrappedStream{ServerStream: ss, ctx: ctx}
	_ = ss.SetHeader(metadata.Pairs(requestIDKey, id))
	return handler(srv, wrapped)
}

// RequestIDFromContext возвращает request-id из контекста (используется в логировании).
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}

// wrappedStream позволяет подменить ctx в ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// HTTPRequestID — HTTP middleware: обеспечивает X-Request-ID в HTTP-запросах.
func HTTPRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.New().String()
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, id))
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}
