// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package proxy — local unknown-service proxy для api-gateway.
//
// Обслуживается только нативный `kacho.cloud.*` API.
//
//   - `MethodResolver` — тип-сигнатура resolver-функции, которую дергает
//     UnknownServiceHandler (см. `Handler` ниже).
//   - `Handler` — простая `grpc.StreamHandler`-обертка, которая роутит
//     unknown service-method к backend через `resolve`.
package proxy

import (
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// MethodResolver — функция определяет в какой backend forward'ить RPC.
// (fullMethod, conn, ok). Если ok==false — метод НЕ выставлен на публичный
// gateway (unknown domain / Internal*-service / backend не зарегистрирован) →
// NotFound. Тот же контракт держит server.go (Resolver): NotFound для blocked /
// unknown, чтобы Internal*-методы выглядели как несуществующие на external
// listener (не "exists but unimplemented"), иначе утечка о наличии admin
// endpoints.
type methodResolverInternal = func(fullMethod string) (string, grpc.ClientConnInterface, bool)

// Handler — gRPC StreamHandler для UnknownServiceHandler. Принимает resolver
// и proxies stream к target backend.
//
// Прозрачный pass-through: incoming metadata форвардится как outgoing (header),
// backend response header/trailer форвардятся обратно клиенту (иначе gRPC
// error-details и trailing metadata бэкенда молча терялись бы), а error-status
// бэкенда пробрасывается как есть.
func Handler(resolve methodResolverInternal) grpc.StreamHandler {
	return func(srv interface{}, ss grpc.ServerStream) error {
		method, ok := grpc.MethodFromServerStream(ss)
		if !ok {
			return status.Error(codes.Internal, "method not in stream context")
		}
		target, conn, ok := resolve(method)
		if !ok {
			// NotFound (не Unimplemented) — единый контракт с server.go
			// (Resolver): Internal*-методы и unknown-domain методы должны быть
			// неотличимы от "method does not exist" для external клиента.
			// Unimplemented подсказал бы, что метод "известен системе, но не
			// реализован" — это разведка.
			return status.Errorf(codes.NotFound, "unknown method: %s", method)
		}
		// Forward incoming metadata as outgoing (shared helper: always .Copy()s,
		// same contract as every cross-process gRPC hop in the gateway).
		outCtx := principalmeta.OutgoingFromIncoming(ss.Context())

		// Create bidi stream on target.
		desc := &grpc.StreamDesc{StreamName: target, ServerStreams: true, ClientStreams: true}
		clientStream, err := conn.NewStream(outCtx, desc, target)
		if err != nil {
			return err
		}

		// Bidirectional copy.
		errCh := make(chan error, 2)
		go func() {
			f := &emptyFrame{}
			for {
				if err := ss.RecvMsg(f); err != nil {
					if err == io.EOF {
						_ = clientStream.CloseSend()
						errCh <- nil
						return
					}
					errCh <- err
					return
				}
				if err := clientStream.SendMsg(f); err != nil {
					errCh <- err
					return
				}
			}
		}()
		go func() {
			// Propagate the backend's response header to the client BEFORE the
			// first response frame — a transparent proxy must forward the
			// backend's initial metadata. Header() blocks until the backend
			// flushes headers (on its first SendMsg or on completion).
			if h, herr := clientStream.Header(); herr == nil && h.Len() > 0 {
				_ = ss.SetHeader(h)
			}
			f := &emptyFrame{}
			for {
				if err := clientStream.RecvMsg(f); err != nil {
					// Stream finished (EOF) or errored: forward the backend's
					// trailing metadata (gRPC error-details / trailers) to the
					// client. Trailer() is valid once RecvMsg returns non-nil.
					if tr := clientStream.Trailer(); tr.Len() > 0 {
						ss.SetTrailer(tr)
					}
					if err == io.EOF {
						errCh <- nil
						return
					}
					errCh <- err
					return
				}
				if err := ss.SendMsg(f); err != nil {
					errCh <- err
					return
				}
			}
		}()
		for i := 0; i < 2; i++ {
			if e := <-errCh; e != nil {
				return e
			}
		}
		return nil
	}
}

// emptyFrame — generic byte container для gRPC frame pass-through.
type emptyFrame struct {
	payload []byte
}

func (f *emptyFrame) Reset() {}
func (f *emptyFrame) String() string {
	return ""
}
func (f *emptyFrame) ProtoMessage() {}

// Marshal/Unmarshal — proxy через raw payload.
func (f *emptyFrame) Marshal() ([]byte, error) { return f.payload, nil }
func (f *emptyFrame) Unmarshal(d []byte) error { f.payload = append([]byte(nil), d...); return nil }
