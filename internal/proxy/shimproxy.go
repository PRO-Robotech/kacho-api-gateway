// Package proxy — local shimproxy stub (KAC-122 yc-shim drop).
//
// Ранее эти helpers жили в `github.com/PRO-Robotech/kacho-yc-shim/shimproxy`
// (отдельный репо). После KAC-122 yc-shim удалён — мы более не поддерживаем
// `yandex.cloud.*` API compatibility. Поэтому функции — минимальный stub:
//
//   - `MethodResolver` — тип-сигнатура остаётся для совместимости с
//     Resolver() ниже.
//   - `IsYandexMethod` / `RewriteToKacho` — оставлены работающими (если
//     потенциальный клиент придёт с yandex.cloud.* — мы rewrite'ем как
//     раньше), но поскольку backends не expose'ят yandex-services, в
//     конечном итоге допустимо удалить весь yc-CLI path entirely.
//   - `Handler` — простая `grpc.StreamHandler`-обёртка, которая роутит
//     unknown service-method к backend через `resolve`.
package proxy

import (
	"io"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MethodResolver — функция определяет в какой backend forward'ить RPC.
// (fullMethod, conn, ok). Если ok==false — Unimplemented.
type methodResolverInternal = func(fullMethod string) (string, grpc.ClientConnInterface, bool)

// IsYandexMethod проверяет начинается ли method с /yandex.cloud.
func IsYandexMethod(method string) bool {
	return strings.HasPrefix(method, "/yandex.cloud.")
}

// RewriteToKacho заменяет /yandex.cloud. → /kacho.cloud.
func RewriteToKacho(method string) string {
	if !IsYandexMethod(method) {
		return method
	}
	return "/kacho.cloud." + strings.TrimPrefix(method, "/yandex.cloud.")
}

// Handler — gRPC StreamHandler для UnknownServiceHandler. Принимает resolver
// и proxies stream к target backend.
//
// Реализация — minimal pass-through; full features (metadata propagation,
// trailers) дёргают grpc internals. Используем стандартный grpc.NewStream
// API для прозрачного proxy.
func Handler(resolve methodResolverInternal) grpc.StreamHandler {
	return func(srv interface{}, ss grpc.ServerStream) error {
		method, ok := grpc.MethodFromServerStream(ss)
		if !ok {
			return status.Error(codes.Internal, "method not in stream context")
		}
		target, conn, ok := resolve(method)
		if !ok {
			return status.Errorf(codes.Unimplemented, "method %s not implemented", method)
		}
		// Forward incoming metadata as outgoing.
		md, _ := metadata.FromIncomingContext(ss.Context())
		outCtx := metadata.NewOutgoingContext(ss.Context(), md)

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
			f := &emptyFrame{}
			for {
				if err := clientStream.RecvMsg(f); err != nil {
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
func (f *emptyFrame) Marshal() ([]byte, error)    { return f.payload, nil }
func (f *emptyFrame) Unmarshal(d []byte) error    { f.payload = append([]byte(nil), d...); return nil }
