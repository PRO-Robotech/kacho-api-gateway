package proxy

import (
	"context"

	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	"google.golang.org/grpc"
)

// NewServer создаёт gRPC-сервер с транспарентным proxy-handler-ом.
// Все входящие запросы обрабатываются через director: allowlist-фильтрация + routing.
func NewServer(director func(context.Context, string) (context.Context, grpc.ClientConnInterface, error), opts ...grpc.ServerOption) *grpc.Server {
	base := []grpc.ServerOption{
		grpc.UnknownServiceHandler(grpcproxy.TransparentHandler(director)),
	}
	return grpc.NewServer(append(base, opts...)...)
}
