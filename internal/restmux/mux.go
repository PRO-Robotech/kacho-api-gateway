// Package restmux инициализирует grpc-gateway ServeMux для REST-запросов.
//
// ПРИМЕЧАНИЕ (sub-phase 0.6): proto-файлы kacho-proto пока НЕ содержат HTTP-аннотаций
// (google.api.http option). Это означает, что grpc-gateway не генерирует
// RegisterXxxHandlerFromEndpoint-функции, поэтому REST-маршруты не зарегистрированы
// напрямую через grpc-gateway. В результате:
//
//   - gRPC — полностью функционален (cmux + grpc-proxy).
//   - REST через /v1/... — возвращает 404 до добавления HTTP-аннотаций в proto.
//
// Для включения REST-маршрутов необходимо:
//  1. Добавить import "google/api/annotations.proto" в .proto-файлы kacho-proto.
//  2. Добавить option (google.api.http) = {...} к каждому публичному RPC.
//  3. Перегенерировать stubs с плагином protoc-gen-grpc-gateway.
//  4. Раскомментировать вызовы RegisterXxxHandlerFromEndpoint ниже.
//
// Статус: архитектурный скелет готов; REST активируется в следующей итерации (фаза 1).
package restmux

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// NewMux создаёт grpc-gateway ServeMux.
// addrs — карта domain → адрес gRPC backend (например, "compute" → "compute.kacho.svc:9090").
//
// Когда HTTP-аннотации будут добавлены в proto, раскомментировать RegisterXxx вызовы:
//
//	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
//	_ = rmv1.RegisterOrganizationServiceHandlerFromEndpoint(ctx, mux, addrs["resourcemanager"], opts)
//	_ = rmv1.RegisterCloudServiceHandlerFromEndpoint(ctx, mux, addrs["resourcemanager"], opts)
//	_ = rmv1.RegisterFolderServiceHandlerFromEndpoint(ctx, mux, addrs["resourcemanager"], opts)
//	_ = vpcv1.RegisterNetworkServiceHandlerFromEndpoint(ctx, mux, addrs["vpc"], opts)
//	_ = vpcv1.RegisterSubnetServiceHandlerFromEndpoint(ctx, mux, addrs["vpc"], opts)
//	_ = vpcv1.RegisterSecurityGroupServiceHandlerFromEndpoint(ctx, mux, addrs["vpc"], opts)
//	_ = vpcv1.RegisterRouteTableServiceHandlerFromEndpoint(ctx, mux, addrs["vpc"], opts)
//	_ = vpcv1.RegisterAddressServiceHandlerFromEndpoint(ctx, mux, addrs["vpc"], opts)
//	_ = cmpv1.RegisterInstanceServiceHandlerFromEndpoint(ctx, mux, addrs["compute"], opts)
//	_ = cmpv1.RegisterDiskServiceHandlerFromEndpoint(ctx, mux, addrs["compute"], opts)
//	_ = cmpv1.RegisterImageServiceHandlerFromEndpoint(ctx, mux, addrs["compute"], opts)
//	_ = cmpv1.RegisterSnapshotServiceHandlerFromEndpoint(ctx, mux, addrs["compute"], opts)
//	_ = lbv1.RegisterNetworkLoadBalancerServiceHandlerFromEndpoint(ctx, mux, addrs["loadbalancer"], opts)
//	_ = lbv1.RegisterTargetGroupServiceHandlerFromEndpoint(ctx, mux, addrs["loadbalancer"], opts)
//
// Итого 14 публичных сервисов. *InternalService* регистрировать НЕЛЬЗЯ (запрет #7).
func NewMux(_ context.Context, _ map[string]string) (http.Handler, error) {
	mux := runtime.NewServeMux()
	// TODO(phase-1): раскомментировать Register-вызовы после добавления HTTP-аннотаций в proto.
	return mux, nil
}
