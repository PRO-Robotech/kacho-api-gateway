package proxy

import (
	"strings"

	"google.golang.org/grpc"

	shimproxy "github.com/PRO-Robotech/kacho-yc-shim/shimproxy"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// Resolver builds a MethodResolver for the unknown-service handler installed
// on the gRPC server. Behaviour:
//
//  1. /yandex.cloud.<rest>  — rewritten to /kacho.cloud.<rest>; then routed
//     exactly like a native /kacho.cloud.* call. This is the yc CLI compat
//     bridge; see kacho-yc-shim repo for context.
//  2. /kacho.cloud.<rest>   — passes through the same allowlist + backend
//     lookup logic that the previous director used.
//  3. anything else — Unimplemented.
//
// allowlist.HasInternalSuffix and allowlist.IsAllowed are evaluated against
// the *kacho.cloud.* path (post-rewrite for yandex calls), so adding new
// public RPCs to allowlist automatically exposes them to yc CLI as well.
func Resolver(backends Backends) shimproxy.MethodResolver {
	return func(fullMethod string) (string, grpc.ClientConnInterface, bool) {
		method := fullMethod
		if shimproxy.IsYandexMethod(fullMethod) {
			method = shimproxy.RewriteToKacho(fullMethod)
		}
		if !strings.HasPrefix(method, "/kacho.cloud.") {
			return "", nil, false
		}
		if allowlist.HasInternalSuffix(method) || !allowlist.IsAllowed(method) {
			return "", nil, false
		}
		// Parse domain from "/kacho.cloud.<domain>.<...>/<Method>".
		parts := strings.SplitN(method, "/", 3)
		if len(parts) < 3 || parts[1] == "" {
			return "", nil, false
		}
		pkgParts := strings.Split(parts[1], ".")
		if len(pkgParts) < 4 {
			return "", nil, false
		}
		conn, ok := backends[pkgParts[2]]
		if !ok {
			return "", nil, false
		}
		return method, conn, true
	}
}

// NewServer creates a gRPC server whose UnknownServiceHandler routes both
// kacho.cloud.* (native) and yandex.cloud.* (yc CLI compat) traffic to the
// appropriate backend, with method-path rewrite when needed.
//
// Native services registered on this server (Health, OperationService,
// ApiEndpointService, IamTokenService) take precedence over the unknown-service
// handler, as per gRPC dispatch semantics.
func NewServer(resolve shimproxy.MethodResolver, opts ...grpc.ServerOption) *grpc.Server {
	base := []grpc.ServerOption{
		grpc.UnknownServiceHandler(shimproxy.Handler(resolve)),
	}
	return grpc.NewServer(append(base, opts...)...)
}
