package proxy

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// Backends — карта «доменное имя → долгоживущий *grpc.ClientConn».
// Ключи: "resourcemanager", "vpc", "compute", "loadbalancer".
type Backends map[string]*grpc.ClientConn

// NewDirector возвращает функцию-директор для mwitkow/grpc-proxy (тип StreamDirector).
// Директор:
//  1. Блокирует *InternalService.* методы (запрет #7, CLAUDE.md).
//  2. Проверяет allowlist.
//  3. Парсит domain из полного пути метода.
//  4. Возвращает ClientConn для нужного backend.
func NewDirector(backends Backends) func(context.Context, string) (context.Context, grpc.ClientConnInterface, error) {
	return func(ctx context.Context, fullMethod string) (context.Context, grpc.ClientConnInterface, error) {
		// 1) Эшелонированная защита + allowlist
		if allowlist.HasInternalSuffix(fullMethod) || !allowlist.IsAllowed(fullMethod) {
			return nil, nil, status.Errorf(codes.NotFound, "unknown method: %s", fullMethod)
		}

		// 2) Парсим domain из пути вида "/kacho.cloud.<domain>.v1.<Service>/<Method>"
		//    parts[0] = ""
		//    parts[1] = "kacho.cloud.<domain>.v1.<Service>"
		//    parts[2] = "<Method>"
		parts := strings.SplitN(fullMethod, "/", 3)
		if len(parts) < 3 || parts[1] == "" {
			return nil, nil, status.Errorf(codes.NotFound, "malformed method path: %s", fullMethod)
		}

		// pkgParts: ["kacho", "cloud", "<domain>", "v1", "<Service>"]
		pkgParts := strings.Split(parts[1], ".")
		if len(pkgParts) < 4 {
			return nil, nil, status.Errorf(codes.NotFound, "malformed package: %s", parts[1])
		}
		domain := pkgParts[2] // "compute" | "vpc" | "resourcemanager" | "loadbalancer"

		conn, ok := backends[domain]
		if !ok {
			return nil, nil, status.Errorf(codes.Unavailable, "no backend for domain %s", domain)
		}

		// 3) Пробрасываем входящие metadata как исходящие
		md, _ := metadata.FromIncomingContext(ctx)
		outCtx := metadata.NewOutgoingContext(ctx, md.Copy())
		return outCtx, conn, nil
	}
}

