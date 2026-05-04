// Package opsproxy реализует OpsProxy — фасад OperationService для api-gateway.
//
// Operation.id имеет 3-символьный domain-prefix (verbatim cloud-provider-API
// convention): "b1g…" → resource-manager, "enp…" → vpc, и т.д.
// OpsProxy парсит prefix → выбирает нужный backend-клиент → проксирует запрос.
// Клиент видит единый endpoint /operations/*.
//
// Маппинг префикса на backend:
//
//	"b1g" → resourcemanager   (операции по Cloud / Folder)
//	"bpf" → resourcemanager   (операции по Organization)
//	"enp" → vpc               (операции по Network / RouteTable / SecurityGroup)
//	"e9b" → vpc               (операции по Subnet / Address)
//
// Префикс заведомо стабильный: ровно 3 символа, lowercase crockford-base32-friendly.
// Тело id (17 символов) — непрозрачно для proxy.
//
// Legacy-префиксы "rm_" / "vpc_" принимаются для backward-compat (id могут
// ещё лежать в БД после переходного периода). Это handled через legacyPrefix
// fallback ниже.
package opsproxy

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
)

// prefixToBackend — карта 3-символьного префикса в имя backend-домена.
var prefixToBackend = map[string]string{
	// resource-manager domain
	"b1g": "resourcemanager", // Cloud / Folder / op-root
	"bpf": "resourcemanager", // Organization
	// vpc domain
	"enp": "vpc", // Network / RouteTable / SecurityGroup / vpc op-root
	"e9b": "vpc", // Subnet / Address
}

// legacyPrefixToBackend — старые «<service>_<uuid>» Operation.id, всё ещё
// допустимые на чтение (например, если они закешированы в долгоживущих
// клиентах). Не используется при создании новых операций.
var legacyPrefixToBackend = map[string]string{
	"rm":                  "resourcemanager",
	"resourcemanager":     "resourcemanager",
	"org":                 "resourcemanager",
	"organizationmanager": "resourcemanager",
	"vpc":                 "vpc",
}

// OpsProxy реализует operationpb.OperationServiceServer, проксируя запросы
// к конкретному backend на основе domain-prefix в Operation.id.
type OpsProxy struct {
	operationpb.UnimplementedOperationServiceServer
	// backends — карта domain → OperationServiceClient данного backend.
	backends map[string]operationpb.OperationServiceClient
}

// New создаёт OpsProxy из карты долгоживущих ClientConn-ов.
// conns — карта domain → *grpc.ClientConn (те же соединения, что и proxy.Backends).
func New(conns map[string]*grpc.ClientConn) *OpsProxy {
	clients := make(map[string]operationpb.OperationServiceClient, len(conns))
	for domain, conn := range conns {
		clients[domain] = operationpb.NewOperationServiceClient(conn)
	}
	return &OpsProxy{backends: clients}
}

// domainFromID парсит domain-prefix из Operation.id и нормализует его к
// backend-ключу.
//
// Порядок проверок:
//  1. id состоит из 20 символов и первые 3 матчатся на prefixToBackend → новый формат.
//  2. id содержит "_" и часть до "_" есть в legacyPrefixToBackend → legacy формат.
//
// Возвращает ("", false) если ни один формат не подошёл.
func domainFromID(id string) (string, bool) {
	// Новый формат: ровно 20 символов, первые 3 — prefix.
	if len(id) == 20 {
		if backend, ok := prefixToBackend[id[:3]]; ok {
			return backend, true
		}
	}
	// Legacy формат: "<prefix>_<uuid>".
	if i := strings.Index(id, "_"); i > 0 {
		legacyPrefix := id[:i]
		if backend, ok := legacyPrefixToBackend[legacyPrefix]; ok {
			return backend, true
		}
	}
	return "", false
}

// Get проксирует OperationService.Get к нужному backend по prefix id.
func (p *OpsProxy) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	domain, ok := domainFromID(req.OperationId)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "operation_id has unknown prefix: %q", req.OperationId)
	}
	client, ok := p.backends[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no backend for domain %q (operation_id=%q)", domain, req.OperationId)
	}
	return client.Get(ctx, req)
}

// Cancel проксирует OperationService.Cancel к нужному backend по prefix id.
func (p *OpsProxy) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	domain, ok := domainFromID(req.OperationId)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "operation_id has unknown prefix: %q", req.OperationId)
	}
	client, ok := p.backends[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no backend for domain %q (operation_id=%q)", domain, req.OperationId)
	}
	return client.Cancel(ctx, req)
}
