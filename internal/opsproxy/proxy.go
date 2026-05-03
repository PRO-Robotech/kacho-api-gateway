// Package opsproxy реализует OpsProxy — фасад OperationService для api-gateway.
//
// Operation.id имеет domain-prefix: "rm_<uuid>", "vpc_<uuid>", "org_<uuid>", и т.д.
// OpsProxy парсит prefix → выбирает нужный backend-клиент → проксирует запрос.
// Клиент видит единый endpoint /operations/*.
//
// Маппинг prefix → backend:
//
//	"rm_"               → resourcemanager
//	"resourcemanager_"  → resourcemanager
//	"org_"              → resourcemanager (Organization тоже на resource-manager)
//	"organizationmanager_" → resourcemanager
//	"vpc_"              → vpc
package opsproxy

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
)

// prefixToBackend нормализует domain-prefix из Operation.id к имени backend.
var prefixToBackend = map[string]string{
	"rm":               "resourcemanager",
	"resourcemanager":  "resourcemanager",
	"org":              "resourcemanager",
	"organizationmanager": "resourcemanager",
	"vpc":              "vpc",
}

// OpsProxy реализует operationpb.OperationServiceServer, проксируя запросы
// к конкретному backend на основе domain-prefix в Operation.id.
//
// domain-prefix — первый сегмент до "_" в id:
//
//	"rm_a1b2..."           → backends["resourcemanager"]
//	"resourcemanager_…"   → backends["resourcemanager"]
//	"org_…"               → backends["resourcemanager"]
//	"vpc_c3d4..."          → backends["vpc"]
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

// domainFromID парсит domain-prefix из Operation.id и нормализует его к backend-ключу.
// Формат: "<prefix>_<uuid>" → backend-ключ из prefixToBackend.
func domainFromID(id string) (string, bool) {
	parts := strings.SplitN(id, "_", 2)
	if len(parts) < 2 || parts[0] == "" {
		return "", false
	}
	backend, ok := prefixToBackend[parts[0]]
	if !ok {
		// Неизвестный prefix — пробуем как прямой backend-ключ (например "vpc_…" → "vpc").
		return parts[0], true
	}
	return backend, true
}

// Get проксирует OperationService.Get к нужному backend по prefix id.
func (p *OpsProxy) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	domain, ok := domainFromID(req.OperationId)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "operation_id must have domain prefix: %q", req.OperationId)
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
		return nil, status.Errorf(codes.InvalidArgument, "operation_id must have domain prefix: %q", req.OperationId)
	}
	client, ok := p.backends[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no backend for domain %q (operation_id=%q)", domain, req.OperationId)
	}
	return client.Cancel(ctx, req)
}
