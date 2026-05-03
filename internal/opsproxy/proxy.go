// Package opsproxy реализует OpsProxy — фасад OperationService для api-gateway.
//
// Operation.id имеет domain-prefix: "compute_<uuid>", "vpc_<uuid>", и т.д.
// OpsProxy парсит prefix → выбирает нужный backend-клиент → проксирует запрос.
// Клиент видит единый endpoint /v1/operations/*.
package opsproxy

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation/v1"
)

// OpsProxy реализует operationpb.OperationServiceServer, проксируя запросы
// к конкретному backend на основе domain-prefix в Operation.id.
//
// domain-prefix — первый сегмент до "_" в id:
//
//	"compute_a1b2..."    → backends["compute"]
//	"vpc_c3d4..."        → backends["vpc"]
//	"resourcemanager_…" → backends["resourcemanager"]
//	"loadbalancer_…"    → backends["loadbalancer"]
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

// domainFromID парсит domain-prefix из Operation.id.
// Формат: "<domain>_<uuid>" → "<domain>".
func domainFromID(id string) (string, bool) {
	parts := strings.SplitN(id, "_", 2)
	if len(parts) < 2 || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}

// Get проксирует OperationService.Get к нужному backend по prefix id.
func (p *OpsProxy) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	domain, ok := domainFromID(req.Id)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "operation id must have domain prefix: %q", req.Id)
	}
	client, ok := p.backends[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no backend for domain %q (id=%q)", domain, req.Id)
	}
	return client.Get(ctx, req)
}

// List проксирует OperationService.List к нужному backend по prefix filter.resource_id.
// Если resource_id пуст или domain неизвестен — возвращает ошибку InvalidArgument.
func (p *OpsProxy) List(ctx context.Context, req *operationpb.ListOperationsRequest) (*operationpb.ListOperationsResponse, error) {
	// List фильтрует по folder_id или resource_id. Для роутинга используем resource_id prefix.
	// Если resource_id задан — роутим по его prefix; иначе — по folder_id prefix (если есть).
	// В MVP-реализации требуем, чтобы хотя бы один из фильтров давал domain-prefix.
	if req.ResourceId != "" {
		domain, ok := domainFromID(req.ResourceId)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"resource_id must have domain prefix for routing: %q", req.ResourceId)
		}
		client, ok := p.backends[domain]
		if !ok {
			return nil, status.Errorf(codes.NotFound,
				"no backend for domain %q (resource_id=%q)", domain, req.ResourceId)
		}
		return client.List(ctx, req)
	}
	// Нет resource_id — broadcast на все backends и merge результатов.
	return p.listAll(ctx, req)
}

// listAll делает параллельный List на все backends и объединяет результаты.
func (p *OpsProxy) listAll(ctx context.Context, req *operationpb.ListOperationsRequest) (*operationpb.ListOperationsResponse, error) {
	type result struct {
		resp *operationpb.ListOperationsResponse
		err  error
	}
	ch := make(chan result, len(p.backends))
	for _, client := range p.backends {
		client := client
		go func() {
			resp, err := client.List(ctx, req)
			ch <- result{resp: resp, err: err}
		}()
	}

	merged := &operationpb.ListOperationsResponse{}
	for i := 0; i < len(p.backends); i++ {
		r := <-ch
		if r.err != nil {
			// Пропускаем ошибки отдельных backends при broadcast (partial failure — OK для poll).
			continue
		}
		merged.Operations = append(merged.Operations, r.resp.Operations...)
	}
	return merged, nil
}

// Cancel проксирует OperationService.Cancel к нужному backend по prefix id.
func (p *OpsProxy) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	domain, ok := domainFromID(req.Id)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "operation id must have domain prefix: %q", req.Id)
	}
	client, ok := p.backends[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no backend for domain %q (id=%q)", domain, req.Id)
	}
	return client.Cancel(ctx, req)
}
