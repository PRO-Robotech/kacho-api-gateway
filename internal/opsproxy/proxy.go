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

// resolveBackend парсит domain-prefix из Operation.id и возвращает либо клиент
// нужного backend, либо gRPC-ошибку, как её отдал бы verbatim YC (probe 2026-05-11):
//
//   - 20-символьный id с известным kacho-prefix → роутим в backend; его NotFound
//     ("Operation X not found") пробрасываем как есть.
//   - 20-символьный id с известным kacho-prefix, но backend не подключён (defensively;
//     в prod не должно случаться) → NotFound "Operation X not found" (операции тут нет).
//   - legacy "<prefix>_<uuid>" с известным legacy-prefix → роутим.
//   - всё остальное (malformed, неизвестный prefix) → InvalidArgument
//     "invalid operation id <X>" — это поведение YC для нераспознанных id (и честно для
//     kacho: валидные operation-id у нас только enp…/e9b…/b1g…/bpf… и legacy-формы).
//
// Замечание: реальный YC на 20-символьный id с prefix чужого домена (`fhm…` = compute)
// отдаёт NotFound (он умеет туда роутить). У kacho нет тех доменов, поэтому для нас
// такой id — InvalidArgument. См. PRO-Robotech/kacho-api-gateway#2.
func (p *OpsProxy) resolveBackend(id string) (operationpb.OperationServiceClient, error) {
	invalid := status.Errorf(codes.InvalidArgument, "invalid operation id %q", id)
	notFound := status.Errorf(codes.NotFound, "Operation %s not found", id)

	var domain string
	switch {
	case len(id) == 20:
		d, ok := prefixToBackend[id[:3]]
		if !ok {
			return nil, invalid
		}
		domain = d
	default:
		i := strings.Index(id, "_")
		if i <= 0 {
			return nil, invalid
		}
		d, ok := legacyPrefixToBackend[id[:i]]
		if !ok {
			return nil, invalid
		}
		domain = d
	}

	client, ok := p.backends[domain]
	if !ok {
		// id синтаксически валиден, но соответствующий backend не подключён —
		// для клиента это «такой операции тут нет».
		return nil, notFound
	}
	return client, nil
}

// Get проксирует OperationService.Get к нужному backend по prefix id.
func (p *OpsProxy) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	client, err := p.resolveBackend(req.OperationId)
	if err != nil {
		return nil, err
	}
	return client.Get(ctx, req)
}

// Cancel проксирует OperationService.Cancel к нужному backend по prefix id.
func (p *OpsProxy) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	client, err := p.resolveBackend(req.OperationId)
	if err != nil {
		return nil, err
	}
	return client.Cancel(ctx, req)
}
