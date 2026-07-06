// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package opsproxy реализует OpsProxy — фасад OperationService для api-gateway.
//
// Operation.id имеет 3-символьный domain-prefix (конвенция Kachō): "enp…" → vpc,
// "epd…" → compute, и т.д. OpsProxy парсит prefix → выбирает нужный
// backend-клиент → проксирует запрос. Клиент видит единый endpoint /operations/*.
//
// Маппинг префикса на backend:
//
//	"enp" → vpc               (операции по Network / RouteTable / SecurityGroup)
//	"e9b" → vpc               (операции по Subnet / Address)
//	"epd" → compute           (ВСЕ операции compute-домена: Instance/Disk/Image/Snapshot —
//	                           PrefixOperationCompute == PrefixInstance, см. kacho-corelib/ids)
//	"iop" → iam               (ВСЕ операции iam-домена: Account/Project/User/SA/Group/Role/AccessBinding)
//	"nlb" → loadbalancer      (ВСЕ операции kacho-nlb: NetworkLoadBalancer/Listener/TargetGroup)
//	"rop" → registry          (ВСЕ операции kacho-registry: Registry/DeleteTag)
//
// Префикс заведомо стабильный: ровно 3 символа, lowercase crockford-base32-friendly.
// Тело id (17 символов) — непрозрачно для proxy.
//
// Legacy-префиксы вида "<service>_<uuid>" принимаются на чтение для
// backward-compat (id могут еще лежать в БД после переходного периода) —
// см. legacyPrefix fallback ниже.
package opsproxy

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// Operation-id prefixes without an exported kacho-corelib constant reachable
// from the gateway. Pinned here as named constants (not bare map literals) and
// guarded by TestPrefixToBackend_* so a divergence is a test failure, giving the
// routing table a single named source of truth per prefix:
//
//   - prefixOperationVPCSubnet ("e9b"): vpc's secondary op-prefix
//     (Subnet/Address). It exists only as a validate-package literal in
//     kacho-vpc — no exported ids.* constant yet.
//   - prefixOperationIAM ("iop"): mirrors kacho-iam domain.PrefixOperationIAM;
//     the gateway must not import kacho-iam internal packages, so it is pinned
//     here.
const (
	prefixOperationVPCSubnet = "e9b"
	prefixOperationIAM       = "iop"
)

// prefixToBackend — карта 3-символьного Operation-id префикса в имя
// backend-домена. Ключи биндятся на exported kacho-corelib константы
// (ids.PrefixOperation*) там, где они есть — единый источник истины: изменение
// префикса в corelib автоматически меняет здесь ключ (а TestPrefixToBackend_*
// ловит расхождение состава). Префиксы без corelib-константы (e9b/iop) — именные
// локальные консты выше.
var prefixToBackend = map[string]string{
	// vpc domain
	ids.PrefixOperationVPC:   "vpc", // enp: Network / RouteTable / SecurityGroup / vpc op-root
	prefixOperationVPCSubnet: "vpc", // e9b: Subnet / Address
	// compute domain
	ids.PrefixOperationCompute: "compute", // epd: все операции compute (Instance/Disk/Image/Snapshot — общий op-prefix)
	// iam domain
	prefixOperationIAM: "iam", // iop: все операции iam (Account/Project/User/SA/Group/Role/AccessBinding — общий op-prefix)
	// loadbalancer domain
	ids.PrefixOperationNLB: "loadbalancer", // nlb: все операции kacho-nlb (NetworkLoadBalancer/Listener/TargetGroup — общий op-prefix)
	// registry domain
	ids.PrefixOperationReg: "registry", // rop: все операции kacho-registry (Registry/DeleteTag)
}

// legacyPrefixToBackend — старые «<service>_<uuid>» Operation.id, все еще
// допустимые на чтение (например, если они закешированы в долгоживущих
// клиентах). Не используется при создании новых операций.
var legacyPrefixToBackend = map[string]string{
	"vpc": "vpc",
}

// OpsProxy реализует operationpb.OperationServiceServer, проксируя запросы
// к конкретному backend на основе domain-prefix в Operation.id.
type OpsProxy struct {
	operationpb.UnimplementedOperationServiceServer
	// backends — карта domain → OperationServiceClient данного backend.
	backends map[string]operationpb.OperationServiceClient
}

// New создает OpsProxy из карты долгоживущих ClientConn-ов.
// conns — карта domain → *grpc.ClientConn (те же соединения, что и proxy.Backends).
func New(conns map[string]*grpc.ClientConn) *OpsProxy {
	clients := make(map[string]operationpb.OperationServiceClient, len(conns))
	for domain, conn := range conns {
		clients[domain] = operationpb.NewOperationServiceClient(conn)
	}
	return &OpsProxy{backends: clients}
}

// resolveBackend парсит domain-prefix из Operation.id и возвращает либо клиент
// нужного backend, либо gRPC-ошибку:
//
//   - 20-символьный id с известным kacho-prefix → роутим в backend; его NotFound
//     ("Operation X not found") пробрасываем как есть.
//   - 20-символьный id с известным kacho-prefix, но backend не подключен (defensively;
//     в prod не должно случаться) → NotFound "Operation X not found" (операции тут нет).
//   - legacy "<prefix>_<uuid>" с известным legacy-prefix → роутим.
//   - все остальное (malformed, неизвестный prefix) → InvalidArgument
//     "invalid operation id <X>" — валидные operation-id у Kachō имеют только
//     известные domain-префиксы (enp…/e9b…/epd…/iop…/nlb…) и legacy-формы.
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
		// id синтаксически валиден, но соответствующий backend не подключен —
		// для клиента это «такой операции тут нет».
		return nil, notFound
	}
	return client, nil
}

// Get проксирует OperationService.Get к нужному backend по prefix id.
// После получения операции проверяет право доступа вызывающего principal'а:
// только создавший операцию (principal_type + principal_id из Operation) может
// ее читать. Исключение — внутренний system/bootstrap caller (воркеры,
// cross-service реконсайл), которому разрешено читать любую операцию.
// Incoming metadata (x-kacho-principal-* set by restmux WithMetadata) должна
// доходить до backend через outgoing-ctx — иначе backend видит анонимный
// principal и его per-RPC authz возвращает NotFound/PermissionDenied. Pattern
// такой же как в server.go (Resolver) / shimproxy.go.
func (p *OpsProxy) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	client, err := p.resolveBackend(req.OperationId)
	if err != nil {
		return nil, err
	}
	op, err := client.Get(principalmeta.OutgoingFromIncoming(ctx), req)
	if err != nil {
		return nil, err
	}
	if err := checkOperationOwnership(ctx, op); err != nil {
		return nil, err
	}
	return op, nil
}

// Cancel проксирует OperationService.Cancel к нужному backend по prefix id.
// То же ownership-check что и Get — только создавший операцию может ее
// отменить, и те же требования по metadata propagation что и для Get.
func (p *OpsProxy) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	client, err := p.resolveBackend(req.OperationId)
	if err != nil {
		return nil, err
	}
	op, err := client.Cancel(principalmeta.OutgoingFromIncoming(ctx), req)
	if err != nil {
		return nil, err
	}
	if err := checkOperationOwnership(ctx, op); err != nil {
		return nil, err
	}
	return op, nil
}

// checkOperationOwnership проверяет что principal в ctx совпадает с
// principal_type/principal_id, записанными в Operation при создании.
//
// Логика (fail-closed на публичной поверхности — порядок важен: caller-identity
// проверяется ПЕРЕД owner-полями операции, чтобы owner-less операция не стала
// world-readable, минуя anonymous/tenant-гейты):
//   - Если principal в ctx не извлекается (анонимный) — PermissionDenied.
//     (Каталог уже требует аутентификацию для OperationService через <exempt>,
//     поэтому этот case теоретически не должен дойти сюда, но мы fail-closed.)
//   - Внутренний system/bootstrap caller (воркер) — пропускаем: он может читать
//     любую операцию (cross-service polling / реконсайл), включая owner-less.
//   - С этого места caller — tenant. Операция без записанного owner'а (nil op или
//     пустой principal_id: legacy pre-owner-tracking строка) НЕ world-readable —
//     реальный owner неизвестен, поэтому tenant'у fail-closed (defense-in-depth
//     против cross-tenant BOLA — CWE-639). Внутренний system-caller (обработан
//     выше) её по-прежнему читает. Owner-less строка строго менее атрибутируема,
//     чем system-owned, поэтому денаим её как минимум так же строго.
//   - Операция, owner которой — system/bootstrap (backend без mounted
//     UnaryPrincipalExtract записывает SystemPrincipal()={type:"system",
//     id:"bootstrap"} для КАЖДОЙ Operation, т.к. corelib operations.Repo.Create
//     fall-back'ается на SystemPrincipal при отсутствии ctx-Principal): реальный
//     tenant-owner не известен, поэтому она НЕ world-readable — только внутренний
//     system-caller (обработан выше) может её прочитать. Tenant-caller →
//     PermissionDenied.
//   - Tenant owner: и principal_id, И principal_type из ctx должны совпадать с
//     записанными в Operation (type-match защищает от коллизии id между
//     principal-типами, напр. user vs service_account — CWE-863).
func checkOperationOwnership(ctx context.Context, op *operationpb.Operation) error {
	callerID, callerType := principalFromContext(ctx)
	if callerID == "" {
		// Анонимный caller — не должен читать операции.
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// system/bootstrap — внутренний воркер, не tenant. Пропускаем: он читает
	// любую операцию, включая owner-less legacy-строки.
	if callerType == "system" && callerID == "bootstrap" {
		return nil
	}
	// Далее caller — tenant. Операция без записанного owner'а не world-readable:
	// реальный owner неизвестен → fail-closed (CWE-639).
	if op == nil || op.GetPrincipalId() == "" {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// Операция с system/bootstrap owner'ом читаема только внутренним
	// system-caller'ом (обработан выше) — tenant'у fail-closed.
	if op.GetPrincipalType() == "system" && op.GetPrincipalId() == "bootstrap" {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if callerID != op.GetPrincipalId() || callerType != op.GetPrincipalType() {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// principalFromContext извлекает (id, type) calling principal из incoming
// gRPC metadata (установленных grpc-gateway через WithMetadata callback или
// gRPC-auth-interceptor).
func principalFromContext(ctx context.Context) (id, ptype string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}
	if v := md.Get(principalmeta.MetaPrincipalID); len(v) > 0 {
		id = v[0]
	}
	if v := md.Get(principalmeta.MetaPrincipalType); len(v) > 0 {
		ptype = v[0]
	}
	return id, ptype
}
