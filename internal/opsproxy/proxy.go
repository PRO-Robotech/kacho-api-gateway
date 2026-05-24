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
//	"epd" → compute           (ВСЕ операции compute-домена: Instance/Disk/Image/Snapshot —
//	                           PrefixOperationCompute == PrefixInstance, см. kacho-corelib/ids)
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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
)

// prefixToBackend — карта 3-символьного префикса в имя backend-домена.
// KAC-124: префиксы `b1g` / `bpf` (resource-manager) удалены — backend упразднён.
// KAC-161: добавлен `nlb` (PrefixOperationNLB == PrefixLoadBalancer в kacho-corelib/ids)
// → loadbalancer backend (kacho-nlb).
var prefixToBackend = map[string]string{
	// vpc domain
	"enp": "vpc", // Network / RouteTable / SecurityGroup / vpc op-root
	"e9b": "vpc", // Subnet / Address
	// compute domain
	"epd": "compute", // все операции compute (Instance/Disk/Image/Snapshot — общий op-prefix)
	// iam domain
	"iop": "iam", // все операции iam (Account/Project/User/SA/Group/Role/AccessBinding — общий op-prefix, KAC-105)
	// loadbalancer domain (KAC-161)
	"nlb": "loadbalancer", // все операции kacho-nlb (NetworkLoadBalancer/Listener/TargetGroup — общий op-prefix)
}

// legacyPrefixToBackend — старые «<service>_<uuid>» Operation.id, всё ещё
// допустимые на чтение (например, если они закешированы в долгоживущих
// клиентах). Не используется при создании новых операций.
// KAC-124: rm/resourcemanager/org/organizationmanager удалены — backend упразднён.
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
// KAC-127: после получения операции проверяет право доступа вызывающего
// principal'а: только создавший операцию (principal_type + principal_id
// из Operation) может её читать. Исключение — system-bootstrap (внутренние
// воркеры) и service-account (cross-service polling).
// KAC-169: incoming metadata (x-kacho-principal-* set by restmux WithMetadata)
// должна доходить до backend через outgoing-ctx — иначе backend видит
// анонимный principal и его per-RPC authz возвращает NotFound/PermissionDenied.
// Pattern такой же как в internal/proxy/director.go / shimproxy.go.
func (p *OpsProxy) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	client, err := p.resolveBackend(req.OperationId)
	if err != nil {
		return nil, err
	}
	op, err := client.Get(propagateMetadata(ctx), req)
	if err != nil {
		return nil, err
	}
	if err := checkOperationOwnership(ctx, op); err != nil {
		return nil, err
	}
	return op, nil
}

// Cancel проксирует OperationService.Cancel к нужному backend по prefix id.
// KAC-127: то же ownership-check что и Get — только создавший операцию
// может её отменить.
// KAC-169: те же требования по metadata propagation что и для Get.
func (p *OpsProxy) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	client, err := p.resolveBackend(req.OperationId)
	if err != nil {
		return nil, err
	}
	op, err := client.Cancel(propagateMetadata(ctx), req)
	if err != nil {
		return nil, err
	}
	if err := checkOperationOwnership(ctx, op); err != nil {
		return nil, err
	}
	return op, nil
}

// propagateMetadata конвертирует incoming gRPC metadata в outgoing для
// последующего вызова backend. Если incoming metadata отсутствует — возвращает
// ctx как есть (не оборачиваем пустым MD, чтобы downstream interceptor'ы
// видели «нет metadata» а не «есть пустая metadata»).
//
// KAC-169: тот же pattern что в internal/proxy/director.go:55-56 и
// internal/proxy/shimproxy.go:44-45 — все cross-process gRPC hops в gateway
// обязаны это делать, иначе principal/request-id headers теряются.
func propagateMetadata(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, md.Copy())
}

// checkOperationOwnership проверяет что principal в ctx совпадает с
// principal_type/principal_id, записанными в Operation при создании.
//
// Логика:
//   - Если op не содержит principal_id (legacy / pre-KAC-105 операции) —
//     пропускаем проверку (graceful degradation для старых записей в БД).
//   - Если principal в ctx не извлекается (анонимный) — PermissionDenied.
//     (Каталог уже требует аутентификацию для OperationService через <exempt>,
//     поэтому этот case теоретически не должен дойти сюда, но мы fail-closed.)
//   - system/bootstrap — пропускаем (внутренние воркеры и тесты, не tenant).
//   - Остальные: principal_id из ctx должен совпадать с op.PrincipalId.
//     principal_type — для доп. верификации (user/service_account).
func checkOperationOwnership(ctx context.Context, op *operationpb.Operation) error {
	if op == nil || op.GetPrincipalId() == "" {
		// Операция без записанного owner'а (legacy) — пропускаем.
		return nil
	}
	// KAC-178 §2 follow-up: pre-W1.4 backend без mounted UnaryPrincipalExtract
	// записывал SystemPrincipal()={type:"system", id:"bootstrap"} как owner
	// для каждой Operation, потому что corelib operations.Repo.Create fall-back'ался
	// на SystemPrincipal при отсутствии ctx-Principal. Эти записи — legacy
	// в том же смысле что и principal_id="" — реальный owner не известен,
	// нельзя ограничивать чтение конкретным user'ом. Treat as legacy → pass.
	if op.GetPrincipalType() == "system" && op.GetPrincipalId() == "bootstrap" {
		return nil
	}
	callerID, callerType := principalFromContext(ctx)
	if callerID == "" {
		// Анонимный caller — не должен читать операции.
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	// system/bootstrap — внутренний воркер, не tenant. Пропускаем.
	if callerType == "system" && callerID == "bootstrap" {
		return nil
	}
	if callerID != op.GetPrincipalId() {
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
	if v := md.Get("x-kacho-principal-id"); len(v) > 0 {
		id = v[0]
	}
	if v := md.Get("x-kacho-principal-type"); len(v) > 0 {
		ptype = v[0]
	}
	return id, ptype
}
