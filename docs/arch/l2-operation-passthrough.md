---
level: functionality
repo: kacho-api-gateway
anchors:
  - rpc: kacho.cloud.operation.OperationService/Get
  - rpc: kacho.cloud.operation.OperationService/Cancel
status: implemented
source_sha: ""
---

# Operation passthrough

Единственная функциональность, которую api-gateway реализует **сам** (а не
просто проксирует на доменный backend) — passthrough поллинга
long-running операций. Реализована in-process компонентом `OpsProxy`
(`internal/opsproxy`), который регистрируется как нативный gRPC-сервис на
gateway-сервере и одновременно как handler в REST split-mux.

## Зачем

Все мутирующие RPC доменов Kachō (`Create` / `Update` / `Delete` / `Move`
/ …) возвращают не ресурс, а `operation.Operation` (workspace CLAUDE.md
§Запрет #9). Клиент дальше поллит `OperationService.Get(id)` до
`done=true`.

Проблема: `Operation` живёт **per-service** — у каждого домена своя
`operations`-таблица и свой `OperationService`. Клиент же видит один общий
endpoint `/operations/{id}` и не должен знать, какой backend породил
операцию. `OpsProxy` решает это: принимает `OperationService.Get`/`Cancel`
на самом gateway и маршрутизирует вызов в нужный backend по **id-prefix**
операции (`iop…` → iam, vpc-операции → vpc, и т.д.).

## Контракт

Два RPC `kacho.cloud.operation.OperationService` (пакет `operation`, без
`v1`):

- `OperationService/Get` — sync; возвращает `Operation` по id: `done`,
  `metadata` (`Any`), `oneof result` (`response` `Any` | `error`
  `google.rpc.Status`).
- `OperationService/Cancel` — sync; запрос на отмену ещё не завершённой
  операции (best-effort, проксируется владельцу).

Обе поверхности:

- **gRPC** — `operationpb.RegisterOperationServiceServer(grpcSrv, opsProxy)`
  в `cmd/api-gateway/main.go`; запросы
  `/kacho.cloud.operation.OperationService/*` идут напрямую в `OpsProxy`,
  минуя transparent-proxy director.
- **REST** — `RegisterOperationServiceHandlerServer` на оба sub-mux'а
  `internal/restmux` (in-process, без отдельного dial).

## Маршрутизация

`OpsProxy` держит карту `domain → *grpc.ClientConn` (те же backend-conn'ы,
что и transparent-proxy). По id-prefix входящей операции выбирает backend
и форвардит `Get`/`Cancel` на его `OperationService`. Для домена
`operation` в карте — self-loopback conn на собственный `ListenAddr`
gateway (исторический артефакт YC-shim path-rewrite; сам shim удалён в
KAC-122/127).

## Gotchas

- `OperationService` — единственный RPC, обслуживаемый **in-process**:
  у него нет выделенного backend, поэтому он не проходит через
  `proxy.Resolver`/allowlist, а регистрируется нативно.
- Операции — per-service: api-gateway не агрегирует и не хранит их, только
  маршрутизирует по prefix к владельцу.
- Per-resource истории операций (`NetworkService.ListOperations`,
  `AccountService.ListOperations` и т.п.) — это RPC доменных backend'ов,
  они проксируются как обычный домен-трафик и в эту L2 не входят; здесь
  только generic `Get` / `Cancel`.
- `status: planned` / `source_sha: ""` — L3/L4 ещё не зафиксированы
  archgraph'ом на конкретном sha.

## Связанные заметки

<!-- archgraph:links -->
- ↑ Приклад: [[_l1-kacho-api-gateway]]
- ↓ Функции (call-дерево, RPC contract): [[l3-l2-operation-passthrough]]
- Переменные: [[l4-kacho-api-gateway]]
<!-- /archgraph:links -->
