---
level: container
repo: kacho-api-gateway
---

# kacho-api-gateway — приклад

`kacho-api-gateway` — **edge-сервис** платформы Kachō: единственная точка
входа для внешних клиентов (SPA `kacho-ui`, CLI, тулинг) к доменным
backend'ам `kacho-vpc` / `kacho-iam` / `kacho-compute`. Сам по себе он
**не реализует ни одного доменного ресурса** — это прозрачный gRPC-proxy
плюс REST-фасад (grpc-gateway), authN/authZ-конвейер и набор edge-only
обвязок (OIDC-login, idempotency, request-id, recovery).

Поэтому archgraph при сканировании нашёл всего **2 entry-point'а** — это не
доменные RPC сервиса, а его собственный passthrough Operations
(`OperationService/Get` и `/Cancel`, обслуживаемые in-process `OpsProxy`).
Всё остальное, что api-gateway «умеет», — это маршруты, физически
принадлежащие backend'ам и видимые в их L2/L3.

## Зона ответственности

- **Edge-терминирование** — два слушателя на одном процессе:
  - публичный `api.kacho.local:443` (TLS-listener) — advertised endpoint для
    внешних клиентов;
  - cluster-internal listener (plaintext) — для `kacho-ui`, admin-tooling,
    port-forward.
  Каждый listener за `cmux` разделяет HTTP/2-`application/grpc` (gRPC-proxy)
  и HTTP/1.1 (grpc-gateway REST + `/healthz` `/readyz`).
- **gRPC transparent-proxy** — `proxy.Resolver` принимает нативные
  `kacho.cloud.*`-вызовы, применяет allowlist и domain-routing, форвардит на
  постоянный `ClientConn` нужного backend'а (один conn на домен,
  client-side round-robin поверх backend-pod'ов).
- **REST-фасад (grpc-gateway)** — `internal/restmux` поднимает split-mux
  (public + internal `ServeMux` с разными `EmitUnpopulated`), регистрирует
  публичные RPC всех доменов под `/vpc/v1/*` `/iam/v1/*` `/compute/v1/*` и
  kacho-only admin-сервисы (vpc AddressPool/Cloud/InternalNetwork, compute
  DiskType/Zone/Region) на их internal-портах (9091).
- **AuthN-конвейер** — dev-HMAC / Kratos session-cookie / Hydra-JWT (DPoP +
  mTLS-bound + step-up), резолв principal через `kacho-iam`
  `InternalIAMService` (gRPC-direct, в обход restmux).
- **AuthZ-конвейер** — per-RPC `AuthorizeService.Check` к `kacho-iam`
  с decision-cache; feature-gated `KACHO_API_GATEWAY_AUTHZ_ENABLED`.
- **Edge-обвязки** — OIDC login/callback/me/logout, RFC 7009 token-revocation
  (`/oauth/logout`), idempotency-store (TTL 24h), request-id, panic-recovery,
  access-log, gRPC reflection, health-агрегация по backend'ам.

**`Internal.*` не на external endpoint** (workspace CLAUDE.md §Запрет #6):
allowlist + `HasInternalSuffix` отсекают `Internal*`-методы на публичном
gRPC-proxy; `InternalIAMService.LookupSubject` вообще не регистрируется в
restmux — api-gateway зовёт `kacho-iam:9091` напрямую gRPC-клиентом.
REST-доступ к admin-`Internal*` — только через cluster-internal REST listener.

## Контракт

api-gateway собственного доменного API не имеет. Что он экспонирует:

| Поверхность | Что |
|---|---|
| Нативный gRPC-proxy | все публичные `kacho.cloud.{vpc,iam,compute}.v1.*` (allowlist) |
| REST public mux | `/vpc/v1/*`, `/iam/v1/*`, `/compute/v1/*` — публичные ресурсы доменов |
| REST internal mux | kacho-only admin: vpc AddressPool/Cloud/InternalNetwork, compute InternalDiskType/Zone/Region; cluster-internal listener only |
| `OperationService` | `Get` / `Cancel` — **собственный** in-process passthrough (`OpsProxy`), маршрутизирует операцию в backend по id-prefix |
| HTTP edge | `/healthz`, `/readyz`, OIDC `/login` `/callback` `/me` `/logout`, `/oauth/logout` |

Единственная функциональность, которую archgraph видит как принадлежащую
самому сервису, — passthrough Operations (см. [[l2-operation-passthrough]]).

## Связи

api-gateway — **корень** runtime-графа доменов: в него звонят только внешние
клиенты, он звонит вниз во все backend-домены. Обратных рёбер
(backend → api-gateway) нет.

**Кого зовёт api-gateway:**

- `→ kacho-vpc` (`:9090` public, `:9091` internal) — proxy всех VPC-RPC +
  admin AddressPool/Cloud/InternalNetwork.
- `→ kacho-compute` (`:9090` / `:9091`) — proxy Compute-RPC + admin
  DiskType/Zone/Region.
- `→ kacho-iam` (`:9090` / `:9091`) — proxy IAM-RPC; плюс **edge-only**
  прямые вызовы: `InternalIAMService.LookupSubject` (JWT → principal),
  `AuthorizeService.Check` (per-RPC authz), `InternalIAMService.PollSubjectChanges`
  (см. воркер ниже), session-revocations adapter.
- self-loopback `ClientConn` на собственный `ListenAddr` — домен `operation`
  в `OpsProxy` указывает на сам gateway (исторически нужен для path-rewrite;
  YC-shim удалён в KAC-122/127, но loopback оставлен).

**Внешние не-kacho зависимости** (runtime): Ory **Kratos** (session-cookie
auth для SPA), Ory **Hydra** (OAuth/OIDC issuer — JWKS, introspection, admin
session-kill), внешний **OIDC IdP**. Эти рёбра — runtime, не build.

## Известная деталь — фоновый воркер `cmd/api-gateway/main.go:273`

archgraph пометил `go scWatcher.Run(ctx)` на строке 273 как нераспознанный
воркер (это не RPC entry-point, поэтому его **нет** в anchors L2 —
включение туда сломало бы C1).

Это **WS-2.3 subject-change watcher** (`internal/watcher`) — фоновый
poll-loop для кросс-репликовой инвалидации authz-decision-кэша:

- Запускается только когда сконструирован `authzMW` (то есть когда
  `KACHO_API_GATEWAY_AUTHZ_ENABLED=true`).
- `clients.SubjectChangePoller` по `cfg.SubjectChangePollInterval` (default
  2s) дёргает `kacho-iam` `InternalIAMService.PollSubjectChanges` по
  возрастающему id-курсору.
- На первом успешном poll'е свежей реплики курсор «прыгает» на `headID`
  без flush'а (cache холодный — backlog `subject_change_outbox` не
  переигрывается).
- На любом непустом последующем батче — `authzMW.InvalidateCache()`:
  request-path-реплика уже само-сбросилась при мутации
  (`authz.MaybeFlushOnMutation`), а этот loop догоняет sibling-реплики в
  пределах одного интервала.
- Poll-only, без shutdown-cleanup и `WaitGroup` — завершается по отмене
  `ctx` (SIGTERM/SIGINT), флашить на выходе нечего.

То есть это не доменный воркер и не часть Operations — чисто edge-механизм
консистентности authz-кэша между репликами gateway.
