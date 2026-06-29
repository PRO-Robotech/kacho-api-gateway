# kacho-api-gateway

Единая точка входа (edge) контрол-плейна **Kachō**. Принимает gRPC и REST на одном
порту (`cmux` мультиплексирует HTTP/2-gRPC и HTTP/1.1-REST), аутентифицирует и
авторизует каждый запрос, после чего прозрачно проксирует его в доменный backend.

Gateway — это периметр платформы: за ним сервисы доменов (`kacho-iam`, `kacho-vpc`,
`kacho-compute`, `kacho-geo`, `kacho-nlb`) общаются только по внутренней сети. Все,
что попадает к ним снаружи, проходит здесь через единые AuthN/AuthZ и фильтр
public-vs-internal.

## Что делает gateway

- **AuthN.** Bearer-JWT, выпущенный Ory Hydra (RS256/ES256/EdDSA, проверка по JWKS:
  alg-whitelist, iss/aud/exp/nbf, ротация ключей по kid); sender-constrained токены
  **DPoP** (RFC 9449) и mTLS-bound (`cnf.x5t#S256`); session-cookie Ory Kratos для SPA;
  HMAC-токены для локальной разработки. Невалидный токен → `401`, никогда не
  понижается до anonymous. В `production-strict` анонимный доступ запрещен.
- **AuthZ.** Каждый RPC проходит per-RPC проверку прав (`AuthorizeService.Check` →
  OpenFGA) на основе встроенного permission-каталога; deny-by-default, fail-closed.
  Step-up-гейт требует нужный уровень аутентификации (`acr`) для чувствительных
  операций.
- **Identity propagation.** Клиентские заголовки `x-kacho-principal-*` /
  `x-kacho-token-*` стрипаются на входе и заново выставляются gateway только после
  валидной аутентификации — подделать identity нельзя.
- **Routing + isolation.** Запрос маршрутизируется по domain-prefix
  (`kacho.cloud.<domain>.v1.*`) в нужный backend через allowlist (deny-by-default).
  `Internal*`-сервисы (admin-поверхность) видны только на cluster-internal listener
  и недоступны на внешнем TLS-endpoint.
- **Operations.** `OperationService.Get/Cancel` обслуживается in-process (OpsProxy):
  по prefix id операция направляется во владеющий ее backend.

## Модель API

- **Ресурсы — плоские** (domain-поля на верхнем уровне; без `spec`/`status`/
  `metadata`-envelope).
- **Чтение синхронно** (`Get`/`List`), **мутации асинхронны** и возвращают
  `Operation`; клиент поллит `OperationService.Get(id)` до `done=true`. Watch-RPC нет.
- **REST** (grpc-gateway): `/<service>/v1/<resource>`, доп. действия — суффикс
  `:verb`. JSON — camelCase.

Домены за gateway: **IAM** (Account / Project / User / ServiceAccount / Group / Role /
AccessBinding), **VPC** (Network / Subnet / SecurityGroup / RouteTable / Address /
Gateway / NetworkInterface), **Compute** (Instance / Disk / Image / Snapshot / DiskType),
**Geography** (Region / Zone), **Load Balancer** (NetworkLoadBalancer / Listener /
TargetGroup).

## Быстрый старт

```bash
# Health (liveness / readiness — readiness зависит от доступности iam).
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz

# Список проектов (REST, с Bearer-токеном).
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/iam/v1/projects

# Создать сеть (async): ответ — Operation, далее поллим его статус.
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  http://localhost:8080/vpc/v1/networks \
  -d '{"projectId":"<project-id>","name":"my-net"}'

# Поллинг операции до done=true.
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/operation/v1/operations/<op-id>
```

gRPC-клиенты ходят на тот же порт (`cmux` различает по `Content-Type: application/grpc`);
видимые через reflection нативные сервисы — `OperationService` и health.

## Public vs cluster-internal

Gateway держит внешний TLS-listener (advertised для клиентов) и cluster-internal
listener (UI / admin-tooling / port-forward). `Internal*`-сервисы (например admin-CRUD
Region/Zone, AddressPool, internal-проекции ресурсов) регистрируются под
`*Internal`-адресами в `internal/restmux/mux.go` и обслуживаются **только** на
внутреннем listener. На внешнем endpoint они выглядят как несуществующие: gRPC-роутер
блокирует их по `HasInternalSuffix`, а REST-диспетчер отвечает `404`. Список публичных
методов — `internal/allowlist/list.go`; метод `*InternalService.*` в него не попадает
никогда.

## Конфигурация

Через переменные окружения (`KACHO_API_GATEWAY_*`). Основное:

| Переменная | Default | Назначение |
|---|---|---|
| `KACHO_API_GATEWAY_LISTEN_ADDR` | `:8080` | cmux listener (gRPC + REST) |
| `KACHO_API_GATEWAY_TLS_LISTEN_ADDR` | — | внешний TLS listener (пусто — выключен) |
| `KACHO_API_GATEWAY_IAM_GRPC` | `iam.kacho.svc.cluster.local:9090` | backend iam |
| `KACHO_API_GATEWAY_VPC_GRPC` | `vpc.kacho.svc.cluster.local:9090` | backend vpc |
| `KACHO_API_GATEWAY_COMPUTE_GRPC` | `compute.kacho.svc.cluster.local:9090` | backend compute |
| `KACHO_API_GATEWAY_GEO_GRPC` | `kacho-geo.kacho.svc.cluster.local:9090` | backend geo |
| `KACHO_API_GATEWAY_NLB_GRPC` | `kacho-nlb.kacho.svc.cluster.local:9090` | backend nlb |
| `KACHO_API_GATEWAY_AUTHN_MODE` | `dev` | `dev` / `production` / `production-strict` |
| `KACHO_API_GATEWAY_AUTHZ_ENABLED` | `false` | per-RPC authz-middleware |
| `KACHO_HYDRA_ISSUER` | derived | issuer/JWKS для проверки JWT |

В production-окружении (`KACHO_APP_ENV=production`) gateway **отказывается стартовать**
при authz-disabled / fail-open / неproduction-режиме authN — secure-by-default.

## Сборка, запуск, тесты

```bash
make build          # бинарь в bin/api-gateway
make test           # go test ./... -race -cover
make vet            # go vet ./...
make lint           # golangci-lint
make docker         # образ kacho-api-gateway:dev (single-repo Dockerfile)
make helm-lint      # helm lint deploy/
```

CI (`.github/workflows/`) гоняет на каждый push/PR: build · vet · gofmt · `go test -race` ·
golangci-lint, а также блокирующие security-сканы (gosec, govulncheck, trivy) и
self-contained Newman E2E на kind+helm-стенде. Ночью — continuous-fuzzing парсеров
DPoP-proof и REST-роутера.

## Структура

```
cmd/api-gateway/                 — composition root (wiring всех listener'ов и middleware)
cmd/protoc-gen-kacho-permissions — генератор permission-каталога из proto доменов
internal/middleware/             — AuthN (JWT/DPoP/mTLS/Kratos), AuthZ, кэши, OIDC, idempotency
internal/proxy/                  — gRPC transparent-proxy (Resolver + allowlist routing)
internal/restmux/                — grpc-gateway REST (public + internal split-mux)
internal/opsproxy/               — OperationService fan-out по prefix
internal/allowlist/              — deny-by-default список публичных RPC
internal/clients/                — gRPC-клиенты к iam (authorize / subject / revocations)
internal/{health,watcher,cache,config,listenerorigin,handler}
```

## Лицензия

Business Source License 1.1 — см. [LICENSE](LICENSE). Свободное использование, кроме
прямой/косвенной коммерческой выгоды; коммерческая лицензия — у Licensor (PRO-Robotech).
