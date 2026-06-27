# Архитектура kacho-api-gateway

Edge-прокси контрол-плейна Kachō: единый вход для gRPC и REST, аутентификация и
авторизация каждого запроса, маршрутизация в доменные backend-сервисы и изоляция
admin-поверхности. Здесь — ключевые проектные решения; обзор и быстрый старт — в
корневом [README](../../README.md).

## Листенеры и мультиплексирование

На основном порту (`:8080`) работает `cmux`: соединения с
`Content-Type: application/grpc` уходят на gRPC-сервер, остальные — на HTTP-сервер
(grpc-gateway REST + `/healthz`/`/readyz`). Опционально поднимается внешний
**TLS-листенер** (advertised для клиентов) — за ним тот же `cmux`-раскол.

Отдельный **cluster-internal gRPC-листенер** (`:9091`) обслуживает
`InternalAuthzCacheService` — см. раздел про invalidation ниже.

Принцип: тот же `http.Server` обслуживает и cluster-internal, и внешний
TLS-листенер; соединения, принятые на внешнем листенере, помечаются
(`listenerorigin`), чтобы REST-диспетчер и authz-слой могли отклонять
`Internal*`-пути, пришедшие с периметра.

## Цепочка middleware

REST-запрос проходит (снаружи внутрь):

```
RequestID → Recovery → AuthN(legacy: dev-HMAC / Kratos) → DPoP/JWT(Hydra) →
AuthZ(per-RPC Check) → AccessLog → Idempotency → REST-mux → backend
```

- **AuthN** валидирует токен/сессию и выставляет `x-kacho-principal-*`. Любые
  клиентские `x-kacho-principal-*` / `x-kacho-token-*` на входе **стрипаются** —
  identity нельзя подделать заголовком. Невалидный токен → `401` (никогда не
  понижается до anonymous).
- **DPoP** проверяет sender-constrained токены (jkt-thumbprint, htm/htu, iat-freshness,
  jti-replay с ограниченным LRU) и mTLS-bound (`cnf.x5t#S256`), затем step-up по `acr`.
- **AuthZ** строит subject+context и зовёт `AuthorizeService.Check` (OpenFGA) по
  встроенному permission-каталогу. Промах по каталогу → deny; ошибка IAM → deny
  (fail-closed; fail-open запрещён в production стартовым гейтом).

gRPC-путь применяет аналогичные интерсепторы; identity прокидывается в backend
через gRPC-metadata.

## Маршрутизация и public-vs-internal

gRPC-трафик идёт через transparent-proxy: `Resolver` (`internal/proxy/server.go`)
парсит `kacho.cloud.<domain>.v1.*`, сверяется с allowlist
(`internal/allowlist/list.go`) и возвращает нужный backend. Deny-by-default:
неизвестный метод и любой `*InternalService.*` (по `HasInternalSuffix`) не
маршрутизируются — выглядят как несуществующие.

REST построен на split-mux (`internal/restmux`): один набор handler'ов на двух
grpc-gateway `ServeMux` (различие только в JSON-маршалинге public-vs-internal).
Диспетчер по пути выбирает mux и **404-ит** `Internal*`-пути, пришедшие на внешний
листенер.

## Operations

Мутации доменов асинхронны и возвращают `Operation`. `OperationService.Get/Cancel`
обслуживается in-process (`internal/opsproxy`): по prefix id операция направляется
во владеющий backend. Watch-RPC нет — клиент поллит.

## Кэши

Все security-кэши ограничены по размеру (LRU) и TTL: JWKS, introspection,
DPoP-replay (TTL ≥ 2× окна свежести proof), authz-decision (с инвалидацией по
subject + poll-watcher + TTL-backstop), subject-cache, idempotency-store
(ограничен, ключ привязан к principal+метод+путь). Это исключает рост памяти и
делает stale-доступ ограниченным во времени.

## Готовность (readiness)

`/healthz` — liveness, всегда `200`. `/readyz` опрашивает backends и возвращает
`503` только при недоступности **критичного** backend (`iam` — он фронтит
AuthN/AuthZ на каждом запросе). Недоступность некритичного backend
(vpc/compute/geo/nlb) деградирует один домен, но не выводит всю реплику из
rotation, чтобы одно-доменный сбой не амплифицировался в полный отказ edge.

## Решение: внутренний listener инвалидации кэша (`:9091`)

`InternalAuthzCacheService.InvalidateSubject` живёт на отдельном cluster-internal
gRPC-листенере (`:9091`), **не** на внешнем TLS-endpoint (admin/internal-only). Его
вызывает push-drainer `kacho-iam`, чтобы инвалидировать authz-decision-кэш в пределах
~1 c после отзыва прав; без него единственный путь сходимости — poll-loop (~30 c).

**Текущая модель доверия — by-design, с сетевой митигацией.** Листенер не несёт
mTLS/authz-интерсепторов и полагается на сетевую изоляцию (`ClusterIP`-Service +
NetworkPolicy: dial только от pod'а iam). Это осознанный trade-off, а не упущение:

- **Blast radius — fail-safe.** Единственный экспонированный RPC только *сбрасывает*
  записи positive-кэша authz. Он не читает и не меняет tenant-данные и не может
  повысить привилегии: следующий запрос всё равно перепроверяется в IAM.
- **Худшее злоупотребление** при латеральном доступе к `:9091` — повторный сброс
  кэша (нагрузка на IAM-проверки), то есть локальный DoS, а не утечка или эскалация.

**Остаточный риск и путь усиления.** Defense-in-depth-инвариант платформы требует
mTLS+authz на каждом листенере; здесь он закрыт сетевым уровнем, но не транспортным.
Усиление (mTLS `RequireAndVerifyClientCert` на `:9091` + предъявление клиентского
сертификата drainer'ом iam) — кросс-сервисное изменение и planned-hardening; до него
полагаемся на NetworkPolicy. Включение mTLS без согласованного обновления iam сломает
путь push-инвалидации (останется корректный, но более медленный poll-fallback).
