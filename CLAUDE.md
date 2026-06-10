# kacho-api-gateway — CLAUDE.md

Edge: gRPC-proxy + grpc-gateway REST-фасад для всех доменов Kachō. Базовые правила
Kachō (`.claude/rules/*`) — локальная копия, синхронизируемая из workspace
(`./sync-tooling.sh`; источник истины — `kacho-workspace/.claude/rules/`, копию здесь не
редактировать). `@import` ниже делает репо самодостаточным и при standalone-клоне.

## Базовые правила Kachō (@import — синканная копия из workspace)

@.claude/rules/00-kacho-core.md
@.claude/rules/api-conventions.md
@.claude/rules/polyrepo.md
@.claude/rules/architecture.md
@.claude/rules/data-integrity.md
@.claude/rules/security.md
@.claude/rules/git-youtrack.md
@.claude/rules/testing.md
@.claude/rules/vault.md
@.claude/rules/ai-tooling.md

## Специфика репо

- Импортирует proto-stubs всех доменов; маршрутизация по domain-prefix; OpsProxy для
  `OperationService.Get/Cancel`. REST-пути — `/<service>/v1/<resource>` (`@.claude/rules/api-conventions.md`).
- **Internal.* НЕ публикуются на external TLS endpoint** — только cluster-internal mux
  (`*InternalAddr`-блок в `internal/restmux/mux.go`); ban #6 (`@.claude/rules/security.md`).
- Регистрация нового public RPC (public mux / internal mux) — агент `api-gateway-registrar`.
- Публичный `List<Resource>` гейтится listauthz — `make audit-list-filter`.
