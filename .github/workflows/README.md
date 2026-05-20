# GitHub Actions workflows — kacho-api-gateway

## docker-build.yml — DockerHub multi-arch image build (KAC-127)

Собирает Docker-образ `kacho-api-gateway` под `linux/amd64` + `linux/arm64` и
публикует multi-arch manifest в DockerHub. Дополняет `ci.yaml` (build/vet/test/lint),
не заменяет его.

### Триггеры

- push в `main`
- push в `KAC-*` (epic / feature ветки)
- push тегов `v[0-9]+.[0-9]+.[0-9]+` и `...rc[0-9]+`

### Образы и теги

| Образ | Теги |
|---|---|
| `<DOCKERHUB_USERNAME>/kacho-api-gateway` | `<branch>-<sha8>` (multiarch), `amd64-<branch>-<sha8>`, `arm64-<branch>-<sha8>` |

`kacho-api-gateway` — gRPC-proxy + grpc-gateway REST edge.

### Требуемые GitHub secrets

| Secret | Назначение |
|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub username (он же namespace для образов) |
| `DOCKERHUB_TOKEN` | Docker Hub access token (scope: Read/Write/Delete) |

Креды одинаковые для всех `kacho-*` репозиториев (один Docker Hub-аккаунт).

### Установка secrets (user-action)

```bash
gh secret set DOCKERHUB_USERNAME --body "<value>" --repo PRO-Robotech/kacho-api-gateway
gh secret set DOCKERHUB_TOKEN    --body "<value>" --repo PRO-Robotech/kacho-api-gateway
```

### Polyrepo build

`kacho-api-gateway` — часть polyrepo: `go.mod` использует `replace ../kacho-corelib`,
`../kacho-proto`; `Dockerfile` делает `COPY kacho-corelib` / `COPY kacho-proto`.
Workflow чекаутит main-репо + siblings (`kacho-corelib`, `kacho-proto`) в один
каталог; build context = этот каталог. Siblings пиннятся к `ref: KAC-127` —
после merge зависимостей в `main` вернуть на `ref: main`.

### self-hosted runner

Job `docker-build-arm64` требует `runs-on: self-hosted` arm64-раннер. Если
arm64-раннер недоступен — образ соберётся только под amd64 (job arm64 + manifest
push зафейлятся; amd64-тег при этом валиден).

## newman-e2e.yml — self-contained newman E2E authz gate (KAC-127)

Полный Newman authz E2E (288-кейсовая default-deny матрица + 30-кейсовая
ServiceAccount/API-token матрица) гоняется **прямо в CI этого репо**: workflow
`newman-e2e.yml` поднимает реальный kind + helm umbrella-стек (Postgres + Ory +
OpenFGA + api-gateway + iam + vpc + compute) на локальном kind-кластере, сидит
shared authz-фикстуры и гоняет сьюты `kacho-iam` через REST api-gateway.

Раньше этот разрыв закрывал `newman-trigger.yml` — он слал `repository_dispatch`
в `kacho-deploy` и требовал вручную заданный PAT `WORKFLOW_DISPATCH_TOKEN`. Без
секрета job молча скипался (`guard` → `has_token=false`), и Newman фактически
не гонялся на PR. `newman-e2e.yml` **не требует никаких секретов**: весь стек
билдится и поднимается в одном job на локальном kind — authz-матрица здесь
реальный блокирующий гейт.

### Триггеры

- `pull_request` в `main`
- `push` в `main`
- `workflow_dispatch` (ручной прогон)

### Что делает

1. Checkout этого репо (ref под тестом) + sibling-репо (`kacho-deploy`,
   `kacho-corelib`, `kacho-proto`, `kacho-vpc`, `kacho-iam`, `kacho-compute`,
   `kacho-api-gateway`, `kacho-workspace`) на `ref: main` (KAC-127 смержен —
   pin снят).
2. Билд всех `kacho-*:dev` образов, `kind load`.
3. `helm install` umbrella (`values.dev.yaml`), ожидание openfga-bootstrap.
4. Сид shared authz-фикстур + прогон 2 newman-сьют (`authz-deny`,
   `authz-sa-apitoken`) через port-forward api-gateway.
5. `assert authz suites green` — fail job если хоть один assertion красный.

Тяжёлый (~15-30 мин) — отдельный workflow, не в быстром `ci.yaml`.

### Секреты

Не требуются. `kacho-ui` — приватный репо, его checkout best-effort
(`continue-on-error`), helm-чарт стабится если checkout не прошёл.

`kacho-deploy/.github/workflows/newman-e2e.yml` остаётся как есть (он
self-contained и гоняется на push/PR в сам `kacho-deploy`).
