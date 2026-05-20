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

## newman-trigger.yml — cross-repo newman-e2e gate (KAC-127)

Полный Newman authz E2E (288-кейсовая default-deny матрица + 30-кейсовая
ServiceAccount/API-token матрица) живёт в `kacho-deploy/.github/workflows/newman-e2e.yml`:
поднимает реальный kind + helm umbrella-стек и гоняет сьюты через REST
api-gateway. Тот workflow триггерится только push/PR в сам `kacho-deploy`.

Но authz-код, который эти сьюты проверяют, живёт **здесь** (`kacho-api-gateway` — JWT / API-token auth-interceptor, tenant-interceptor и REST<->gRPC mux, через который проходит каждый authz-запрос).
PR в этот репо, ломающий access-matrix, иначе прошёл бы CI (`ci.yaml` гоняет
только per-service unit/integration тесты, не cross-stack authz-матрицу).

`newman-trigger.yml` закрывает этот разрыв: на каждый PR / push в `KAC-127`
он шлёт `repository_dispatch` (event type `newman-e2e`) в
`PRO-Robotech/kacho-deploy`, передавая `client_payload` `{repo, ref, sha, source}`,
затем находит запущенный run, поллит его и зеркалит conclusion — красная
authz-матрица фейлит PR здесь.

### Триггеры

- `pull_request` в `main` / `KAC-127`
- `push` в `KAC-127`
- `workflow_dispatch` (ручной прогон)

### Требуемый GitHub secret

| Secret | Назначение |
|---|---|
| `WORKFLOW_DISPATCH_TOKEN` | PAT с правом POST `repos/PRO-Robotech/kacho-deploy/dispatches` |

`GITHUB_TOKEN` по умолчанию **не может** dispatch'ить в чужой репозиторий —
нужен отдельный PAT:

- **classic PAT** — scope `repo`;
- **fine-grained PAT** — `Actions: read and write` + `Contents: read` на
  `PRO-Robotech/kacho-deploy` (а для polling статуса run'а — `Actions: read`
  на том же репо).

Если secret не задан — job фейлится сразу с понятной ошибкой (шаг
`guard — dispatch token present`), а не молча.

### Установка secret (user-action)

```bash
gh secret set WORKFLOW_DISPATCH_TOKEN --body "<pat-value>" --repo PRO-Robotech/kacho-api-gateway
```

Тот же PAT ставится во все 4 authz-репо (`kacho-iam`, `kacho-vpc`,
`kacho-compute`, `kacho-api-gateway`). Хранить значение PAT — только в GitHub
Secrets, не в коде / не в vault.

### Как newman-e2e использует payload

`kacho-deploy/newman-e2e.yml` принимает `repository_dispatch` type `newman-e2e`.
Шаг `resolve sibling refs` читает `client_payload.repo` + `.ref` и переопределяет
checkout **именно этого** sibling'а на ветку под тестом; остальные siblings
остаются на pin'е `KAC-127` — PR проверяется против интеграционной ветки всех
прочих компонентов.
