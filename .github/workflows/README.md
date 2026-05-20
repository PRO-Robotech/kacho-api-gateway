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
