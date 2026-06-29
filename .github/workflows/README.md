# GitHub Actions workflows — kacho-api-gateway

Single-repo CI: `go.mod` тянет per-domain proto-stubs и `kacho-corelib` как
versioned-модули из GitHub (без `replace`), поэтому быстрые гейты собирают репо
самостоятельно, без checkout соседних репозиториев.

## ci.yaml — быстрый push/PR гейт

На каждый push/PR: `go build` · `go vet` · `gofmt` · `go test ./... -race` ·
`golangci-lint`. Здесь прогоняется вся unit/integration-сьюта (включая негативные
authN/authZ-пути), поэтому регрессия в trust-boundary не пройдёт незаметно.

## security-scan.yml — блокирующие supply-chain / SAST гейты

`gosec` (severity medium), `govulncheck` и `trivy` (CRITICAL/HIGH) — каждый
**блокирует** job на находке (никаких advisory-only). Версии сканеров запиннены.

## docker-build.yml — multi-arch образ в DockerHub

Собирает `kacho-api-gateway` под `linux/amd64` + `linux/arm64` одной
`buildx --push` job и публикует multi-arch manifest. Dockerfile single-repo
(`COPY . .` + `go mod download`).

Требуемые secrets:

| Secret | Назначение |
|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub username (namespace для образов) |
| `DOCKERHUB_TOKEN` | Docker Hub access token (Read/Write) |

## continuous-fuzz.yml — ночной фаззинг

`FuzzDPoPProof` и `FuzzAuthzMiddleware` гоняют реальные парсеры пользовательского
ввода (DPoP-proof валидатор, REST-роутер). Краш фейлит job и выгружает
воспроизводящий corpus-entry.

## newman-e2e.yml — full-stack authz E2E

Поднимает весь umbrella-стек (Postgres + Ory + OpenFGA + все доменные сервисы) на
локальном kind-кластере и гоняет authz-матрицы через REST api-gateway. Блокирующий
gate на push/PR в `main` (и `workflow_dispatch`). Тяжёлый (~15-30 мин) — отдельный
workflow, чтобы не замедлять быстрый `ci`. Сервисные образы собираются single-repo
(context = чекаут каждого сервиса), kacho-geo берётся published-образом.
