# kacho-api-gateway

Единая точка входа платформы Kachō. Принимает gRPC и REST на порту 8080 через `cmux`, прозрачно проксирует gRPC на четыре backend-сервиса через `mwitkow/grpc-proxy`, фильтрует запросы через allowlist (запрет #7 CLAUDE.md: Internal-методы не маршрутизируются).

## Быстрый старт

### gRPC (через grpcurl)

```bash
# Список организаций
grpcurl -plaintext api.kacho.local:80 \
  kacho.cloud.resourcemanager.v1.OrganizationService/List \
  -d '{}'

# Создать Instance
grpcurl -plaintext api.kacho.local:80 \
  kacho.cloud.compute.v1.InstanceService/Upsert \
  -d '{
    "instances": [{
      "metadata": {"name": "my-vm", "folderId": "<folder-uid>"},
      "spec": {
        "platformId": "standard-v3",
        "zoneId": "kacho-zone-a",
        "resources": {"cores": 2, "memory": "4Gi"},
        "bootDisk": {"diskId": "<disk-uid>"},
        "networkInterfaces": [{"subnetId": "<subnet-uid>"}],
        "desiredPowerState": "RUNNING"
      }
    }]
  }'

# Watch-стрим экземпляров
grpcurl -plaintext api.kacho.local:80 \
  kacho.cloud.compute.v1.InstanceService/Watch \
  -d '{"selectors": [], "resource_version": "0"}'
```

### REST (через curl)

REST-маршруты `/v1/...` активируются после добавления `google.api.http` аннотаций в proto-файлы (запланировано на фазу 1). До тех пор доступны только health endpoints:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

## Allowlist

Список разрешённых публичных методов — Go-константа в `internal/allowlist/list.go`. Чтобы добавить новый публичный метод:

```go
// В internal/allowlist/list.go:
var AllowedMethods = map[string]struct{}{
    // ...
    "/kacho.cloud.newdomain.v1.NewService/NewMethod": {},
}
```

**Правило:** методы `*InternalService.*` НИКОГДА не добавляются в список. Функция `HasInternalSuffix` обеспечивает эшелонированную защиту.

## Переменные окружения

| Переменная | Default | Описание |
|---|---|---|
| `KACHO_API_GATEWAY_LISTEN_ADDR` | `:8080` | Адрес cmux listener |
| `KACHO_RESOURCE_MANAGER_GRPC` | `resource-manager.kacho.svc.cluster.local:9090` | Адрес resource-manager backend |
| `KACHO_VPC_GRPC` | `vpc.kacho.svc.cluster.local:9090` | Адрес vpc backend |
| `KACHO_COMPUTE_GRPC` | `compute.kacho.svc.cluster.local:9090` | Адрес compute backend |
| `KACHO_LOADBALANCER_GRPC` | `loadbalancer.kacho.svc.cluster.local:9090` | Адрес loadbalancer backend |

## Архитектура

```
Client (gRPC / REST)
    │ :8080
    ▼
cmux (soheilhy/cmux)
    ├── Content-Type: application/grpc  ──▶  gRPC Server
    │                                         │ mwitkow/grpc-proxy
    │                                         │ allowlist filter
    │                                         └──▶ backend:9090
    └── HTTP/1.1 / h2c REST           ──▶  HTTP Server
                                              ├── /healthz  (liveness)
                                              ├── /readyz   (readiness, checks backends)
                                              └── grpc-gateway mux (REST, фаза 1)
```

## Примечание о REST

Proto-файлы `kacho-proto` пока не содержат HTTP-аннотаций (`google.api.http` option). Grpc-gateway ServeMux инициализируется, но маршруты `/v1/...` возвращают 404. Для активации REST необходимо:

1. Добавить `import "google/api/annotations.proto"` и `option (google.api.http)` к публичным RPC в `kacho-proto`.
2. Перегенерировать stubs с плагином `protoc-gen-grpc-gateway`.
3. Раскомментировать `RegisterXxxHandlerFromEndpoint` вызовы в `internal/restmux/mux.go`.

## Сборка

```bash
# Локальная
make build

# Docker (parent-context — запускать из cloud-demo/)
make docker

# Тесты
make test

# Helm lint
make helm-lint
```
