# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

BINARY := api-gateway
CMD    := ./cmd/api-gateway
IMAGE  := kacho-api-gateway:dev

# Permission catalog — рантайм source-of-truth для per-RPC authz-middleware.
# Генерируется ЗДЕСЬ (api-gateway импортирует proto всех доменов) скриптом
# scripts/gen-permission-catalog.sh из proto-деревьев репозиториев-владельцев
# (kacho-iam / kacho-vpc / kacho-compute / kacho-geo / kacho-nlb) + общей
# инфраструктуры kacho-corelib. Рантайм использует вшитую копию ниже.
PERMISSION_CATALOG_TARGET := internal/middleware/embed/permission_catalog.json
PERMISSION_CATALOG_BUILD  := build/permission_catalog.json

.PHONY: build test vet lint docker helm-lint permission-catalog permission-catalog-apply

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) $(CMD)

test:
	go test ./... -race -cover -timeout 300s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

docker:
	cd .. && docker build -f kacho-api-gateway/Dockerfile -t $(IMAGE) .

helm-lint:
	helm lint deploy/

# Регенерация каталога из proto всех доменов в $(PERMISSION_CATALOG_BUILD)
# (не перезаписывает вшитый embed) + diff против текущего рантайм-каталога.
# Требует рабочую копию workspace с соседними репозиториями (../kacho-*).
permission-catalog:
	./scripts/gen-permission-catalog.sh $(PERMISSION_CATALOG_BUILD)
	@echo "--- diff $(PERMISSION_CATALOG_TARGET) (embedded) vs regenerated ---"
	@diff -u $(PERMISSION_CATALOG_TARGET) $(PERMISSION_CATALOG_BUILD) || true

# Принять регенерированный каталог как новый вшитый source-of-truth.
# Осознанное действие (меняет рантайм-authz-контракт) — после ревью diff'а.
permission-catalog-apply: permission-catalog
	cp $(PERMISSION_CATALOG_BUILD) $(PERMISSION_CATALOG_TARGET)
	@echo "Applied regenerated catalog to $(PERMISSION_CATALOG_TARGET)."
