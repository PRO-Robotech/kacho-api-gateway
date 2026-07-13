# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

BINARY := api-gateway
CMD    := ./cmd/api-gateway
IMAGE  := kacho-api-gateway:dev

# Permission catalog — рантайм source-of-truth для per-RPC authz-middleware.
# Генерируется ЗДЕСЬ (api-gateway импортирует proto всех доменов) скриптом
# scripts/gen-permission-catalog.sh из proto-деревьев репозиториев-владельцев
# (kacho-iam / kacho-vpc / kacho-compute / kacho-geo / kacho-nlb / kacho-registry /
# kacho-storage) + общей
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

# CI GATE: fail if the embedded catalog is STALE vs the proto surface. Catches the
# class of regression where a new/renamed RPC ships without a catalog entry → the
# per-RPC authz middleware returns "catalog: no entry for method" (AUTHZ_DENIED) at
# runtime. Requires a workspace checkout (../kacho-proto) + buf. The IAM embedded
# copy MUST byte-match this one (single source of truth) — also asserted here.
IAM_CATALOG := ../kacho-iam/internal/apps/kacho/seed/embedded/permission_catalog.json
.PHONY: permission-catalog-check
permission-catalog-check:
	./scripts/gen-permission-catalog.sh $(PERMISSION_CATALOG_BUILD)
	@diff -u $(PERMISSION_CATALOG_TARGET) $(PERMISSION_CATALOG_BUILD) \
	  || { echo "::error::permission_catalog.json (api-gateway embed) is STALE vs proto — run 'make permission-catalog-apply' + sync IAM copy, then commit"; exit 1; }
	@if [ -f $(IAM_CATALOG) ]; then diff -u $(IAM_CATALOG) $(PERMISSION_CATALOG_TARGET) \
	  || { echo "::error::IAM embedded catalog drifted from api-gateway copy — re-sync both from the regenerated catalog"; exit 1; }; fi
	@echo "permission catalog is complete and both copies are in sync."
