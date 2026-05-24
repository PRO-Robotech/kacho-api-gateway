BINARY := api-gateway
CMD    := ./cmd/api-gateway
IMAGE  := kacho-api-gateway:dev

# Permission catalog — runtime source-of-truth (see kacho-workspace
# docs/architecture/09-permission-catalog-source-of-truth.md). Phase 1 manual.
# Phase 3 (auto-gen via kacho-proto/gen/) → uncomment the cp line below.
PERMISSION_CATALOG_TARGET := internal/middleware/embed/permission_catalog.json
PERMISSION_CATALOG_SOURCE := ../kacho-proto/gen/permission_catalog.json

.PHONY: build test vet lint docker helm-lint sync-permission-catalog

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) $(CMD)

test:
	go test ./... -race -cover -timeout 300s

vet:
	go vet ./...

lint:
	golangci-lint run ./... || true

docker:
	cd .. && docker build -f kacho-api-gateway/Dockerfile -t $(IMAGE) .

helm-lint:
	helm lint deploy/

# Sync permission_catalog.json from kacho-proto/gen (Phase 3, KAC-127 §6.9.3).
# Phase 1 (current): source is hand-maintained in $(PERMISSION_CATALOG_TARGET);
# this target fails fast if Phase-3 generator output is missing — that's the
# signal to keep doing manual edits + PR review.
sync-permission-catalog:
	@if [ ! -f $(PERMISSION_CATALOG_SOURCE) ]; then \
		echo "ERR: $(PERMISSION_CATALOG_SOURCE) not found — Phase 3 generator not yet shipped."; \
		echo "Edit $(PERMISSION_CATALOG_TARGET) by hand for now (see kacho-workspace docs/architecture/09-permission-catalog-source-of-truth.md)."; \
		exit 1; \
	fi
	cp $(PERMISSION_CATALOG_SOURCE) $(PERMISSION_CATALOG_TARGET)
	@echo "Synced catalog from $(PERMISSION_CATALOG_SOURCE)."
