FROM golang:1.25-alpine AS builder
WORKDIR /src

# Копируем зависимые модули (parent-context pattern — сборка из cloud-demo/)
COPY kacho-corelib /src/kacho-corelib
COPY kacho-proto /src/kacho-proto
COPY kacho-api-gateway /src/kacho-api-gateway

WORKDIR /src/kacho-api-gateway
RUN go mod download
RUN CGO_ENABLED=0 go build -o /api-gateway ./cmd/api-gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /api-gateway /usr/local/bin/api-gateway
USER 65532
ENTRYPOINT ["/usr/local/bin/api-gateway"]
