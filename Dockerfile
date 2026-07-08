# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Single-repo build: зависимости (kacho-corelib + proto-stubs доменов
# kacho-compute/geo/iam/nlb/vpc) тянутся как versioned-модули из GitHub
# (go.mod без replace), build-context — этот репо.
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /api-gateway ./cmd/api-gateway

FROM mirror.gcr.io/library/alpine:3.20
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /api-gateway /usr/local/bin/api-gateway
USER 65532
ENTRYPOINT ["/usr/local/bin/api-gateway"]
