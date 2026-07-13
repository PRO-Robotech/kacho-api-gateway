#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

#
# gen-rest-route-table.sh — регенерация internal/middleware/rest_route_table_gen.go
# из аннотаций `option (google.api.http)` proto всех доменов Kachō.
#
# api-gateway импортирует proto-stubs всех доменов и потому является
# единственным местом, откуда виден полный набор REST-биндингов платформы.
# Таблица path->FQN собирается ЗДЕСЬ (не в доменных репозиториях): после
# proto-децентрализации доменные .proto живут в репозиториях-владельцах
# (kacho-iam / kacho-vpc / kacho-compute / kacho-geo / kacho-nlb /
# kacho-registry / kacho-storage), а общая инфраструктура (operation / validation)
# — в kacho-corelib.
#
# Что делает скрипт (то же дерево, что gen-permission-catalog.sh):
#   1. собирает единое buf-дерево во временном каталоге: общая инфраструктура из
#      kacho-corelib + cloud/<domain> каждого домена-владельца + anchor-файл
#      permissions_catalog_root.proto;
#   2. собирает плагин ./cmd/protoc-gen-kacho-rest-routes;
#   3. запускает `buf generate` со `strategy: all` — плагин получает ВЕСЬ образ
#      одним вызовом и эмитит rest_route_table_gen.go;
#   4. прогоняет gofmt и кладет результат в internal/middleware/.
#
# Требует рабочую копию workspace с соседними репозиториями (../kacho-*) — это
# dev/maintenance-инструмент, а не часть рантайма (рантайм использует уже вшитую
# таблицу). Идемпотентен: повторный прогон без изменений proto дает нулевой diff.
#
# Использование:
#   scripts/gen-rest-route-table.sh [OUTPUT_GO]
# По умолчанию OUTPUT_GO = internal/middleware/rest_route_table_gen.go.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIBLINGS="$(cd "${REPO_ROOT}/.." && pwd)"
OUT="${1:-${REPO_ROOT}/internal/middleware/rest_route_table_gen.go}"

# Proto централизован в kacho-proto (per-service .proto упразднены); все домены
# читаются из единого ../kacho-proto/proto (симметрично gen-permission-catalog.sh).
CORELIB="${SIBLINGS}/kacho-proto/proto"
IAM="${SIBLINGS}/kacho-proto/proto"
VPC="${SIBLINGS}/kacho-proto/proto"
COMPUTE="${SIBLINGS}/kacho-proto/proto"
GEO="${SIBLINGS}/kacho-proto/proto"
NLB="${SIBLINGS}/kacho-proto/proto"
REGISTRY="${SIBLINGS}/kacho-proto/proto"
STORAGE="${SIBLINGS}/kacho-proto/proto"

for d in "${CORELIB}" "${IAM}" "${VPC}" "${COMPUTE}" "${GEO}" "${NLB}" "${REGISTRY}" "${STORAGE}"; do
  if [[ ! -d "${d}" ]]; then
    echo "ERR: proto-дерево не найдено: ${d}" >&2
    echo "Нужна рабочая копия workspace с соседними репозиториями (../kacho-*)." >&2
    exit 1
  fi
done
command -v buf >/dev/null || { echo "ERR: buf не установлен" >&2; exit 1; }

STAGE="$(mktemp -d)/routes-proto"
BIN="$(mktemp -d)"
trap 'rm -rf "${STAGE%/*}" "${BIN}"' EXIT
mkdir -p "${STAGE}/kacho/cloud" "${STAGE}/kacho/iam/authz"

# --- общая инфраструктура из kacho-corelib (БЕЗ apigateway — служебный сервис,
#     не входящий в публичный/доменный набор REST-биндингов) ---
cp -R "${CORELIB}/google"                       "${STAGE}/google"
cp -R "${CORELIB}/kacho/cloud/operation"        "${STAGE}/kacho/cloud/operation"
cp    "${CORELIB}/kacho/cloud/validation.proto" "${STAGE}/kacho/cloud/validation.proto"
cp -R "${CORELIB}/kacho/cloud/api"              "${STAGE}/kacho/cloud/api"
cp -R "${CORELIB}/kacho/iam/authz/v1"           "${STAGE}/kacho/iam/authz/v1"

# --- доменные деревья из репозиториев-владельцев ---
cp -R "${IAM}/kacho/cloud/iam"             "${STAGE}/kacho/cloud/iam"
cp -R "${VPC}/kacho/cloud/vpc"             "${STAGE}/kacho/cloud/vpc"
cp -R "${VPC}/kacho/cloud/reference"       "${STAGE}/kacho/cloud/reference"
cp -R "${COMPUTE}/kacho/cloud/compute"     "${STAGE}/kacho/cloud/compute"
cp -R "${COMPUTE}/kacho/cloud/access"      "${STAGE}/kacho/cloud/access"
cp -R "${COMPUTE}/kacho/cloud/maintenance" "${STAGE}/kacho/cloud/maintenance"
cp -R "${GEO}/kacho/cloud/geo"             "${STAGE}/kacho/cloud/geo"
cp -R "${NLB}/kacho/cloud/loadbalancer"    "${STAGE}/kacho/cloud/loadbalancer"
cp -R "${REGISTRY}/kacho/cloud/registry"   "${STAGE}/kacho/cloud/registry"
cp -R "${STORAGE}/kacho/cloud/storage"     "${STAGE}/kacho/cloud/storage"

# --- anchor-файл плагина (primary file) ---
mkdir -p "${STAGE}/kacho/iam/authz/catalog/v1"
cp "${REPO_ROOT}/proto/kacho/iam/authz/catalog/v1/permissions_catalog_root.proto" \
   "${STAGE}/kacho/iam/authz/catalog/v1/permissions_catalog_root.proto"

# --- сборка плагина ---
go -C "${REPO_ROOT}" build -o "${BIN}/protoc-gen-kacho-rest-routes" ./cmd/protoc-gen-kacho-rest-routes

# --- buf-конфиг во временном дереве ---
cat > "${STAGE}/buf.yaml" <<'YAML'
version: v2
modules:
  - path: .
YAML
cat > "${STAGE}/buf.gen.yaml" <<'YAML'
version: v2
plugins:
  # strategy: all — плагину подается ВЕСЬ образ одним вызовом (иначе buf по
  # умолчанию дробит генерацию по директориям и primary-файл получает пустое
  # замыкание -> пустая таблица).
  - local: protoc-gen-kacho-rest-routes
    out: out
    strategy: all
YAML

mkdir -p "${STAGE}/out"
( cd "${STAGE}" && PATH="${BIN}:${PATH}" buf generate )

# Плагин уже прогоняет go/format; повторный gofmt — дешевая страховка.
gofmt -w "${STAGE}/out/rest_route_table_gen.go"

mkdir -p "$(dirname "${OUT}")"
cp "${STAGE}/out/rest_route_table_gen.go" "${OUT}"

n="$(grep -c 'Method:' "${OUT}" || true)"
echo "OK: ${OUT} (${n} routes)"
