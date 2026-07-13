#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

#
# gen-permission-catalog.sh — регенерация permission_catalog.json из proto всех
# доменов Kachō.
#
# api-gateway импортирует proto-stubs всех доменов и потому является
# единственным местом, откуда виден полный набор RPC платформы. Каталог
# permissions собирается ЗДЕСЬ (а не в общем proto-репозитории): после
# proto-децентрализации доменные .proto живут в репозиториях-владельцах
# (kacho-iam / kacho-vpc / kacho-compute / kacho-geo / kacho-nlb / kacho-registry /
# kacho-storage), а общая
# инфраструктура (operation / validation / authz_options) — в kacho-corelib.
#
# Что делает скрипт:
#   1. собирает единое buf-дерево во временном каталоге: общая инфраструктура из
#      kacho-corelib + cloud/<domain> каждого домена-владельца + anchor-файл
#      proto/kacho/iam/authz/catalog/v1/permissions_catalog_root.proto;
#   2. собирает плагин ./cmd/protoc-gen-kacho-permissions;
#   3. запускает `buf generate` со `strategy: all` — плагин получает ВЕСЬ образ
#      одним вызовом и эмитит permission_catalog.json (+ warnings-файл, если
#      какой-то RPC не аннотирован).
#
# Требует рабочую копию workspace с соседними репозиториями (../kacho-*) — это
# dev/maintenance-инструмент, а не часть рантайма (рантайм использует уже
# вшитый internal/middleware/embed/permission_catalog.json). Single-repo сборка
# (CI / Docker / опубликованный клон) каталог не регенерит — он зашит.
#
# Использование:
#   scripts/gen-permission-catalog.sh [OUTPUT_JSON]
# По умолчанию OUTPUT_JSON = build/permission_catalog.json (каталог не
# перезаписывает вшитый embed — это делает `make permission-catalog-apply`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIBLINGS="$(cd "${REPO_ROOT}/.." && pwd)"
OUT="${1:-${REPO_ROOT}/build/permission_catalog.json}"

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

STAGE="$(mktemp -d)/catalog-proto"
BIN="$(mktemp -d)"
trap 'rm -rf "${STAGE%/*}" "${BIN}"' EXIT
mkdir -p "${STAGE}/kacho/cloud" "${STAGE}/kacho/iam/authz"

# --- общая инфраструктура из kacho-corelib (БЕЗ apigateway — у него свой
#     служебный сервис, не входящий в публичный/доменный каталог) ---
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
go -C "${REPO_ROOT}" build -o "${BIN}/protoc-gen-kacho-permissions" ./cmd/protoc-gen-kacho-permissions

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
  # замыкание → пустой каталог).
  - local: protoc-gen-kacho-permissions
    out: out
    strategy: all
YAML

mkdir -p "${STAGE}/out"
( cd "${STAGE}" && PATH="${BIN}:${PATH}" buf generate )

mkdir -p "$(dirname "${OUT}")"
cp "${STAGE}/out/permission_catalog.json" "${OUT}"
if [[ -f "${STAGE}/out/permission_catalog_warnings.txt" ]]; then
  cp "${STAGE}/out/permission_catalog_warnings.txt" "$(dirname "${OUT}")/permission_catalog_warnings.txt"
  echo "WARN: часть RPC без аннотаций — см. $(dirname "${OUT}")/permission_catalog_warnings.txt" >&2
fi

n="$(grep -c '"fqn"' "${OUT}" || true)"
echo "OK: ${OUT} (${n} entries)"
