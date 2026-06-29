// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// permission_catalog_embed.go — go:embed-driven catalog asset.
//
// Вшитая (build-time) копия permission_catalog.json. Хранится в этом репо
// (а не читается из соседних proto-деревьев в рантайме), чтобы бинарь
// api-gateway был самодостаточен и деплоился одним контейнером без
// volume-mount'ов.
//
// Источник генерации — proto всех доменов Kachō. api-gateway импортирует
// proto-stubs всех доменов, поэтому каталог собирается именно здесь
// (cmd/protoc-gen-kacho-permissions + scripts/gen-permission-catalog.sh),
// обходя service/method каждого домена-владельца (kacho-iam / kacho-vpc /
// kacho-compute / kacho-geo / kacho-nlb) + общую инфраструктуру kacho-corelib.
//
// Регенерация (требует рабочую копию workspace с соседними репозиториями):
//
//	make permission-catalog        # регенерит в build/ + показывает diff
//	make permission-catalog-apply  # принимает регенерацию как новый embed
//
// Override at runtime via env `KACHO_API_GATEWAY_PERMISSION_CATALOG_FILE` —
// useful for staged rollouts (deploy new catalog to a ConfigMap, point env
// at the mount, SIGHUP to reload) without rebuilding the image.
package middleware

import _ "embed"

// embeddedCatalogJSON — the build-time-frozen catalog used when the
// runtime override file is absent.
//
//go:embed embed/permission_catalog.json
var embeddedCatalogJSON []byte

// EmbeddedPermissionCatalogJSON returns the embedded JSON bytes. Exported
// for tests and for callers that want to inspect the raw asset without
// going through PermissionCatalog parsing.
func EmbeddedPermissionCatalogJSON() []byte {
	// Return a copy so callers can't mutate the package-level slice.
	out := make([]byte, len(embeddedCatalogJSON))
	copy(out, embeddedCatalogJSON)
	return out
}

// LoadEmbeddedPermissionCatalog returns a fully populated PermissionCatalog
// backed by the embedded JSON. Caller passes an optional fsPath to override
// with an on-disk file (ConfigMap mount); empty fsPath uses the embed.
func LoadEmbeddedPermissionCatalog(fsPath string) (*PermissionCatalog, error) {
	c := NewPermissionCatalog()
	if fsPath != "" {
		if err := c.LoadFromFile(fsPath); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err := c.LoadFromBytes(embeddedCatalogJSON); err != nil {
		return nil, err
	}
	return c, nil
}
