// permission_catalog_embed.go — go:embed-driven catalog asset.
//
// Build-time bundled mirror of kacho-proto/gen/permission_catalog.json. Kept
// in this repo (vs reading the sibling kacho-proto checkout at runtime) so
// the api-gateway binary is self-contained and deployable as a single
// container without volume mounts.
//
// **Sync discipline (KAC-127 Phase 3, mirrors `make sync-migrations`)**:
//
//	cp ../kacho-proto/gen/permission_catalog.json \
//	   internal/middleware/embed/permission_catalog.json
//
// Re-run after any change to (kacho.iam.authz.v1.*) options or the
// `protoc-gen-kacho-permissions` plugin (kacho-proto Phase 3). CI verifies
// drift via `make verify-permission-catalog` (computes sha256 over the
// kacho-proto source and compares against the embedded copy).
//
// Override at runtime via env `KACHO_API_GATEWAY_PERMISSION_CATALOG_FILE` —
// useful for staged rollouts (deploy new catalog to a ConfigMap, point env
// at the mount, SIGHUP to reload) without rebuilding the image.
package middleware

import _ "embed"

// embeddedCatalogJSON — the build-time-frozen catalog used when the
// runtime override file is absent. ~30 KB for 303 entries (Phase 3).
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
