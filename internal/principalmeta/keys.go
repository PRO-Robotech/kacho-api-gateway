// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package principalmeta is the single source of truth for the principal-identity
// header/metadata key contract that authorization decisions,
// operation-ownership enforcement, and principal forwarding all depend on.
//
// Producers (auth / DPoP middleware) set these on the request; consumers
// (authz, idempotency, restmux WithMetadata, opsproxy) read them. Previously
// each side re-typed the bare string literal independently, so a rename on one
// side that missed the other would compile cleanly and silently drop the
// principal at runtime (anonymous → PermissionDenied), a security-relevant break
// with no compile-time or test signal. Referencing these constants makes any
// divergence a compile error.
//
// Three surface forms exist for the SAME logical key:
//
//   - Header*      — canonical HTTP header (http.Header.Set/Get canonicalises to
//     this casing). Used by HTTP-side producers/consumers and downstream audit.
//   - HeaderGRPCMeta* — the "Grpc-Metadata-"-prefixed HTTP header. grpc-gateway
//     forwards an HTTP header `Grpc-Metadata-Foo` to the backend as gRPC
//     metadata `foo`, so producers set BOTH the bare and the prefixed header.
//   - Meta*        — the lowercase gRPC metadata key (metadata.MD is lowercased)
//     read by a backend / opsproxy via metadata.FromIncomingContext.
package principalmeta

// Canonical HTTP header names.
const (
	HeaderPrincipalType    = "X-Kacho-Principal-Type"
	HeaderPrincipalID      = "X-Kacho-Principal-Id"
	HeaderPrincipalDisplay = "X-Kacho-Principal-Display-Name"
	HeaderTokenACR         = "X-Kacho-Token-Acr"
)

// Grpc-Metadata-prefixed HTTP header names (grpc-gateway → gRPC metadata bridge).
const (
	HeaderGRPCMetaPrincipalType    = "Grpc-Metadata-" + HeaderPrincipalType
	HeaderGRPCMetaPrincipalID      = "Grpc-Metadata-" + HeaderPrincipalID
	HeaderGRPCMetaPrincipalDisplay = "Grpc-Metadata-" + HeaderPrincipalDisplay
	HeaderGRPCMetaTokenACR         = "Grpc-Metadata-" + HeaderTokenACR
)

// Lowercase gRPC metadata keys (metadata.MD.Get/Append lowercases its argument;
// backends read exactly these).
const (
	MetaPrincipalType    = "x-kacho-principal-type"
	MetaPrincipalID      = "x-kacho-principal-id"
	MetaPrincipalDisplay = "x-kacho-principal-display-name"
	MetaTokenACR         = "x-kacho-token-acr"
)

// Lowercase prefixes used to strip forgeable client-supplied identity
// headers/metadata before the gateway sets its own trusted values.
const (
	MetaPrincipalPrefix     = "x-kacho-principal-"
	MetaGRPCPrincipalPrefix = "grpc-metadata-x-kacho-principal-"
)
