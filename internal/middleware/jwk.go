// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// jwk.go — RFC 7517 JWK parsing + RFC 7638 thumbprint computation.
//
// Used by:
//   - jwks_verifier.go — fetches Hydra JWKS, converts to crypto.PublicKey for
//     JWT signature verification.
//   - dpop.go — parses embedded `jwk` from DPoP JWT header, verifies DPoP
//     signature, computes `jkt` thumbprint for cnf.jkt match.
//
// Algorithms supported (RFC 8725 §2.1 whitelist):
//   - RS256 (RSA-PKCS1v15 + SHA-256)
//   - ES256 (ECDSA P-256 + SHA-256)
//   - EdDSA (Ed25519)
//
// Strict pinning: per-kid alg is enforced (if JWT alg ≠ JWK alg for matching
// kid → reject). `alg=none` / `HS*` hard-rejected — they never appear in this
// path because keyFunc returns ErrUnsupportedAlg before key resolution.
package middleware

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Whitelisted algorithms for asymmetric JWS verification.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

// AllowedJWTAlgs — algorithm whitelist for Hydra-issued access tokens (RFC 8725
// §2.1; algorithm-confusion mitigation).
var AllowedJWTAlgs = map[string]struct{}{
	AlgRS256: {},
	AlgES256: {},
	AlgEdDSA: {},
}

// AllowedDPoPAlgs — DPoP-specific whitelist (RFC 9449 §4.2: ES256, ES384, ES512,
// EdDSA). RS256 explicitly rejected for DPoP (larger keys → too big for header).
var AllowedDPoPAlgs = map[string]struct{}{
	AlgES256: {},
	AlgEdDSA: {},
}

// Standard sentinel errors used by jwk / jwks / dpop pipelines. Surface them
// directly to callers — they encode "invalid_token" / "invalid_dpop_proof"
// reasons we want to propagate verbatim in WWW-Authenticate headers.
var (
	ErrUnsupportedAlg     = errors.New("unsupported jws alg")
	ErrAlgMismatch        = errors.New("kid alg does not match token alg")
	ErrInvalidJWK         = errors.New("invalid jwk")
	ErrKeyNotFound        = errors.New("signing key not found in jwks")
	ErrJWKSFetchFailed    = errors.New("jwks fetch failed")
	ErrJWKSUnreachable    = errors.New("jwks endpoint unreachable")
	ErrJWKThumbprintMatch = errors.New("jwk thumbprint mismatch with cnf.jkt")
)

// JWK — minimal RFC 7517 representation of a single JSON Web Key. Only the
// fields required by the algorithms we support are decoded; unknown fields are
// silently ignored (RFC 7517 §4 forward-compat).
type JWK struct {
	Kty string `json:"kty"`           // "RSA" | "EC" | "OKP"
	Kid string `json:"kid,omitempty"` // optional key id
	Alg string `json:"alg,omitempty"` // explicit alg pinning (recommended)
	Use string `json:"use,omitempty"` // "sig" expected

	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC fields
	Crv string `json:"crv,omitempty"` // "P-256" only (we restrict)
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// OKP (Ed25519) fields — Crv="Ed25519", X=raw 32 bytes
}

// JWKSet — RFC 7517 §5 set of JWK entries.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// FindByKid returns the first JWK with matching kid. If kid is empty, returns
// the first key if and only if there is exactly one key in the set (RFC 7515
// §4.1.4 — "kid omitted" allowed only with single-key set). Otherwise returns
// ErrKeyNotFound to prevent ambiguous fallback.
func (s *JWKSet) FindByKid(kid string) (*JWK, error) {
	if s == nil || len(s.Keys) == 0 {
		return nil, ErrKeyNotFound
	}
	if kid == "" {
		if len(s.Keys) == 1 {
			return &s.Keys[0], nil
		}
		return nil, ErrKeyNotFound
	}
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], nil
		}
	}
	return nil, ErrKeyNotFound
}

// PublicKey converts the JWK to a stdlib crypto.PublicKey, validating shape.
// Returns ErrInvalidJWK on malformed fields, ErrUnsupportedAlg on unknown kty.
func (k *JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return rsaFromJWK(k)
	case "EC":
		return ecdsaFromJWK(k)
	case "OKP":
		return ed25519FromJWK(k)
	default:
		return nil, fmt.Errorf("%w: kty=%q", ErrUnsupportedAlg, k.Kty)
	}
}

// AlgForJWT returns the JWS alg this key MUST be used for (RFC 7517 §4.4 "alg"
// when present; otherwise derived from kty+crv).
func (k *JWK) AlgForJWT() string {
	if k.Alg != "" {
		return k.Alg
	}
	switch k.Kty {
	case "RSA":
		return AlgRS256
	case "EC":
		if k.Crv == "P-256" {
			return AlgES256
		}
	case "OKP":
		if k.Crv == "Ed25519" {
			return AlgEdDSA
		}
	}
	return ""
}

// Thumbprint — RFC 7638 §3 SHA-256 JWK thumbprint (base64url, no padding).
// Canonical JSON: lexicographic ordering of required members only. Required
// members per kty:
//
//	RSA → {e, kty, n}
//	EC  → {crv, kty, x, y}
//	OKP → {crv, kty, x}
//
// Returns ErrUnsupportedAlg on unknown kty.
func (k *JWK) Thumbprint() (string, error) {
	var canonical string
	switch k.Kty {
	case "RSA":
		if k.N == "" || k.E == "" {
			return "", ErrInvalidJWK
		}
		// JSON canonical: keys sorted lexicographically, no whitespace.
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "EC":
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return "", ErrInvalidJWK
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "OKP":
		if k.Crv == "" || k.X == "" {
			return "", ErrInvalidJWK
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X)
	default:
		return "", fmt.Errorf("%w: kty=%q", ErrUnsupportedAlg, k.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ParseJWKHeader decodes an embedded `jwk` JSON object from a DPoP JWT header.
// Used by dpop.go after splitting the JWT header. Returns the parsed key and
// the canonical JSON encoding (preserved for ad-hoc audit logging).
func ParseJWKHeader(raw json.RawMessage) (*JWK, error) {
	if len(raw) == 0 {
		return nil, ErrInvalidJWK
	}
	var k JWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWK, err)
	}
	if k.Kty == "" {
		return nil, ErrInvalidJWK
	}
	return &k, nil
}

// rsaFromJWK reconstructs *rsa.PublicKey from RFC 7518 §6.3.1 fields.
func rsaFromJWK(k *JWK) (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, fmt.Errorf("%w: RSA requires n,e", ErrInvalidJWK)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("%w: n base64: %v", ErrInvalidJWK, err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("%w: e base64: %v", ErrInvalidJWK, err)
	}
	// e is a small int (typically 65537), encoded as big-endian byte sequence.
	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 | int(b)
	}
	if eInt <= 0 {
		return nil, fmt.Errorf("%w: invalid RSA exponent", ErrInvalidJWK)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

// ecdsaFromJWK reconstructs *ecdsa.PublicKey from RFC 7518 §6.2.1 fields.
// Restricted to P-256 (ES256) per our alg whitelist.
func ecdsaFromJWK(k *JWK) (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("%w: only P-256 supported, got crv=%q", ErrUnsupportedAlg, k.Crv)
	}
	if k.X == "" || k.Y == "" {
		return nil, fmt.Errorf("%w: EC requires x,y", ErrInvalidJWK)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("%w: x base64: %v", ErrInvalidJWK, err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: y base64: %v", ErrInvalidJWK, err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	// Validate point is on the curve (defence-in-depth — bad JWK could embed
	// a non-curve point and bypass ECDSA security). IsOnCurve is the on-curve
	// security control here; the crypto/ecdh migration of this low-level API is
	// out of scope.
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) { //nolint:staticcheck // SA1019: explicit on-curve validation of a parsed JWK
		return nil, fmt.Errorf("%w: EC point not on P-256 curve", ErrInvalidJWK)
	}
	return pub, nil
}

// ed25519FromJWK reconstructs ed25519.PublicKey from RFC 8037 §2 fields.
func ed25519FromJWK(k *JWK) (ed25519.PublicKey, error) {
	if k.Crv != "Ed25519" {
		return nil, fmt.Errorf("%w: only Ed25519 OKP supported, got crv=%q", ErrUnsupportedAlg, k.Crv)
	}
	if k.X == "" {
		return nil, fmt.Errorf("%w: OKP requires x", ErrInvalidJWK)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("%w: x base64: %v", ErrInvalidJWK, err)
	}
	if l := len(xBytes); l != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key wrong size (%d, want %d)", ErrInvalidJWK, l, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(xBytes), nil
}
