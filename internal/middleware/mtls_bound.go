// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// mtls_bound.go — RFC 8705 (Mutual-TLS Client Authentication and Certificate-
// Bound Access Tokens) validator.
//
// Applies when a verified access token has `cnf.x5t#S256` set (mTLS-bound
// instead of DPoP-bound). The TLS terminator (api-gateway TLS listener)
// surfaces the client certificate via the *tls.ConnectionState; we compute
// SHA-256 of the leaf certificate's DER bytes and require an exact match to
// `cnf.x5t#S256`.
//
// Used by:
//   - Backend M2M clients (service accounts) provisioned with a static client
//     certificate + Hydra client_credentials grant; Hydra binds the issued
//     token to the cert thumbprint.
//
// SPIFFE SVID is the long-term replacement; both shapes are supported via the
// same RFC 8705 mechanism.
package middleware

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// Sentinel mTLS errors. Map to RFC 6750 `invalid_token` challenges.
var (
	ErrMTLSCertMissing   = errors.New("mtls-bound token requires client certificate")
	ErrMTLSThumbMismatch = errors.New("cnf.x5t#S256 does not match client certificate")
	ErrMTLSBadCert       = errors.New("client certificate could not be processed")
)

// MTLSBoundValidator — stateless; safe to share across requests.
type MTLSBoundValidator struct{}

// NewMTLSBoundValidator constructs a validator.
func NewMTLSBoundValidator() *MTLSBoundValidator { return &MTLSBoundValidator{} }

// Validate runs RFC 8705 verification.
//
//   - If token has no `cnf.x5t#S256` → nothing to check (caller should still
//     enforce DPoP or no-cnf bearer policy elsewhere).
//   - Otherwise: client must have presented a leaf certificate during TLS
//     handshake; SHA-256(leaf.Raw) must equal cnf.x5t#S256 (base64url-no-pad).
//
// `connState` may be nil (e.g. when behind an L4 terminator that passes the
// cert via header) — in that case `clientCert` carries the parsed cert.
// Exactly one of (connState, clientCert) should be non-nil.
func (v *MTLSBoundValidator) Validate(token *VerifiedToken, connState *tls.ConnectionState, clientCert *x509.Certificate) error {
	if token == nil {
		return errors.New("mtls validate: token is required")
	}
	if !token.Cnf.HasX5tS {
		return nil
	}
	leaf, err := resolveClientCert(connState, clientCert)
	if err != nil {
		return err
	}
	got := certThumbprint(leaf)
	if got != token.Cnf.X5tS256 {
		return ErrMTLSThumbMismatch
	}
	return nil
}

// resolveClientCert returns the leaf certificate from either the TLS conn
// state or an explicit parameter. Returns ErrMTLSCertMissing if neither
// path yields a cert.
func resolveClientCert(connState *tls.ConnectionState, explicit *x509.Certificate) (*x509.Certificate, error) {
	if explicit != nil {
		return explicit, nil
	}
	if connState == nil || len(connState.PeerCertificates) == 0 {
		return nil, ErrMTLSCertMissing
	}
	leaf := connState.PeerCertificates[0]
	if leaf == nil || len(leaf.Raw) == 0 {
		return nil, ErrMTLSBadCert
	}
	return leaf, nil
}

// certThumbprint computes base64url-no-pad SHA-256 of the raw DER bytes —
// the same definition Hydra uses when injecting cnf.x5t#S256 (RFC 8705 §3.1).
func certThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
