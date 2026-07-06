// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// dpop.go — RFC 9449 (OAuth 2.0 Demonstrating Proof-of-Possession at the
// Application Layer) validator.
//
// Validates a DPoP proof JWT against a previously-verified, DPoP-bound access
// token. Used by api-gateway HTTP middleware: when a request arrives with
// `Authorization: DPoP <jwt>` (RFC 9449 §7.1) AND the access token has
// `cnf.jkt` set, the DPoP header MUST be present and pass every check below.
//
// Validation steps (RFC 9449 §4.3 + §10.1 verification rules):
//
//  1. Parse JWT compact form; header MUST be {typ:"dpop+jwt", alg, jwk}.
//  2. alg ∈ {ES256, EdDSA}; reject RS256 (too big for header) / HS* / none.
//  3. Verify JWS signature using the embedded `jwk` (RFC 9449 §4.2).
//  4. Compute SHA-256 JWK thumbprint (RFC 7638) and assert it equals
//     `accessToken.cnf.jkt` (RFC 9449 §6.1). Mismatch ⇒ token theft attempt.
//  5. Assert `htm == request.Method` (case-sensitive; RFC 9449 §4.3).
//  6. Assert `htu == canonical-htu(request URL)`. Canonical form strips
//     query/fragment; lowercases scheme+host; preserves path (RFC 9449 §4.3
//     + RFC 3986 §6.2.3).
//  7. Assert `|now - iat| ≤ freshness` (default 60s).
//  8. Assert `jti` not in replay cache; insert.
//  9. If access token has `ath` claim (RFC 9449 §4.3-h), require DPoP `ath`
//     to equal `base64url(SHA-256(accessToken.Raw))`. Hydra emits `ath` for
//     DPoP-protected resources; absence is permitted (legacy clients).
//
// Errors are mapped to RFC 6750 challenge headers by the calling middleware:
//
//	WWW-Authenticate: DPoP error="invalid_dpop_proof",
//	    error_description="<sentinel-derived text>"
package middleware

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel DPoP errors. Translated by the HTTP/gRPC entrypoint into
// `invalid_dpop_proof` challenges with appropriate `error_description`.
var (
	ErrDPoPMissingHeader   = errors.New("dpop header missing")
	ErrDPoPInvalidHeader   = errors.New("dpop header malformed")
	ErrDPoPBadTyp          = errors.New("dpop typ must be dpop+jwt")
	ErrDPoPBadAlg          = errors.New("dpop alg not in {ES256, EdDSA}")
	ErrDPoPMissingJWK      = errors.New("dpop header missing jwk")
	ErrDPoPBadSignature    = errors.New("dpop signature verification failed")
	ErrDPoPHTMMismatch     = errors.New("htm claim does not match HTTP method")
	ErrDPoPHTUMismatch     = errors.New("htu claim does not match request URL")
	ErrDPoPIATFresh        = errors.New("dpop proof iat is too old or too far in the future")
	ErrDPoPMissingJTI      = errors.New("dpop missing jti")
	ErrDPoPJktMismatch     = errors.New("cnf.jkt thumbprint mismatch")
	ErrDPoPAthMismatch     = errors.New("dpop ath does not match access token hash")
	ErrDPoPRequiredButBear = errors.New("dpop required: access token has cnf.jkt but no DPoP header presented")
)

// DPoPValidator wires the replay cache and freshness window. Stateless beyond
// the replay cache → safe for use as a singleton.
type DPoPValidator struct {
	replay         *DPoPReplayCache
	iatFreshness   time.Duration
	now            func() time.Time
	requireAthWhen func(*VerifiedToken) bool // optional: ath enforcement gate
}

// DPoPValidatorConfig — construction parameters.
type DPoPValidatorConfig struct {
	ReplayCache  *DPoPReplayCache
	IatFreshness time.Duration
	Now          func() time.Time
	// RequireAthWhen — when set and returns true, an `ath` claim is mandatory
	// and must match SHA-256(accessToken.Raw). If nil, `ath` is checked only
	// when present (RFC 9449 §4.3 says ath is "RECOMMENDED" for protected
	// resources but not strictly mandatory).
	RequireAthWhen func(*VerifiedToken) bool
}

// NewDPoPValidator constructs a validator.
func NewDPoPValidator(cfg DPoPValidatorConfig) (*DPoPValidator, error) {
	if cfg.ReplayCache == nil {
		return nil, errors.New("dpop validator: ReplayCache is required")
	}
	if cfg.IatFreshness <= 0 {
		cfg.IatFreshness = 60 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &DPoPValidator{
		replay:         cfg.ReplayCache,
		iatFreshness:   cfg.IatFreshness,
		now:            now,
		requireAthWhen: cfg.RequireAthWhen,
	}, nil
}

// DPoPRequest — input bundle. Carries the HTTP method, canonical URL, and
// the DPoP header value. Pass an empty header when none was sent — the
// validator decides whether a missing header is fatal (when the access
// token is DPoP-bound) or acceptable (plain bearer token).
type DPoPRequest struct {
	Method     string // request method (POST/GET/...)
	URL        string // canonical request URL (with scheme + host)
	DPoPHeader string // raw header value (single JWT; multi-value not allowed by RFC)
}

// Validate runs the full pipeline. Returns nil on success; sentinel on any
// failure (mappable to WWW-Authenticate description).
//
// Accepts a VerifiedToken so the validator can:
//   - Skip DPoP checks if the token is not DPoP-bound (cnf.jkt absent).
//   - Compare the embedded JWK thumbprint against cnf.jkt.
//   - Optionally enforce the `ath` claim against the raw access token.
func (v *DPoPValidator) Validate(token *VerifiedToken, req DPoPRequest) error {
	if token == nil {
		return errors.New("dpop validate: token is required")
	}

	// Fast path: token is not DPoP-bound (plain bearer or mTLS-bound).
	if !token.Cnf.HasJkt {
		if req.DPoPHeader != "" {
			// Defensive: client presented a DPoP header but token is not DPoP-bound.
			// This is suspicious (could be an attempt to confuse the gateway). We
			// reject — DPoP MUST only be paired with DPoP-bound tokens (RFC 9449
			// §7.1: "if the request is authenticated with a DPoP-bound access
			// token, the DPoP proof MUST be sent"). The inverse — bearer token
			// with a DPoP header — is undefined; we treat it as invalid_dpop_proof
			// to fail closed.
			return fmt.Errorf("%w: token has no cnf.jkt", ErrDPoPInvalidHeader)
		}
		return nil
	}

	// Token IS DPoP-bound — header MUST be present.
	if req.DPoPHeader == "" {
		return ErrDPoPRequiredButBear
	}

	// 1. Split + parse header to extract embedded jwk.
	header, err := splitJWT(req.DPoPHeader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPInvalidHeader, err)
	}
	var hdr struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if jerr := json.Unmarshal(header, &hdr); jerr != nil {
		return fmt.Errorf("%w: header json: %v", ErrDPoPInvalidHeader, jerr)
	}
	if hdr.Typ != "dpop+jwt" {
		return fmt.Errorf("%w: got %q", ErrDPoPBadTyp, hdr.Typ)
	}
	if _, ok := AllowedDPoPAlgs[hdr.Alg]; !ok {
		return fmt.Errorf("%w: got %q", ErrDPoPBadAlg, hdr.Alg)
	}
	if len(hdr.JWK) == 0 {
		return ErrDPoPMissingJWK
	}
	jwk, err := ParseJWKHeader(hdr.JWK)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPInvalidHeader, err)
	}
	// Refuse jwk with private fields embedded (`d` etc.) — leak of private
	// key indicates client bug; reject to alert.
	if hasPrivateJWKFields(hdr.JWK) {
		return fmt.Errorf("%w: jwk contains private fields", ErrDPoPInvalidHeader)
	}

	// 2. Verify DPoP JWT signature against embedded jwk.
	pubKey, err := jwk.PublicKey()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPInvalidHeader, err)
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{hdr.Alg}),
		// DPoP has no exp/nbf — we do iat freshness manually.
		jwt.WithLeeway(0),
	)
	claims := jwt.MapClaims{}
	parsed, err := parser.ParseWithClaims(req.DPoPHeader, claims, func(_ *jwt.Token) (any, error) {
		return pubKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("%w: %v", ErrDPoPBadSignature, err)
	}

	// 3. Thumbprint match against cnf.jkt.
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPInvalidHeader, err)
	}
	if thumbprint != token.Cnf.Jkt {
		return ErrDPoPJktMismatch
	}

	// 4. htm validation.
	htm, _ := claims["htm"].(string)
	if htm != req.Method {
		return fmt.Errorf("%w: htm=%q method=%q", ErrDPoPHTMMismatch, htm, req.Method)
	}

	// 5. htu validation — both sides canonicalised (no query/fragment, scheme
	//    + host lower-cased, default port stripped).
	htuRaw, _ := claims["htu"].(string)
	gotHTU, err := canonicalHTU(htuRaw)
	if err != nil {
		return fmt.Errorf("%w: htu unparseable: %v", ErrDPoPHTUMismatch, err)
	}
	wantHTU, err := canonicalHTU(req.URL)
	if err != nil {
		return fmt.Errorf("%w: request url unparseable: %v", ErrDPoPHTUMismatch, err)
	}
	if gotHTU != wantHTU {
		return fmt.Errorf("%w: htu=%q want=%q", ErrDPoPHTUMismatch, gotHTU, wantHTU)
	}

	// 6. iat freshness.
	iat, ok := numericTime(claims["iat"])
	if !ok {
		return fmt.Errorf("%w: missing iat", ErrDPoPIATFresh)
	}
	now := v.now()
	diff := now.Sub(iat)
	if diff < 0 {
		diff = -diff
	}
	if diff > v.iatFreshness {
		return fmt.Errorf("%w: |now-iat|=%s threshold=%s", ErrDPoPIATFresh, diff, v.iatFreshness)
	}

	// 7. jti replay.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return ErrDPoPMissingJTI
	}
	if err := v.replay.Add(jti); err != nil {
		return err
	}

	// 8. Optional ath check.
	athClaim, hasAth := claims["ath"].(string)
	requireAth := v.requireAthWhen != nil && v.requireAthWhen(token)
	if hasAth || requireAth {
		expected := athThumbprint(token.Raw)
		if athClaim != expected {
			return ErrDPoPAthMismatch
		}
	}

	return nil
}

// canonicalHTU normalises a URL per RFC 9449 §4.3 / RFC 3986 §6.2:
//
//   - scheme + host lower-cased
//   - default-port stripped (443 for https, 80 for http)
//   - query + fragment stripped (htu does not include them)
//   - path preserved verbatim (including trailing slash sensitivity)
func canonicalHTU(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" {
		return "", errors.New("missing scheme")
	}
	if u.Host == "" {
		return "", errors.New("missing host")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	// Strip default port.
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// athThumbprint returns base64url-no-pad SHA-256 of the raw access token
// (RFC 9449 §4.3 — "ath: access token hash").
func athThumbprint(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// hasPrivateJWKFields detects `d`, `p`, `q`, `dp`, `dq`, `qi` — any of these
// in a public JWK indicates leaked private material. Reject defensively.
func hasPrivateJWKFields(raw json.RawMessage) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	for _, k := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}
