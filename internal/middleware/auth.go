// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package middleware — auth.go: JWT validation + Principal injection.
//
// Поведение зависит от cfg.AuthN.Mode.
//
// Две стратегии валидации Bearer, выбираются по `alg` в JWT-хедере:
//   - **HMAC-dev** (HS256, `KACHO_API_GATEWAY_AUTHN_DEV_SECRET`) — dev/e2e токены.
//     Работает **только в mode=dev**: в production / production-strict эта
//     симметричная стратегия ОТКЛЮЧЕНА (SEC — symmetric-key principal forgery,
//     CWE-347), даже если dev-secret задан. Валидно-подписанный HS256 токен в
//     prod → reject Unauthenticated (единственная принятая стратегия — Hydra JWKS).
//   - **Hydra JWKS** (RS256/ES256/EdDSA, `WithVerifier`) — реальные login-токены;
//     principal берется из верифицированных `kacho_principal_*` claims (top-level
//     или `ext_claims`), SubjectLookuper — fallback только при их отсутствии.
//
// Per-mode:
//   - **dev** (default): backwards-compat. Без Bearer — pass-through anonymous
//     (Principal{system, anonymous}). С Bearer — валидируется (HMAC-dev ИЛИ Hydra
//     JWKS по alg); HMAC-subject (external_id) не найден в kacho_iam → fallback на
//     anonymous, чтобы не ломать существующие newman-сценарии. Bad token (любая
//     стратегия) → reject Unauthenticated, НИКОГДА anonymous.
//   - **production**: Subject lookup → kacho-iam; NotFound → reject.
//   - **production-strict**: Bearer обязателен **всегда** (`Unauthenticated`
//     без него); все остальные правила — как в production.
//
// Архитектура:
//
//	┌─ parse Bearer ─┐    ┌─ JWT validate ─┐    ┌─ SubjectLookup ─┐    ┌─ Principal in ctx ─┐
//	│ Authorization │ → │ JWKS/HMAC      │ → │ kacho-iam:9091  │ → │ x-kacho-principal-* │
//	└────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────────┘
//
// Loop-prevention: InternalIAMService.LookupSubject зовется **gRPC-direct**
// (через iamSubjectClient), НЕ через restmux, иначе recursion.
package middleware

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// AuthMode — режим работы auth-interceptor'а.
type AuthMode string

const (
	AuthModeDev              AuthMode = "dev"
	AuthModeProduction       AuthMode = "production"
	AuthModeProductionStrict AuthMode = "production-strict"
)

// authFailedMsg is the single, constant client-visible message for every
// authN-failure returned by the gRPC interceptor. It deliberately does NOT
// echo backend/JWT error detail (info-exposure, CWE-209) and does NOT vary by
// whether the token was malformed vs the subject was unprovisioned — a varying
// message is a provisioned-subject enumeration oracle (CWE-204). The detailed
// cause is logged server-side only (mirrors the redaction already done in
// authz.go). The REST path uses its own fixed strings via writeHTTPUnauthorized.
const authFailedMsg = "authentication failed"

// SubjectLookuper — port-интерфейс для subject-резолва. Реализация —
// `internal/clients/iam_subject_client.go` (gRPC-direct к kacho-iam:9091).
// Декларирован тут, чтобы не тащить proto-dep в middleware (Clean
// Architecture — handler/middleware layer).
type SubjectLookuper interface {
	LookupByExternalID(ctx context.Context, externalID string) (Subject, error)
}

// KratosSubjectLookuper — опциональное расширение SubjectLookuper для Kratos
// session-flow: при NotFound делает lazy-upsert User mirror'а через
// InternalUserService.UpsertFromIdentity.
type KratosSubjectLookuper interface {
	LookupOrUpsertFromKratos(ctx context.Context, identityID, email, displayName string) (Subject, error)
}

// Subject — резолвленный subject (User или ServiceAccount).
type Subject struct {
	Type        string // "user" | "service_account"
	ID          string
	DisplayName string
}

// TokenVerifier — port для JWKS-валидации Hydra-issued RS256 access JWT.
// Реализация — `*JWTVerifier` (jwt_verifier.go), уже сконструированная
// в cmd/main.go для DPoP; тот же инстанс переиспользуется в principal-path.
// Декларирован интерфейсом, чтобы AuthInterceptor не был жестко привязан к
// конкретному типу (тестируемость + Clean Architecture).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*VerifiedToken, error)
}

// AuthInterceptor — JWT validate + subject lookup + Principal injection.
type AuthInterceptor struct {
	mode          AuthMode
	devSecret     []byte // HMAC-secret для mode=dev (если пуст — Bearer reject в dev/production-strict).
	subjectLookup SubjectLookuper
	kratos        *KratosClient // optional Ory Kratos /whoami client (nil → disabled)
	verifier      TokenVerifier // JWKS-валидатор Hydra RS256 access JWT (nil → disabled, HMAC-only)
	mtlsPrincipal bool          // derive Principal from a verified client cert (hybrid external listener)
	logger        *slog.Logger

	// Headers, которые auth-interceptor пропускает в backend metadata
	// (после успешного auth). Backend через corelib `grpcsrv.PrincipalExtractInterceptor`
	// прочитает их в ctx.
	mdKeyPrincipalType    string // principalmeta.MetaPrincipalType
	mdKeyPrincipalID      string // principalmeta.MetaPrincipalID
	mdKeyPrincipalDisplay string // principalmeta.MetaPrincipalDisplay
}

// NewAuthInterceptor создает interceptor с настройками из конфига.
func NewAuthInterceptor(mode AuthMode, devSecret string, lookup SubjectLookuper, logger *slog.Logger) *AuthInterceptor {
	return &AuthInterceptor{
		mode:                  mode,
		devSecret:             []byte(devSecret),
		subjectLookup:         lookup,
		logger:                logger,
		mdKeyPrincipalType:    principalmeta.MetaPrincipalType,
		mdKeyPrincipalID:      principalmeta.MetaPrincipalID,
		mdKeyPrincipalDisplay: principalmeta.MetaPrincipalDisplay,
	}
}

// WithKratos подключает Kratos /whoami client.
// Если выставлено, HTTP middleware сначала пытается резолвить principal по
// ory_kratos_session cookie; при отсутствии cookie / 401 — fallback на JWT.
func (a *AuthInterceptor) WithKratos(c *KratosClient) *AuthInterceptor {
	a.kratos = c
	return a
}

// WithVerifier подключает JWKS-валидатор Hydra-issued RS256 access JWT.
// Когда выставлен, validateJWT детектит signing method: RS256/ES256/EdDSA →
// проверка через JWKS-verifier (verified claims), HMAC → существующий dev-path.
// Principal строится из верифицированных `kacho_principal_*` claims напрямую
// (top-level или ext_claims); SubjectLookuper — fallback только при их
// отсутствии. nil → JWKS-path выключен (HMAC-only).
func (a *AuthInterceptor) WithVerifier(v TokenVerifier) *AuthInterceptor {
	a.verifier = v
	return a
}

// WithMTLSPrincipal enables the hybrid-listener cert-principal path: when
// the external TLS listener runs with tls.VerifyClientCertIfGiven, a request that
// arrived over a connection with a VERIFIED client cert (a valid Kachō cert) has
// its Principal derived from the cert's SPIFFE SAN BEFORE the JWT path — so a
// service→service caller authenticates on its mTLS identity with no JWT. When the
// flag is off (default), or no verified cert is present, the existing JWT flow is
// unchanged. The cert is trusted ONLY because the listener already verified the
// chain (VerifiedChains non-empty); client-supplied x-kacho-principal-* metadata
// is still stripped (no spoofing).
func (a *AuthInterceptor) WithMTLSPrincipal(enable bool) *AuthInterceptor {
	a.mtlsPrincipal = enable
	return a
}

// Unary — gRPC unary server interceptor.
func (a *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		newCtx, err := a.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

// Stream — gRPC stream server interceptor.
func (a *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx, err := a.authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		// wrappedStream объявлен в request_id.go — переиспользуем для ctx-override.
		wrapped := &wrappedStream{ServerStream: ss, ctx: newCtx}
		return handler(srv, wrapped)
	}
}

// authorize — основной flow: parse → validate → lookup → inject Principal.
func (a *AuthInterceptor) authorize(ctx context.Context, fullMethod string) (context.Context, error) {
	// Strip client-supplied x-kacho-principal-* incoming metadata, чтобы
	// исключить header-injection privilege escalation.
	if inMD, ok := metadata.FromIncomingContext(ctx); ok {
		var stripped bool
		md := inMD.Copy()
		for k := range md {
			if isClientForgeableIdentityHeader(strings.ToLower(k)) {
				delete(md, k)
				stripped = true
			}
		}
		if stripped {
			ctx = metadata.NewIncomingContext(ctx, md)
			a.logger.Warn("auth: stripped client-supplied x-kacho-principal-* metadata",
				"method", fullMethod)
		}
	}
	// Hybrid external listener: a connection that presented a VALID Kachō
	// client cert (the listener verified its chain via VerifyClientCertIfGiven)
	// authenticates on its mTLS identity — derive the Principal from the verified
	// cert's SPIFFE SAN and SKIP the JWT requirement entirely (no SubjectLookuper
	// round-trip). This precedes the Bearer flow so a service→service caller with
	// a cert but no JWT is NOT rejected in production-strict. The cert is trusted
	// only because the listener already verified it; client-supplied
	// x-kacho-principal-* metadata was stripped above (no spoofing).
	if a.mtlsPrincipal {
		if pType, pID, ok := principalFromVerifiedPeer(ctx); ok {
			a.logger.Debug("auth: principal derived from verified client cert (mTLS)",
				"method", fullMethod, "type", pType, "id", pID)
			return a.injectPrincipal(ctx, pType, pID, pID), nil
		}
	}

	bearer := extractBearer(ctx)

	// Empty Bearer handling per mode.
	if bearer == "" {
		switch a.mode {
		case AuthModeProductionStrict:
			return nil, status.Error(codes.Unauthenticated, "missing Bearer token")
		default: // dev / production
			return a.injectAnonymous(ctx), nil
		}
	}

	// Hydra-issued RS256/ES256/EdDSA access JWT → validate via JWKS
	// verifier (a SECOND strategy alongside the HMAC-dev path). On a verified
	// token the Principal is derived directly from the `kacho_principal_*`
	// claims (top-level or ext_claims) — no SubjectLookuper round-trip unless
	// those claims are absent. A present-but-bad token (bad sig / expired /
	// wrong iss / disallowed alg) or an unreachable JWKS endpoint is REJECTED
	// Unauthenticated (fail-closed), NEVER downgraded to anonymous.
	if a.verifier != nil && isAsymmetricJWT(bearer) {
		vt, verr := a.verifier.Verify(ctx, bearer)
		if verr != nil {
			a.logger.Warn("auth: Hydra JWT validation failed (JWKS)",
				"method", fullMethod, "err", verr)
			return nil, status.Error(codes.Unauthenticated, authFailedMsg)
		}
		pType, pID, display, perr := principalFromVerifiedToken(vt)
		if perr == nil {
			return a.injectPrincipal(ctx, pType, pID, display), nil
		}
		// Claims absent → fall back to SubjectLookuper on the verified sub.
		return a.authorizeViaLookup(ctx, fullMethod, vt.Subject)
	}

	// Validate JWT via the HMAC-dev path (dev/e2e tokens, zero regression).
	//
	// A Bearer header that is present but malformed / expired /
	// signature-invalid is a FAILED authentication
	// attempt — it must be rejected with `Unauthenticated` (HTTP 401), NOT
	// silently downgraded to anonymous (which would then hit authz and
	// surface as 403). authN failures precede authZ. This holds in every
	// mode: a bad token never grants anonymous access. A *missing* Bearer is
	// handled above (dev/production → anonymous, strict → 401).
	claims, err := a.validateJWT(bearer)
	if err != nil {
		a.logger.Warn("auth: JWT validation failed",
			"method", fullMethod, "err", err)
		return nil, status.Error(codes.Unauthenticated, authFailedMsg)
	}

	// Resolve subject via kacho-iam (gRPC-direct).
	subjectID, _ := claims["sub"].(string)
	if subjectID == "" {
		return nil, status.Error(codes.Unauthenticated, "token missing subject")
	}

	// Service Account / API-token principals. A token
	// minted by the Hydra client_credentials flow (or a static API token)
	// carries `kacho_principal_type=service_account` + `kacho_sa_id=<svaId>`.
	// `sub` is the SA id itself, which is NOT a User `external_id`, so the
	// User LookupByExternalID below would miss and (in dev) downgrade the SA
	// to anonymous. Resolve the SA principal directly from the typed claims.
	if pt, _ := claims["kacho_principal_type"].(string); pt == "service_account" {
		saID, _ := claims["kacho_sa_id"].(string)
		if saID == "" {
			saID = subjectID
		}
		return a.injectPrincipal(ctx, "service_account", saID, saID), nil
	}

	return a.authorizeViaLookup(ctx, fullMethod, subjectID)
}

// authorizeViaLookup резолвит principal через SubjectLookuper по external id
// (sub). Используется как HMAC-dev tail, так и JWKS-fallback (verified
// токен без kacho_principal_* claims). Поведение при NotFound зависит от mode:
// dev → anonymous (back-compat newman), production /
// production-strict → reject Unauthenticated.
func (a *AuthInterceptor) authorizeViaLookup(ctx context.Context, fullMethod, subjectID string) (context.Context, error) {
	if subjectID == "" {
		return nil, status.Error(codes.Unauthenticated, "token missing subject")
	}
	subj, err := a.subjectLookup.LookupByExternalID(ctx, subjectID)
	if err != nil {
		switch a.mode {
		case AuthModeProductionStrict, AuthModeProduction:
			// production[-strict]: subject обязан уже существовать в kacho-iam.
			// Log the raw iam error server-side; return the constant non-oracle
			// message so a validly-signed-but-unprovisioned token is
			// indistinguishable from a bad-signature token (no subject
			// enumeration, no iam error-text leak).
			a.logger.Warn("auth: subject not in kacho-iam (rejecting)",
				"method", fullMethod, "external_id", subjectID, "err", err)
			return nil, status.Error(codes.Unauthenticated, authFailedMsg)
		default: // dev
			a.logger.Debug("auth: subject not in kacho-iam, fallback to anonymous",
				"method", fullMethod, "external_id", subjectID, "err", err)
			return a.injectAnonymous(ctx), nil
		}
	}

	// Inject Principal в ctx + metadata (backend читает через corelib).
	return a.injectPrincipal(ctx, subj.Type, subj.ID, subj.DisplayName), nil
}

func (a *AuthInterceptor) injectAnonymous(ctx context.Context) context.Context {
	return a.injectPrincipal(ctx, "system", "anonymous", "")
}

func (a *AuthInterceptor) injectPrincipal(ctx context.Context, pType, pID, displayName string) context.Context {
	p := operations.Principal{Type: pType, ID: pID, DisplayName: displayName}
	ctx = operations.WithPrincipal(ctx, p)

	// Inject в INCOMING metadata: proxy-слой (opsproxy.Get/Cancel,
	// shimproxy.Handler) пересобирает backend-outgoing из INCOMING через
	// principalmeta.OutgoingFromIncoming, а opsproxy.checkOperationOwnership
	// читает caller-principal тоже из INCOMING. Без записи в incoming
	// gRPC-direct-путь молча роняет principal (клиент аутентифицирован, но hop
	// форвардит анонима → ownership-check/backend видят анонимного caller'а).
	// Incoming уже очищен от client-forgeable x-kacho-principal-* выше, так что
	// это доверенный override, а не spoof. (REST-путь работает, потому что
	// restmux выставляет principal как incoming — здесь достигается паритет.)
	inMD, _ := metadata.FromIncomingContext(ctx)
	if inMD == nil {
		inMD = metadata.MD{}
	} else {
		inMD = inMD.Copy()
	}
	inMD.Set(a.mdKeyPrincipalType, pType)
	inMD.Set(a.mdKeyPrincipalID, pID)
	inMD.Set(a.mdKeyPrincipalDisplay, displayName)
	ctx = metadata.NewIncomingContext(ctx, inMD)

	// Inject в outgoing metadata — для нативного handler'а, который форвардит
	// собственный outgoing-ctx напрямую (без OutgoingFromIncoming-пересборки).
	md, _ := metadata.FromOutgoingContext(ctx)
	if md == nil {
		md = metadata.MD{}
	} else {
		md = md.Copy()
	}
	md.Set(a.mdKeyPrincipalType, pType)
	md.Set(a.mdKeyPrincipalID, pID)
	md.Set(a.mdKeyPrincipalDisplay, displayName)
	return metadata.NewOutgoingContext(ctx, md)
}

// isAsymmetricJWT peeks the unverified JWT header and reports whether its `alg`
// is in the asymmetric whitelist (RS256/ES256/EdDSA) — i.e. a Hydra-issued
// access token that must go through the JWKS verifier rather than the HMAC-dev
// path. HS* / none / non-JWT → false (handled by the HMAC branch / rejected).
// This is a strategy selector only; the verifier re-checks the alg authoritatively
// against the pinned JWK (algorithm-confusion is impossible here — a forged HS256
// with an asymmetric-looking header would fail HMAC validation, and an RS256
// claiming HS256 fails the JWKS alg whitelist).
func isAsymmetricJWT(tokenStr string) bool {
	headerB64, _, ok := strings.Cut(tokenStr, ".")
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if jerr := json.Unmarshal(raw, &hdr); jerr != nil {
		return false
	}
	_, asymmetric := AllowedJWTAlgs[hdr.Alg]
	return asymmetric
}

// principalFromVerifiedToken derives the Kachō Principal from a JWKS-verified
// Hydra token's `kacho_principal_*` claims. It reads each claim robustly
// from EITHER the top level (Hydra allowed_top_level_claims promotion) OR the
// nested `ext_claims` map (token_hook session.access_token.ext_claims). Returns
// an error when the principal claims are absent so the caller can fall back to
// the SubjectLookuper. displayName comes from a present display claim, else
// the principal id.
func principalFromVerifiedToken(vt *VerifiedToken) (pType, pID, displayName string, err error) {
	pType = verifiedClaim(vt, "kacho_principal_type")
	pID = verifiedClaim(vt, "kacho_principal_id")
	if pType == "" || pID == "" {
		return "", "", "", fmt.Errorf("verified token carries no kacho_principal_* claims")
	}
	displayName = verifiedClaim(vt, "kacho_principal_display_name")
	if displayName == "" {
		displayName = pID
	}
	return pType, pID, displayName, nil
}

// verifiedClaim reads a string claim from a verified token, preferring the
// top-level claim, then the nested `ext_claims` map (claim-placement
// robustness).
func verifiedClaim(vt *VerifiedToken, key string) string {
	if vt.Claims != nil {
		if s, ok := vt.Claims[key].(string); ok && s != "" {
			return s
		}
	}
	if vt.ExtClaims != nil {
		if s, ok := vt.ExtClaims[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// principalFromVerifiedPeer derives a Kachō Principal from the verified client
// cert of the gRPC peer (hybrid listener). It returns ok=false unless the
// peer carries TLS auth-info with a NON-EMPTY VerifiedChains — i.e. the listener
// actually verified the presented cert against the trust anchor
// (VerifyClientCertIfGiven). An unverified / absent cert (browser, JWT client)
// yields ok=false so the caller falls through to the JWT path.
//
// The principal is mapped from the leaf's SPIFFE URI SAN
// (spiffe://kacho.cloud/ns/<ns>/sa/<sa>): a service→service caller is a
// `service_account` whose id is the `<sa>` segment. Display name defaults to the
// id at the call site.
func principalFromVerifiedPeer(ctx context.Context) (pType, pID string, ok bool) {
	p, present := peer.FromContext(ctx)
	if !present || p == nil {
		return "", "", false
	}
	tlsInfo, isTLS := p.AuthInfo.(credentials.TLSInfo)
	if !isTLS {
		return "", "", false
	}
	leaf := verifiedLeaf(tlsInfo.State.VerifiedChains)
	if leaf == nil {
		return "", "", false
	}
	for _, u := range leaf.URIs {
		if sa, matched := saFromSPIFFE(u.String()); matched {
			return "service_account", sa, true
		}
	}
	return "", "", false
}

// verifiedLeaf returns the leaf (chain[0]) of the first non-empty verified chain,
// or nil when no chain was verified (the cert was absent or did not chain to a
// trusted CA).
func verifiedLeaf(chains [][]*x509.Certificate) *x509.Certificate {
	for _, chain := range chains {
		if len(chain) > 0 && chain[0] != nil {
			return chain[0]
		}
	}
	return nil
}

// saFromSPIFFE parses a Kachō SPIFFE id of the form
// `spiffe://kacho.cloud/ns/<ns>/sa/<sa>` and returns the `<sa>` workload segment.
// Any other URI shape (or a non-Kachō trust domain) → matched=false.
func saFromSPIFFE(uri string) (sa string, matched bool) {
	const prefix = "spiffe://kacho.cloud/ns/"
	rest, ok := strings.CutPrefix(uri, prefix)
	if !ok {
		return "", false
	}
	// rest = "<ns>/sa/<sa>"
	_, after, ok := strings.Cut(rest, "/sa/")
	if !ok || after == "" {
		return "", false
	}
	// Guard against trailing path segments — the sa segment must be terminal.
	if strings.Contains(after, "/") {
		return "", false
	}
	return after, true
}

func (a *AuthInterceptor) validateJWT(tokenStr string) (jwt.MapClaims, error) {
	// SEC (sec-hardening-r8): the symmetric HMAC-dev token path is a dev/e2e
	// affordance ONLY. In production / production-strict it MUST be refused
	// wholesale — a validly-HS256-signed token (an attacker who learned or
	// guessed KACHO_API_GATEWAY_AUTHN_DEV_SECRET) would otherwise yield a real
	// principal, and a `kacho_principal_type=service_account` claim is injected
	// as a service_account with NO IAM lookup (symmetric-key principal forgery,
	// CWE-347). The only accepted Bearer strategy in prod is the asymmetric JWKS
	// (Hydra) verifier, which runs BEFORE this path for RS256/ES256/EdDSA tokens.
	// Fail closed regardless of whether a dev-secret happens to be configured
	// (defense-in-depth alongside the fatal startup guard in cmd/api-gateway).
	if a.mode != AuthModeDev {
		return nil, fmt.Errorf("HMAC-dev token path disabled in %q mode", a.mode)
	}
	if len(a.devSecret) == 0 {
		// HMAC-dev path requires a configured dev-secret. Hydra RS256 tokens are
		// validated by the JWKS verifier branch BEFORE reaching here, so
		// an empty dev-secret only disables the HS256-dev path.
		return nil, fmt.Errorf("no signing key configured (dev secret empty)")
	}
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.devSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}
	return claims, nil
}

// setPrincipalHeaders writes the resolved principal onto the REST request in
// both the plain form (read by restmux WithMetadata → outgoing gRPC metadata)
// and the legacy grpc-gateway convention form (fallback path). Shared by the
// Hydra-JWT branch with the Kratos and SA-token paths.
func setPrincipalHeaders(r *http.Request, pType, pID, displayName string) {
	r.Header.Set(principalmeta.HeaderPrincipalType, pType)
	r.Header.Set(principalmeta.HeaderPrincipalID, pID)
	r.Header.Set(principalmeta.HeaderPrincipalDisplay, displayName)
	r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalType, pType)
	r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalID, pID)
	r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalDisplay, displayName)
}

// writeHTTPUnauthorized emits a 401 with a gRPC-shaped JSON body (code 16 =
// Unauthenticated) and a `WWW-Authenticate` challenge. Used by the REST auth
// path when a Bearer token is present but fails validation — authN failures
// must surface as 401, never as 403 (which is the authZ verdict).
func writeHTTPUnauthorized(w http.ResponseWriter, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+desc+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"code":16,"message":"` + desc + `"}`))
}

// isClientForgeableIdentityHeader reports whether a lower-cased inbound header
// name carries gateway-derived identity/token context that a client must never
// supply: principal (type/id/display-name) and token (acr/jti/scope/exp), in
// both the plain and grpc-gateway `grpc-metadata-` forms. These are set only by
// the gateway after a validated credential, so they are stripped before the
// auth flow — otherwise a forged X-Kacho-Token-Acr would reach the step-up gate
// and the backend acr-floor.
func isClientForgeableIdentityHeader(lower string) bool {
	switch {
	case strings.HasPrefix(lower, principalmeta.MetaPrincipalPrefix),
		strings.HasPrefix(lower, principalmeta.MetaGRPCPrincipalPrefix),
		strings.HasPrefix(lower, "x-kacho-token-"),
		strings.HasPrefix(lower, "grpc-metadata-x-kacho-token-"):
		return true
	}
	return false
}

func extractBearer(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, h := range md.Get("authorization") {
		if v, ok := strings.CutPrefix(h, "Bearer "); ok {
			return v
		}
		if v, ok := strings.CutPrefix(h, "bearer "); ok {
			return v
		}
	}
	return ""
}

// HTTP — middleware для grpc-gateway REST mux. Парсит Authorization header
// и прокидывает его как metadata в gRPC ctx (стандартный grpc-gateway-форвард
// в `incomingHeaderMatcher`).
//
// Также: если есть cookie `kacho_session=...` (UI), переписываем ее в
// Authorization Bearer.
func (a *AuthInterceptor) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip client-forgeable identity headers before any auth path runs, then
		// try each strategy in fail-closed order. The `injected` flag from the
		// Kratos path suppresses the JWT paths (a resolved session wins). The
		// Hydra and dev-JWT paths are terminal when they apply: they either write
		// a 401 or serve `next` themselves and report handled=true.
		a.stripForgeableIdentityHeaders(r)

		injected := a.tryKratosSession(r)
		a.rewriteCookieToBearer(r)

		if !injected {
			if a.tryHydraJWT(w, r, next) {
				return
			}
			if a.tryDevSecretJWT(w, r, next) {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// stripForgeableIdentityHeaders removes incoming X-Kacho-Principal-* (and the
// grpc-gateway `Grpc-Metadata-` / lower-case variants) so a client cannot forge
// `X-Kacho-Principal-Type: user` and bypass auth (full privilege escalation).
// These headers are set ONLY by the auth middleware after a resolved
// Bearer/Kratos credential.
func (a *AuthInterceptor) stripForgeableIdentityHeaders(r *http.Request) {
	for k := range r.Header {
		if isClientForgeableIdentityHeader(strings.ToLower(k)) {
			r.Header.Del(k)
		}
	}
}

// tryKratosSession resolves a Kratos session cookie (ory_kratos_session) to a
// principal BEFORE the JWT paths so SPA users without a Bearer get a principal.
// Returns true when a principal was injected (which suppresses the JWT paths).
func (a *AuthInterceptor) tryKratosSession(r *http.Request) bool {
	if a.kratos == nil {
		return false
	}
	cookieHdr := r.Header.Get("Cookie")
	if !strings.Contains(cookieHdr, "ory_kratos_session") {
		return false
	}
	res := a.kratos.Whoami(r.Context(), cookieHdr)
	if !res.Active || res.IdentityID == "" {
		return false
	}
	var subj Subject
	var err error
	// Если lookuper поддерживает lazy-upsert (Kratos new-user path) — используем
	// его; иначе обычный lookup.
	if kl, ok := a.subjectLookup.(KratosSubjectLookuper); ok {
		subj, err = kl.LookupOrUpsertFromKratos(r.Context(), res.IdentityID, res.Email, res.DisplayName)
	} else {
		subj, err = a.subjectLookup.LookupByExternalID(r.Context(), res.IdentityID)
	}
	if err != nil {
		a.logger.Debug("auth.HTTP: Kratos SubjectLookup failed",
			"identity_id", res.IdentityID, "err", err.Error())
		return false
	}
	r.Header.Set(principalmeta.HeaderPrincipalType, subj.Type)
	r.Header.Set(principalmeta.HeaderPrincipalID, subj.ID)
	r.Header.Set(principalmeta.HeaderPrincipalDisplay, subj.DisplayName)
	r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalType, subj.Type)
	r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalID, subj.ID)
	r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalDisplay, subj.DisplayName)
	a.logger.Info("auth.HTTP: Principal injected (Kratos)",
		"type", subj.Type, "id", subj.ID, "identity_id", res.IdentityID)
	return true
}

// rewriteCookieToBearer rewrites the UI `kacho_session` cookie into an
// Authorization: Bearer header when no Authorization header is present.
func (a *AuthInterceptor) rewriteCookieToBearer(r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		return
	}
	if c, err := r.Cookie("kacho_session"); err == nil && c.Value != "" {
		r.Header.Set("Authorization", "Bearer "+c.Value)
	}
}

// tryHydraJWT validates a Hydra-issued asymmetric (RS256/ES256/EdDSA) access JWT
// over REST via the JWKS verifier (parity with the gRPC interceptor path) and
// derives the principal from the verified `kacho_principal_*` claims (top-level
// or ext_claims), falling back to SubjectLookuper on the verified sub. A
// present-but-bad token or unreachable JWKS → 401 fail-closed, never anonymous.
// Returns true when this path was terminal (401 written, or principal resolved
// and `next` served) — i.e. the caller must return. Returns false when the path
// does not apply (no verifier / not an asymmetric Bearer) so the next strategy
// runs.
func (a *AuthInterceptor) tryHydraJWT(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	if a.verifier == nil {
		return false
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !isAsymmetricJWT(tok) {
		return false
	}
	vt, verr := a.verifier.Verify(r.Context(), tok)
	if verr != nil {
		a.logger.Warn("auth.HTTP: Hydra JWT validate failed (JWKS)", "err", verr.Error())
		writeHTTPUnauthorized(w, "token validation failed")
		return true
	}
	if pType, pID, display, perr := principalFromVerifiedToken(vt); perr == nil {
		setPrincipalHeaders(r, pType, pID, display)
		a.logger.Info("auth.HTTP: Principal injected (Hydra JWT)", "type", pType, "id", pID)
		next.ServeHTTP(w, r)
		return true
	}
	// Claims absent → fall back to SubjectLookuper on the verified sub.
	if vt.Subject == "" {
		a.logger.Warn("auth.HTTP: Hydra JWT has empty sub and no kacho_principal_* claims")
		writeHTTPUnauthorized(w, "token missing subject")
		return true
	}
	if subj, lerr := a.subjectLookup.LookupByExternalID(r.Context(), vt.Subject); lerr != nil {
		a.logger.Debug("auth.HTTP: SubjectLookup failed (Hydra JWT fallback)", "external_id", vt.Subject, "err", lerr.Error())
	} else {
		setPrincipalHeaders(r, subj.Type, subj.ID, subj.DisplayName)
		a.logger.Info("auth.HTTP: Principal injected (Hydra JWT fallback)", "type", subj.Type, "id", subj.ID)
	}
	next.ServeHTTP(w, r)
	return true
}

// tryDevSecretJWT validates a symmetric dev-secret Bearer JWT and injects the
// principal (service-account or User-lookup). A present-but-invalid token → 401
// fail-closed. Returns true only when the path was terminal (401, or an SA
// principal was injected and `next` served). For the ordinary User-lookup case
// it sets the headers and returns false so the caller serves `next` once at the
// end (preserving the original fall-through).
func (a *AuthInterceptor) tryDevSecretJWT(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	if r.Header.Get("Authorization") == "" || len(a.devSecret) == 0 {
		return false
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	claims, jwtErr := a.validateJWT(tok)
	if jwtErr != nil {
		// A Bearer header that is present but malformed / expired /
		// signature-invalid is a failed authN attempt → reject with
		// 401 BEFORE authz, never pass it through as anonymous (which
		// surfaces as 403).
		a.logger.Warn("auth.HTTP: JWT validate failed", "err", jwtErr.Error())
		writeHTTPUnauthorized(w, "token validation failed")
		return true
	}
	subjectID, _ := claims["sub"].(string)
	if subjectID == "" {
		a.logger.Warn("auth.HTTP: JWT has empty sub")
		writeHTTPUnauthorized(w, "token missing subject")
		return true
	}
	// Service Account / API-token principals.
	// A client_credentials / API token carries
	// `kacho_principal_type=service_account` + `kacho_sa_id`; `sub`
	// is the SA id, not a User external_id, so the User lookup below
	// would miss and leave the request principal-less → the authz
	// layer then denies it as unauthenticated. Resolve the SA
	// principal directly from the typed claims (parity with the
	// gRPC intercept path).
	if pt, _ := claims["kacho_principal_type"].(string); pt == "service_account" {
		saID, _ := claims["kacho_sa_id"].(string)
		if saID == "" {
			saID = subjectID
		}
		r.Header.Set(principalmeta.HeaderPrincipalType, "service_account")
		r.Header.Set(principalmeta.HeaderPrincipalID, saID)
		r.Header.Set(principalmeta.HeaderPrincipalDisplay, saID)
		r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalType, "service_account")
		r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalID, saID)
		r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalDisplay, saID)
		a.logger.Info("auth.HTTP: SA principal injected", "id", saID)
		next.ServeHTTP(w, r)
		return true
	}
	subj, lookupErr := a.subjectLookup.LookupByExternalID(r.Context(), subjectID)
	if lookupErr != nil {
		a.logger.Debug("auth.HTTP: SubjectLookup failed", "external_id", subjectID, "err", lookupErr.Error())
	} else {
		// Plain headers — WithMetadata callback in restmux форвардит.
		r.Header.Set(principalmeta.HeaderPrincipalType, subj.Type)
		r.Header.Set(principalmeta.HeaderPrincipalID, subj.ID)
		r.Header.Set(principalmeta.HeaderPrincipalDisplay, subj.DisplayName)
		// Legacy form — grpc-gateway default convention fallback.
		r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalType, subj.Type)
		r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalID, subj.ID)
		r.Header.Set(principalmeta.HeaderGRPCMetaPrincipalDisplay, subj.DisplayName)
		a.logger.Info("auth.HTTP: Principal injected", "type", subj.Type, "id", subj.ID)
	}
	return false
}
