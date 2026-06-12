// Package middleware — auth.go: JWT validation + Principal injection (KAC-107 E2).
//
// Replaces auth_noop.go. Поведение зависит от cfg.AuthN.Mode.
//
// Две стратегии валидации Bearer (SEC-J), выбираются по `alg` в JWT-хедере:
//   - **HMAC-dev** (HS256, `KACHO_API_GATEWAY_AUTHN_DEV_SECRET`) — dev/e2e токены.
//   - **Hydra JWKS** (RS256/ES256/EdDSA, `WithVerifier`) — реальные login-токены;
//     principal берётся из верифицированных `kacho_principal_*` claims (top-level
//     или `ext_claims`), SubjectLookuper — fallback только при их отсутствии.
//
// Per-mode:
//   - **dev** (default): backwards-compat. Без Bearer — pass-through anonymous
//     (Principal{system, anonymous}). С Bearer — валидируется (HMAC-dev ИЛИ Hydra
//     JWKS по alg); HMAC-subject (external_id) не найден в kacho_iam → fallback на
//     anonymous, чтобы не ломать существующие newman-сценарии. Bad token (любая
//     стратегия) → reject Unauthenticated, НИКОГДА anonymous.
//   - **production**: Subject lookup → kacho-iam; NotFound → reject.
//     NotFound lazy-mirror через `InternalUserService.UpsertFromIdentity` — TODO.
//   - **production-strict**: Bearer обязателен **всегда** (`Unauthenticated`
//     без него); все остальные правила — как в production.
//
// Архитектура (acceptance §4.3):
//
//	┌─ parse Bearer ─┐    ┌─ JWT validate ─┐    ┌─ SubjectLookup ─┐    ┌─ Principal in ctx ─┐
//	│ Authorization │ → │ JWKS/HMAC      │ → │ kacho-iam:9091  │ → │ x-kacho-principal-* │
//	└────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────────┘
//
// Loop-prevention запрет #6: InternalIAMService.LookupSubject зовётся
// **gRPC-direct** (через iamSubjectClient), НЕ через restmux, иначе recursion.
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
)

// AuthMode — режим работы auth-interceptor'а (D4, D8 в acceptance §2).
type AuthMode string

const (
	AuthModeDev              AuthMode = "dev"
	AuthModeProduction       AuthMode = "production"
	AuthModeProductionStrict AuthMode = "production-strict"
)

// SubjectLookuper — port-интерфейс для subject-резолва. Реализация —
// `internal/clients/iam_subject_client.go` (gRPC-direct к kacho-iam:9091).
// Декларирован тут, чтобы не тащить proto-dep в middleware (Clean
// Architecture — handler/middleware layer).
type SubjectLookuper interface {
	LookupByExternalID(ctx context.Context, externalID string) (Subject, error)
}

// KratosSubjectLookuper — опциональное расширение SubjectLookuper для Kratos
// session-flow: при NotFound делает lazy-upsert User mirror'а через
// InternalUserService.UpsertFromIdentity (KAC-116).
type KratosSubjectLookuper interface {
	LookupOrUpsertFromKratos(ctx context.Context, identityID, email, displayName string) (Subject, error)
}

// Subject — резолвленный subject (User или ServiceAccount).
type Subject struct {
	Type        string // "user" | "service_account"
	ID          string
	DisplayName string
}

// TokenVerifier — port для JWKS-валидации Hydra-issued RS256 access JWT
// (SEC-J). Реализация — `*JWTVerifier` (jwt_verifier.go), уже сконструированная
// в cmd/main.go для DPoP; тот же инстанс переиспользуется в principal-path.
// Декларирован интерфейсом, чтобы AuthInterceptor не был жёстко привязан к
// конкретному типу (тестируемость + Clean Architecture).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*VerifiedToken, error)
}

// AuthInterceptor — JWT validate + subject lookup + Principal injection.
type AuthInterceptor struct {
	mode          AuthMode
	devSecret     []byte // HMAC-secret для mode=dev (если пуст — Bearer reject в dev/production-strict).
	subjectLookup SubjectLookuper
	kratos        *KratosClient // KAC-116: optional Ory Kratos /whoami client (nil → disabled)
	verifier      TokenVerifier // SEC-J: JWKS-валидатор Hydra RS256 access JWT (nil → disabled, HMAC-only)
	mtlsPrincipal bool          // SEC-K: derive Principal from a verified client cert (hybrid external listener)
	logger        *slog.Logger

	// Headers, которые auth-interceptor пропускает в backend metadata
	// (после успешного auth). Backend через corelib `grpcsrv.PrincipalExtractInterceptor`
	// прочитает их в ctx.
	mdKeyPrincipalType    string // "x-kacho-principal-type"
	mdKeyPrincipalID      string // "x-kacho-principal-id"
	mdKeyPrincipalDisplay string // "x-kacho-principal-display-name"
}

// NewAuthInterceptor создаёт interceptor с настройками из конфига.
func NewAuthInterceptor(mode AuthMode, devSecret string, lookup SubjectLookuper, logger *slog.Logger) *AuthInterceptor {
	return &AuthInterceptor{
		mode:                  mode,
		devSecret:             []byte(devSecret),
		subjectLookup:         lookup,
		logger:                logger,
		mdKeyPrincipalType:    "x-kacho-principal-type",
		mdKeyPrincipalID:      "x-kacho-principal-id",
		mdKeyPrincipalDisplay: "x-kacho-principal-display-name",
	}
}

// WithKratos подключает Kratos /whoami client (KAC-116).
// Если выставлено, HTTP middleware сначала пытается резолвить principal по
// ory_kratos_session cookie; при отсутствии cookie / 401 — fallback на JWT.
func (a *AuthInterceptor) WithKratos(c *KratosClient) *AuthInterceptor {
	a.kratos = c
	return a
}

// WithVerifier подключает JWKS-валидатор Hydra-issued RS256 access JWT (SEC-J).
// Когда выставлен, validateJWT детектит signing method: RS256/ES256/EdDSA →
// проверка через JWKS-verifier (verified claims), HMAC → существующий dev-path.
// Principal строится из верифицированных `kacho_principal_*` claims напрямую
// (top-level или ext_claims); SubjectLookuper — fallback только при их
// отсутствии. nil → JWKS-path выключен (HMAC-only, как до SEC-J).
func (a *AuthInterceptor) WithVerifier(v TokenVerifier) *AuthInterceptor {
	a.verifier = v
	return a
}

// WithMTLSPrincipal enables the SEC-K hybrid-listener cert-principal path: when
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
	// KAC-122 CRIT-8 fix: strip client-supplied x-kacho-principal-* incoming
	// metadata, чтобы исключить header-injection privilege escalation.
	if inMD, ok := metadata.FromIncomingContext(ctx); ok {
		var stripped bool
		md := inMD.Copy()
		for k := range md {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-kacho-principal-") ||
				strings.HasPrefix(lk, "grpc-metadata-x-kacho-principal-") {
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
	// SEC-K hybrid external listener: a connection that presented a VALID Kachō
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

	// Empty Bearer handling per mode (D4).
	if bearer == "" {
		switch a.mode {
		case AuthModeProductionStrict:
			return nil, status.Error(codes.Unauthenticated, "missing Bearer token")
		default: // dev / production
			return a.injectAnonymous(ctx), nil
		}
	}

	// SEC-J: Hydra-issued RS256/ES256/EdDSA access JWT → validate via JWKS
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
			return nil, status.Errorf(codes.Unauthenticated, "token validation failed: %v", verr)
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
	// KAC-127 api-token authn pre-gate: a Bearer header that is present but
	// malformed / expired / signature-invalid is a FAILED authentication
	// attempt — it must be rejected with `Unauthenticated` (HTTP 401), NOT
	// silently downgraded to anonymous (which would then hit authz and
	// surface as 403). authN failures precede authZ. This holds in every
	// mode: a bad token never grants anonymous access. A *missing* Bearer is
	// handled above (dev/production → anonymous, strict → 401).
	claims, err := a.validateJWT(bearer)
	if err != nil {
		a.logger.Warn("auth: JWT validation failed",
			"method", fullMethod, "err", err)
		return nil, status.Errorf(codes.Unauthenticated, "token validation failed: %v", err)
	}

	// Resolve subject via kacho-iam (gRPC-direct).
	subjectID, _ := claims["sub"].(string)
	if subjectID == "" {
		return nil, status.Error(codes.Unauthenticated, "token missing subject")
	}

	// KAC-127 models 5-6 — Service Account / API-token principals. A token
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
// (sub). Используется как HMAC-dev tail, так и SEC-J JWKS-fallback (A4: verified
// токен без kacho_principal_* claims). Поведение при NotFound зависит от mode —
// идентично legacy-пути: dev → anonymous (back-compat newman), production /
// production-strict → reject Unauthenticated.
func (a *AuthInterceptor) authorizeViaLookup(ctx context.Context, fullMethod, subjectID string) (context.Context, error) {
	if subjectID == "" {
		return nil, status.Error(codes.Unauthenticated, "token missing subject")
	}
	subj, err := a.subjectLookup.LookupByExternalID(ctx, subjectID)
	if err != nil {
		switch a.mode {
		case AuthModeProductionStrict:
			return nil, status.Errorf(codes.Unauthenticated, "subject not found: %v", err)
		case AuthModeProduction:
			// TODO(KAC-107 follow-up): lazy-mirror через UpsertFromIdentity (D10).
			return nil, status.Errorf(codes.Unauthenticated, "subject not found: %v", err)
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

	// Inject в outgoing metadata, чтобы proxy-слой передал backend'у.
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
// Hydra token's `kacho_principal_*` claims (SEC-J). It reads each claim robustly
// from EITHER the top level (Hydra allowed_top_level_claims promotion) OR the
// nested `ext_claims` map (token_hook session.access_token.ext_claims). Returns
// an error when the principal claims are absent so the caller can fall back to
// the SubjectLookuper (A4). displayName comes from a present display claim, else
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
// top-level claim, then the nested `ext_claims` map (SEC-J claim-placement
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
// cert of the gRPC peer (SEC-K hybrid listener). It returns ok=false unless the
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
	if len(a.devSecret) == 0 {
		// HMAC-dev path requires a configured dev-secret. Hydra RS256 tokens are
		// validated by the JWKS verifier branch (SEC-J) BEFORE reaching here, so
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
// SEC-J Hydra-JWT branch with the existing KAC-116/KAC-127 paths.
func setPrincipalHeaders(r *http.Request, pType, pID, displayName string) {
	r.Header.Set("X-Kacho-Principal-Type", pType)
	r.Header.Set("X-Kacho-Principal-Id", pID)
	r.Header.Set("X-Kacho-Principal-Display-Name", displayName)
	r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Type", pType)
	r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Id", pID)
	r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Display-Name", displayName)
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

// HTTPAuth — middleware для grpc-gateway REST mux. Парсит Authorization header
// и прокидывает его как metadata в gRPC ctx (стандартный grpc-gateway-форвард
// в `incomingHeaderMatcher`). Здесь мы только логируем — реальная проверка
// произойдёт в Unary interceptor'е после конвертации REST → gRPC.
//
// Также: если есть cookie `kacho_session=...` (UI), переписываем её в
// Authorization Bearer (acceptance §3.4 D5). Cookie session — отложено в
// KAC-107 follow-up; пока no-op.
func (a *AuthInterceptor) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// KAC-122 CRIT-8 fix: strip incoming X-Kacho-Principal-* headers
		// до auth-flow. Client может передать `X-Kacho-Principal-Type: user`
		// и обойти auth — это polno privilege escalation. Заголовки
		// устанавливаются ТОЛЬКО auth-middleware после resolved Bearer/Kratos.
		// Также чистим `Grpc-Metadata-X-Kacho-Principal-*` (grpc-gateway
		// canonical convention) и нижне-case варианты.
		for k := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-kacho-principal-") ||
				strings.HasPrefix(lk, "grpc-metadata-x-kacho-principal-") {
				r.Header.Del(k)
			}
		}

		// KAC-116: Kratos session-based auth (cookie ory_kratos_session).
		// Резолвится ДО JWT-path, чтобы SPA-пользователи (без Bearer) получали
		// principal. Если whoami возвращает active session — выставляем headers
		// и пропускаем JWT-блок. Иначе — fallback на JWT.
		injected := false
		if a.kratos != nil {
			cookieHdr := r.Header.Get("Cookie")
			if strings.Contains(cookieHdr, "ory_kratos_session") {
				res := a.kratos.Whoami(r.Context(), cookieHdr)
				if res.Active && res.IdentityID != "" {
					var subj Subject
					var err error
					// KAC-116: если lookuper поддерживает lazy-upsert (Kratos new-user
					// path) — используем его; иначе обычный lookup.
					if kl, ok := a.subjectLookup.(KratosSubjectLookuper); ok {
						subj, err = kl.LookupOrUpsertFromKratos(r.Context(), res.IdentityID, res.Email, res.DisplayName)
					} else {
						subj, err = a.subjectLookup.LookupByExternalID(r.Context(), res.IdentityID)
					}
					if err != nil {
						a.logger.Debug("auth.HTTP: Kratos SubjectLookup failed",
							"identity_id", res.IdentityID, "err", err.Error())
					} else {
						r.Header.Set("X-Kacho-Principal-Type", subj.Type)
						r.Header.Set("X-Kacho-Principal-Id", subj.ID)
						r.Header.Set("X-Kacho-Principal-Display-Name", subj.DisplayName)
						r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Type", subj.Type)
						r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Id", subj.ID)
						r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Display-Name", subj.DisplayName)
						a.logger.Info("auth.HTTP: Principal injected (Kratos)",
							"type", subj.Type, "id", subj.ID, "email", res.Email)
						injected = true
					}
				}
			}
		}

		// Cookie → Bearer rewrite (D5) — KAC-107 follow-up.
		if r.Header.Get("Authorization") == "" {
			if c, err := r.Cookie("kacho_session"); err == nil && c.Value != "" {
				r.Header.Set("Authorization", "Bearer "+c.Value)
			}
		}

		// KAC-107 follow-up #2: REST→backend Principal propagation (JWT path).
		// gRPC server interceptor работает только для grpc-proxy path, не для grpc-gateway
		// REST. Здесь делаем JWT-parse + SubjectLookup + ставим headers
		// `X-Kacho-Principal-*`. Дальше restmux.NewMux WithMetadata callback явно
		// читает их из http.Request и кладёт в outgoing gRPC metadata
		// `x-kacho-principal-*`, которые backend читает через
		// corelib/grpcsrv.UnaryPrincipalExtract. Также пишем legacy-form
		// `Grpc-Metadata-X-Kacho-Principal-*` для совместимости с default
		// grpc-gateway convention (если WithMetadata не работает — fallback path).
		if !injected {
			_ = injected // satisfy unused-var в коротких ветках
		}

		// SEC-J: Hydra-issued RS256/ES256/EdDSA access JWT over REST — validate
		// via the JWKS verifier (parity with the gRPC interceptor path, I7) and
		// derive the principal from the verified `kacho_principal_*` claims
		// (top-level or ext_claims). A present-but-bad token or an unreachable
		// JWKS endpoint → 401 fail-closed, NEVER passed through anonymous.
		if auth := r.Header.Get("Authorization"); !injected && a.verifier != nil {
			if tok, ok := strings.CutPrefix(auth, "Bearer "); ok && isAsymmetricJWT(tok) {
				vt, verr := a.verifier.Verify(r.Context(), tok)
				if verr != nil {
					a.logger.Warn("auth.HTTP: Hydra JWT validate failed (JWKS)", "err", verr.Error())
					writeHTTPUnauthorized(w, "token validation failed")
					return
				}
				if pType, pID, display, perr := principalFromVerifiedToken(vt); perr == nil {
					setPrincipalHeaders(r, pType, pID, display)
					a.logger.Info("auth.HTTP: Principal injected (Hydra JWT)", "type", pType, "id", pID)
					next.ServeHTTP(w, r)
					return
				}
				// Claims absent → fall back to SubjectLookuper on the verified sub.
				if vt.Subject == "" {
					a.logger.Warn("auth.HTTP: Hydra JWT has empty sub and no kacho_principal_* claims")
					writeHTTPUnauthorized(w, "token missing subject")
					return
				}
				if subj, lerr := a.subjectLookup.LookupByExternalID(r.Context(), vt.Subject); lerr != nil {
					a.logger.Debug("auth.HTTP: SubjectLookup failed (Hydra JWT fallback)", "external_id", vt.Subject, "err", lerr.Error())
				} else {
					setPrincipalHeaders(r, subj.Type, subj.ID, subj.DisplayName)
					a.logger.Info("auth.HTTP: Principal injected (Hydra JWT fallback)", "type", subj.Type, "id", subj.ID)
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		if auth := r.Header.Get("Authorization"); !injected && auth != "" && len(a.devSecret) > 0 {
			if tok, ok := strings.CutPrefix(auth, "Bearer "); ok {
				claims, jwtErr := a.validateJWT(tok)
				if jwtErr != nil {
					// KAC-127 api-token authn pre-gate: a Bearer header that is
					// present but malformed / expired / signature-invalid is a
					// failed authN attempt → reject with 401 BEFORE authz, never
					// pass it through as anonymous (which surfaces as 403).
					a.logger.Warn("auth.HTTP: JWT validate failed", "err", jwtErr.Error())
					writeHTTPUnauthorized(w, "token validation failed")
					return
				}
				subjectID, _ := claims["sub"].(string)
				if subjectID == "" {
					a.logger.Warn("auth.HTTP: JWT has empty sub")
					writeHTTPUnauthorized(w, "token missing subject")
					return
				}
				// KAC-127 models 5-6 — Service Account / API-token principals.
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
					r.Header.Set("X-Kacho-Principal-Type", "service_account")
					r.Header.Set("X-Kacho-Principal-Id", saID)
					r.Header.Set("X-Kacho-Principal-Display-Name", saID)
					r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Type", "service_account")
					r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Id", saID)
					r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Display-Name", saID)
					a.logger.Info("auth.HTTP: SA principal injected", "id", saID)
					next.ServeHTTP(w, r)
					return
				}
				subj, lookupErr := a.subjectLookup.LookupByExternalID(r.Context(), subjectID)
				if lookupErr != nil {
					a.logger.Debug("auth.HTTP: SubjectLookup failed", "external_id", subjectID, "err", lookupErr.Error())
				} else {
					// Plain headers — WithMetadata callback in restmux форвардит.
					r.Header.Set("X-Kacho-Principal-Type", subj.Type)
					r.Header.Set("X-Kacho-Principal-Id", subj.ID)
					r.Header.Set("X-Kacho-Principal-Display-Name", subj.DisplayName)
					// Legacy form — grpc-gateway default convention fallback.
					r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Type", subj.Type)
					r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Id", subj.ID)
					r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Display-Name", subj.DisplayName)
					a.logger.Info("auth.HTTP: Principal injected", "type", subj.Type, "id", subj.ID)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
