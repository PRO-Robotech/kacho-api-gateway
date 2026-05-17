// Package middleware — auth.go: JWT validation + Principal injection (KAC-107 E2).
//
// Replaces auth_noop.go. Поведение зависит от cfg.AuthN.Mode:
//
//   - **dev** (default): backwards-compat. Без Bearer — pass-through anonymous
//     (Principal{system, anonymous}). С Bearer — валидируется как HMAC-dev token
//     (`KACHO_API_GATEWAY_AUTHN_DEV_SECRET`); subject claim — Zitadel external_id;
//     если subject не находится в kacho_iam — fallback на anonymous, чтобы не
//     ломать существующие newman-сценарии.
//   - **production**: Bearer обязателен только для non-anonymous endpoints
//     (которые сейчас никак не маркированы — placeholder). Валидируется через
//     Zitadel JWKS (TODO — после fix'а Zitadel deploy). Subject lookup → kacho-iam.
//     NotFound → lazy-mirror через `InternalUserService.UpsertFromIdentity`.
//   - **production-strict**: Bearer обязателен **всегда** (`Unauthenticated`
//     без него); все остальные правила — как в production.
//
// Архитектура (acceptance §4.3):
//   ┌─ parse Bearer ─┐    ┌─ JWT validate ─┐    ┌─ SubjectLookup ─┐    ┌─ Principal in ctx ─┐
//   │ Authorization │ → │ JWKS/HMAC      │ → │ kacho-iam:9091  │ → │ x-kacho-principal-* │
//   └────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────────┘
//
// Loop-prevention запрет #6: InternalIAMService.LookupSubject зовётся
// **gRPC-direct** (через iamSubjectClient), НЕ через restmux, иначе recursion.
package middleware

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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

// Subject — резолвленный subject (User или ServiceAccount).
type Subject struct {
	Type        string // "user" | "service_account"
	ID          string
	DisplayName string
}

// AuthInterceptor — JWT validate + subject lookup + Principal injection.
type AuthInterceptor struct {
	mode          AuthMode
	devSecret     []byte // HMAC-secret для mode=dev (если пуст — Bearer reject в dev/production-strict).
	subjectLookup SubjectLookuper
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

	// Validate JWT (HMAC-dev для текущей фазы; Zitadel JWKS — после deploy fix).
	claims, err := a.validateJWT(bearer)
	if err != nil {
		// dev mode: tolerate invalid Bearer → fallback anonymous (backwards-compat).
		if a.mode == AuthModeDev {
			a.logger.Debug("auth: invalid Bearer in dev mode, falling back to anonymous",
				"method", fullMethod, "err", err)
			return a.injectAnonymous(ctx), nil
		}
		a.logger.Warn("auth: JWT validation failed",
			"method", fullMethod, "err", err)
		return nil, status.Errorf(codes.Unauthenticated, "token validation failed: %v", err)
	}

	// Resolve subject via kacho-iam (gRPC-direct).
	subjectID, _ := claims["sub"].(string)
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

func (a *AuthInterceptor) validateJWT(tokenStr string) (jwt.MapClaims, error) {
	if len(a.devSecret) == 0 {
		// TODO(KAC-107 follow-up): Zitadel JWKS-validate ветка после фикса Zitadel deploy.
		// Сейчас в production / production-strict без dev-secret — auth не пройдёт.
		return nil, fmt.Errorf("no signing key configured (dev secret empty, Zitadel JWKS deferred)")
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
		// Cookie → Bearer rewrite (D5) — KAC-107 follow-up.
		if r.Header.Get("Authorization") == "" {
			if c, err := r.Cookie("kacho_session"); err == nil && c.Value != "" {
				r.Header.Set("Authorization", "Bearer "+c.Value)
			}
		}

		// KAC-107 follow-up #2: REST→backend Principal propagation.
		// gRPC server interceptor работает только для grpc-proxy path, не для grpc-gateway
		// REST. Здесь делаем JWT-parse + SubjectLookup + ставим headers
		// `Grpc-Metadata-X-Kacho-Principal-*` — grpc-gateway runtime по умолчанию
		// форвардит их как outgoing metadata `x-kacho-principal-*`, которые backend
		// читает через corelib/grpcsrv.UnaryPrincipalExtract.
		if auth := r.Header.Get("Authorization"); auth != "" && len(a.devSecret) > 0 {
			if tok, ok := strings.CutPrefix(auth, "Bearer "); ok {
				if claims, err := a.validateJWT(tok); err == nil {
					subjectID, _ := claims["sub"].(string)
					if subjectID != "" {
						if subj, err := a.subjectLookup.LookupByExternalID(r.Context(), subjectID); err == nil {
							r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Type", subj.Type)
							r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Id", subj.ID)
							r.Header.Set("Grpc-Metadata-X-Kacho-Principal-Display-Name", subj.DisplayName)
						}
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
