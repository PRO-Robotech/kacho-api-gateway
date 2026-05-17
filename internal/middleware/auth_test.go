package middleware_test

// auth_test.go — unit-тесты AuthInterceptor (KAC-107 E2).

import (
	"context"
	stderrors "errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

type fakeLookup struct {
	subj middleware.Subject
	err  error
}

func (f *fakeLookup) LookupByExternalID(_ context.Context, _ string) (middleware.Subject, error) {
	return f.subj, f.err
}

func authTestLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func makeDevJWT(t *testing.T, secret, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

func TestAuth_DevMode_NoBearer_Anonymous(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "", nil, authTestLogger())
	called := false
	handler := func(ctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "system", p.Type)
		assert.Equal(t, "anonymous", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAuth_DevMode_ValidBearer_RealPrincipal(t *testing.T) {
	const secret = "dev-secret-test"
	lookup := &fakeLookup{subj: middleware.Subject{
		Type: "user", ID: "usr-alice", DisplayName: "Alice",
	}}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, secret, lookup, authTestLogger())

	jwt := makeDevJWT(t, secret, "zit-12345")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+jwt))

	handler := func(ctx context.Context, _ any) (any, error) {
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "user", p.Type)
		assert.Equal(t, "usr-alice", p.ID)
		assert.Equal(t, "Alice", p.DisplayName)
		md, _ := metadata.FromOutgoingContext(ctx)
		assert.Equal(t, []string{"user"}, md.Get("x-kacho-principal-type"))
		assert.Equal(t, []string{"usr-alice"}, md.Get("x-kacho-principal-id"))
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.NoError(t, err)
}

func TestAuth_DevMode_InvalidBearer_FallbackAnonymous(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeDev, "secret", &fakeLookup{}, authTestLogger())
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer not-a-jwt"))

	called := false
	handler := func(ctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "system", p.Type)
		assert.Equal(t, "anonymous", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAuth_ProductionStrict_NoBearer_Rejected(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProductionStrict, "", &fakeLookup{}, authTestLogger())
	handler := func(_ context.Context, _ any) (any, error) {
		t.Fatal("handler must not be called")
		return nil, nil
	}
	_, err := auth.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "missing Bearer")
}

func TestAuth_Production_SubjectNotFound_Rejected(t *testing.T) {
	const secret = "prod-secret"
	lookup := &fakeLookup{err: stderrors.New("subject not found")}
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProduction, secret, lookup, authTestLogger())

	jwt := makeDevJWT(t, secret, "zit-missing")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+jwt))

	handler := func(_ context.Context, _ any) (any, error) {
		t.Fatal("handler must not be called")
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuth_Production_InvalidBearer_Rejected(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProduction, "secret", &fakeLookup{}, authTestLogger())
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer garbage"))

	handler := func(_ context.Context, _ any) (any, error) {
		t.Fatal("handler must not be called")
		return nil, nil
	}
	_, err := auth.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestAuth_Production_NoBearer_AllowsAnonymous(t *testing.T) {
	auth := middleware.NewAuthInterceptor(middleware.AuthModeProduction, "secret", &fakeLookup{}, authTestLogger())
	called := false
	handler := func(ctx context.Context, _ any) (any, error) {
		called = true
		p := operations.PrincipalFromContext(ctx)
		assert.Equal(t, "system", p.Type)
		assert.Equal(t, "anonymous", p.ID)
		return nil, nil
	}
	_, err := auth.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)
	require.NoError(t, err)
	assert.True(t, called)
}
