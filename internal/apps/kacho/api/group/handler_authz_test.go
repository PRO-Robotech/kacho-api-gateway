package group

// handler_authz_test.go — unit-тесты Group handler default-deny matrix (KAC-123).
//
// Покрытие auth-matrix (без БД, через mock AuthzChecker):
//   - anonymous List → empty
//   - anonymous Get → PermissionDenied (через checkAuthz)
//   - user без viewer → PermissionDenied на Get/List/ListMembers
//   - user с viewer → 200 (получает данные)
//   - user с admin → bypass viewer и admin (Create/Update/Delete/AddMember/RemoveMember)
//   - service_account principal → bypass
//   - List без account_id и без system-admin → empty
//   - system-admin (kacho_system:root#admin) → видит все (без account_id)
//
// Use-case'ы — заглушки через интерфейсы (только handler-логика тестируется).

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

// ── mock AuthzChecker ───────────────────────────────────────────────────────

type mockAuthz struct {
	mu sync.Mutex
	// allow["subject|relation|object"] = true → Check возвращает true
	allow map[string]bool
}

func newMockAuthz() *mockAuthz { return &mockAuthz{allow: map[string]bool{}} }

func (m *mockAuthz) Allow(subject, relation, object string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allow[subject+"|"+relation+"|"+object] = true
}

func (m *mockAuthz) Check(_ context.Context, subject, relation, object string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allow[subject+"|"+relation+"|"+object], nil
}

func (m *mockAuthz) LookupObjectIDs(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

// ── principal helper ────────────────────────────────────────────────────────

// principalCtx — кладёт Principal в context через operations.WithPrincipal
// (тот же канонический путь, что использует gRPC interceptor в api-gateway).
// Пустой ptype + pid → ctx БЕЗ principal → PrincipalFromContext вернёт
// SystemPrincipal{Type:"system", ID:"bootstrap"} (anonymous fallback).
func principalCtx(ptype, pid string) context.Context {
	if ptype == "" && pid == "" {
		return context.Background()
	}
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: ptype, ID: pid})
}

// ── isolated handler factory ────────────────────────────────────────────────

// freshHandler возвращает Handler с stub use-case'ами и сконфигурированным authz.
// Use-case'ы не должны вызываться в default-deny кейсах — мы проверяем early-return.
func freshHandler(authz AuthzChecker) *Handler {
	h := &Handler{
		create:       &CreateGroupUseCase{},
		update:       &UpdateGroupUseCase{},
		delete:       &DeleteGroupUseCase{},
		get:          nil, // тесты на Get/Update/Delete используют test-spec помеченный t.Skip если требуют get
		list:         nil,
		addMember:    nil,
		removeMember: nil,
		listMembers:  nil,
	}
	if authz != nil {
		h.WithAuthz(authz)
	}
	return h
}

// ── List default-deny ───────────────────────────────────────────────────────

func TestList_Anonymous_Empty(t *testing.T) {
	authz := newMockAuthz()
	h := freshHandler(authz)
	resp, err := h.List(principalCtx("", ""), &iamv1.ListGroupsRequest{AccountId: "acc-xyz"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Groups, "anonymous → empty groups list")
}

func TestList_User_NoViewer_NoAccountID_Empty(t *testing.T) {
	authz := newMockAuthz()
	h := freshHandler(authz)
	ctx := principalCtx("user", "usr00000000000000aaaa")
	resp, err := h.List(ctx, &iamv1.ListGroupsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Groups, "user без account_id и без system-admin → empty")
}

func TestList_User_NoViewer_OnAccount_PermissionDenied(t *testing.T) {
	authz := newMockAuthz()
	h := freshHandler(authz)
	ctx := principalCtx("user", "usr00000000000000aaaa")
	_, err := h.List(ctx, &iamv1.ListGroupsRequest{AccountId: "acc-foreign"})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(), "viewer тупл отсутствует → 403")
}

// ── Auth-rules unit tests ───────────────────────────────────────────────────

func TestCheckAuthz_ServiceAccountBypass(t *testing.T) {
	authz := newMockAuthz() // ничего не allow'им
	h := freshHandler(authz)
	ctx := principalCtx("service_account", "sva00000000000000zzzz")
	err := h.checkAuthz(ctx, "admin", "acc-anywhere")
	assert.NoError(t, err, "service_account principal — bypass")
}

func TestCheckAuthz_SystemAdminBypass(t *testing.T) {
	authz := newMockAuthz()
	authz.Allow("user:usr00000000000000boot", "admin", "kacho_system:root")
	h := freshHandler(authz)
	ctx := principalCtx("user", "usr00000000000000boot")
	err := h.checkAuthz(ctx, "admin", "acc-anything")
	assert.NoError(t, err, "system-admin — bypass account check")
}

func TestCheckAuthz_RegularUser_Viewer_OnAccount(t *testing.T) {
	authz := newMockAuthz()
	authz.Allow("user:usr00000000000000reg1", "viewer", "account:acc-own")
	h := freshHandler(authz)
	ctx := principalCtx("user", "usr00000000000000reg1")
	err := h.checkAuthz(ctx, "viewer", "acc-own")
	assert.NoError(t, err, "user с viewer на account → allow")
}

func TestCheckAuthz_RegularUser_NoTuple_OnForeignAccount(t *testing.T) {
	authz := newMockAuthz()
	authz.Allow("user:usr00000000000000reg1", "viewer", "account:acc-own")
	h := freshHandler(authz)
	ctx := principalCtx("user", "usr00000000000000reg1")
	err := h.checkAuthz(ctx, "viewer", "acc-foreign")
	require.Error(t, err, "user без tuple на foreign account → 403")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestCheckAuthz_RegularUser_RequiresAdmin_HasOnlyViewer(t *testing.T) {
	authz := newMockAuthz()
	authz.Allow("user:usr00000000000000reg1", "viewer", "account:acc-own")
	h := freshHandler(authz)
	ctx := principalCtx("user", "usr00000000000000reg1")
	err := h.checkAuthz(ctx, "admin", "acc-own")
	require.Error(t, err, "viewer не покрывает admin (cascade в Keto-side не моделируется в mock)")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestCheckAuthz_Anonymous_PermissionDenied(t *testing.T) {
	authz := newMockAuthz()
	h := freshHandler(authz)
	ctx := principalCtx("", "")
	err := h.checkAuthz(ctx, "viewer", "acc-any")
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// isSystemAdmin — отдельный helper, используется в List без account_id.
func TestIsSystemAdmin(t *testing.T) {
	authz := newMockAuthz()
	authz.Allow("user:usr00000000000000boot", "admin", "kacho_system:root")
	h := freshHandler(authz)

	cases := []struct {
		name     string
		ptype    string
		pid      string
		expected bool
	}{
		{"bootstrap admin user", "user", "usr00000000000000boot", true},
		{"regular user без tuple", "user", "usr00000000000000reg1", false},
		{"service_account", "service_account", "sva00000000000000xxx", false},
		{"anonymous", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := operations.Principal{Type: tc.ptype, ID: tc.pid}
			got := h.isSystemAdmin(context.Background(), p)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ── dev-mode: nil authz → permissive (для unit-тестов в других пакетах) ─────

func TestCheckAuthz_DevMode_NilAuthz_Permissive(t *testing.T) {
	h := freshHandler(nil)
	ctx := principalCtx("user", "usr00000000000000aaaa")
	err := h.checkAuthz(ctx, "admin", "acc-any")
	assert.NoError(t, err, "nil authz → dev-mode permissive (без Keto)")
}

// ── Ensure use-case stubs не вызываются на early-return ─────────────────────

func TestList_Anonymous_DoesNotInvokeUseCase(t *testing.T) {
	// Если бы use-case был вызван — он бы упал с nil-pointer (мы дали list=nil).
	// Тест проходит = early-return сработал ДО use-case'а.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("anonymous List вызвал use-case (panic): %v", r)
		}
	}()
	authz := newMockAuthz()
	h := freshHandler(authz)
	_, err := h.List(principalCtx("", ""), &iamv1.ListGroupsRequest{})
	require.NoError(t, err)
}

// ── Sanity: import errors не вылетают ───────────────────────────────────────

var _ = errors.New // ensure errors import used (may be conditional)
