package access_binding

// handler_authz_test.go — unit-тесты AccessBinding ListBySubject default-deny (KAC-123).
//
// Покрытие auth-matrix без БД:
//   - anonymous → empty list (НЕ ошибка)
//   - service_account principal → bypass (admin-tooling)
//   - user principal → cross-user listBySubject → PermissionDenied
//   - user principal → свой listBySubject → use-case вызывается

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

func principalCtx(ptype, pid string) context.Context {
	if ptype == "" && pid == "" {
		return context.Background()
	}
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: ptype, ID: pid})
}

// stubHandler — без use-case'ов; default-deny ветка должна срабатывать до их вызова.
func stubHandler() *Handler {
	return &Handler{}
}

func TestListBySubject_Anonymous_Empty(t *testing.T) {
	h := stubHandler()
	resp, err := h.ListBySubject(principalCtx("", ""), &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "user",
		SubjectId:   "usr00000000000000abcd",
	})
	require.NoError(t, err, "anonymous → empty, не error")
	require.NotNil(t, resp)
	assert.Empty(t, resp.AccessBindings)
}

func TestListBySubject_User_CrossUser_PermissionDenied(t *testing.T) {
	h := stubHandler()
	ctx := principalCtx("user", "usr00000000000000aaaa")
	_, err := h.ListBySubject(ctx, &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "user",
		SubjectId:   "usr00000000000000bbbb", // другой user!
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"user не может смотреть AB другого user'а")
}

func TestListBySubject_User_NonUserSubjectType_PermissionDenied(t *testing.T) {
	h := stubHandler()
	ctx := principalCtx("user", "usr00000000000000aaaa")
	_, err := h.ListBySubject(ctx, &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "service_account",
		SubjectId:   "sva00000000000000xxxx",
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"user не может смотреть AB service_account / group")
}

// User для своих bindings — должен ДОЙТИ до use-case'а (а тот nil → panic recover).
// Тест проходит = early-return НЕ сработал на self-subject.
func TestListBySubject_User_OwnBindings_PassesAuthGate(t *testing.T) {
	h := stubHandler()
	ctx := principalCtx("user", "usr00000000000000aaaa")
	defer func() {
		// nil use-case → panic ожидаем; это значит, что auth-gate пропустил вызов.
		if r := recover(); r == nil {
			t.Fatal("ожидался panic от nil use-case'а — это доказывает, что auth-gate пропустил self-subject")
		}
	}()
	_, _ = h.ListBySubject(ctx, &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "user",
		SubjectId:   "usr00000000000000aaaa", // тот же → auth-gate должен пропустить
	})
}

// service_account principal → bypass auth-gate (admin tooling).
func TestListBySubject_ServiceAccount_Bypass(t *testing.T) {
	h := stubHandler()
	ctx := principalCtx("service_account", "sva00000000000000xxxx")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("ожидался panic от nil use-case'а — это доказывает bypass для SA")
		}
	}()
	_, _ = h.ListBySubject(ctx, &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "user",
		SubjectId:   "usr00000000000000zzzz", // любой subject — SA bypass'ит
	})
}
