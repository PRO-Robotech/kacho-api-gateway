package middleware_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestSubjectExtractor_UnifiedPrincipal_User(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		Subject: "hydra-sub-abc",
		ExtClaims: map[string]any{
			"kacho_principal_type": "user",
			"kacho_principal_id":   "usr_alice",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "user:usr_alice", r.FGA)
	assert.Equal(t, middleware.SubjectKindUser, r.Kind)
	assert.Equal(t, "usr_alice", r.ID)
}

func TestSubjectExtractor_UnifiedPrincipal_ServiceAccount(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		ExtClaims: map[string]any{
			"kacho_principal_type": "service_account",
			"kacho_principal_id":   "sva_robot",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "service_account:sva_robot", r.FGA)
	assert.Equal(t, middleware.SubjectKindServiceAccount, r.Kind)
}

func TestSubjectExtractor_UnifiedPrincipal_WorkloadAlias(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		ExtClaims: map[string]any{
			"kacho_principal_type": "workload",
			"kacho_principal_id":   "wid_pod1",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "workload:wid_pod1", r.FGA)
	assert.Equal(t, middleware.SubjectKindWorkload, r.Kind)
}

func TestSubjectExtractor_FallbackKachoUserID(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		ExtClaims: map[string]any{
			"kacho_user_id": "usr_legacy",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "user:usr_legacy", r.FGA)
	assert.Equal(t, "ext_claims.kacho_user_id", r.Source)
}

func TestSubjectExtractor_FallbackKachoSAID(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		ExtClaims: map[string]any{
			"kacho_sa_id": "sva_old",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "service_account:sva_old", r.FGA)
}

func TestSubjectExtractor_FallbackKachoWorkloadID(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		ExtClaims: map[string]any{
			"kacho_workload_id": "wid_xyz",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "workload:wid_xyz", r.FGA)
}

func TestSubjectExtractor_NoFallback_NoExtClaims_Rejects(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{Subject: "hydra-sub-xyz"}
	_, ok := e.Extract(tok)
	assert.False(t, ok)
}

func TestSubjectExtractor_AllowFallback_NoExtClaims_External(t *testing.T) {
	e := middleware.NewSubjectExtractor(true)
	tok := &middleware.VerifiedToken{Subject: "hydra-sub-xyz"}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "external:hydra-sub-xyz", r.FGA)
	assert.Equal(t, middleware.SubjectKindExternal, r.Kind)
	assert.Equal(t, "jwt.sub", r.Source)
}

func TestSubjectExtractor_NilToken(t *testing.T) {
	e := middleware.NewSubjectExtractor(true)
	_, ok := e.Extract(nil)
	assert.False(t, ok)
}

func TestSubjectExtractor_UnknownPrincipalType_FallsThrough(t *testing.T) {
	e := middleware.NewSubjectExtractor(false)
	tok := &middleware.VerifiedToken{
		ExtClaims: map[string]any{
			"kacho_principal_type": "alien",
			"kacho_principal_id":   "x",
			"kacho_user_id":        "usr_fallback",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "user:usr_fallback", r.FGA)
}

func TestSubjectExtractor_AliasFormats(t *testing.T) {
	tests := []struct {
		raw  string
		want middleware.SubjectKind
	}{
		{"user", middleware.SubjectKindUser},
		{"USR", middleware.SubjectKindUser},
		{"USER", middleware.SubjectKindUser},
		{"service_account", middleware.SubjectKindServiceAccount},
		{"service-account", middleware.SubjectKindServiceAccount},
		{"serviceaccount", middleware.SubjectKindServiceAccount},
		{"sva", middleware.SubjectKindServiceAccount},
		{"workload", middleware.SubjectKindWorkload},
		{"wid", middleware.SubjectKindWorkload},
	}
	e := middleware.NewSubjectExtractor(false)
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			tok := &middleware.VerifiedToken{
				ExtClaims: map[string]any{
					"kacho_principal_type": tt.raw,
					"kacho_principal_id":   "abc",
				},
			}
			r, ok := e.Extract(tok)
			require.True(t, ok)
			assert.Equal(t, tt.want, r.Kind)
		})
	}
}

func TestResolvedSubject_String(t *testing.T) {
	r := middleware.ResolvedSubject{FGA: "user:usr_x"}
	assert.Equal(t, "user:usr_x", r.String())
	assert.Equal(t, "<unknown>", middleware.ResolvedSubject{}.String())
}

func TestSubjectExtractor_EmptyPrincipalFields_FallsThrough(t *testing.T) {
	e := middleware.NewSubjectExtractor(true)
	// Both empty → should fall through to next rule (kacho_user_id) then sub fallback.
	tok := &middleware.VerifiedToken{
		Subject: "hydra-sub",
		ExtClaims: map[string]any{
			"kacho_principal_type": "",
			"kacho_principal_id":   "",
		},
	}
	r, ok := e.Extract(tok)
	require.True(t, ok)
	assert.Equal(t, "external:hydra-sub", r.FGA)
}
