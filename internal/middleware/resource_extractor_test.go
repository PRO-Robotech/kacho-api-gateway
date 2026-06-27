// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
)

func TestResourceExtractor_FromProto_StringField(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			ObjectType:       "project",
			FromRequestField: "subject",
		},
	}
	req := &iamv1.AuthorizeCheckRequest{Subject: "user:usr_abc"}
	id, ok := e.ExtractFromProto(req, entry)
	require.True(t, ok)
	assert.Equal(t, "user:usr_abc", id.String())
	assert.False(t, id.IsWildcard())
}

func TestResourceExtractor_FromProto_ResourceRefMessage(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			ObjectType:       "project",
			FromRequestField: "resource",
		},
	}
	// ListSubjectsRequest has `resource` of type ResourceRef.
	req := &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "project", Id: "prj_billing_42"},
		Action:   "iam.authorize.listSubjects",
	}
	id, ok := e.ExtractFromProto(req, entry)
	require.True(t, ok)
	assert.Equal(t, "prj_billing_42", id.String())
}

func TestResourceExtractor_FromProto_MissingField_Wildcard(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			FromRequestField: "nonexistent_field",
		},
	}
	req := &iamv1.AuthorizeCheckRequest{Subject: "user:usr_abc"}
	id, ok := e.ExtractFromProto(req, entry)
	require.True(t, ok)
	assert.True(t, id.IsWildcard())
}

func TestResourceExtractor_FromProto_EmptyField_Wildcard(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{FromRequestField: ""},
	}
	id, ok := e.ExtractFromProto(&iamv1.AuthorizeCheckRequest{}, entry)
	require.True(t, ok)
	assert.True(t, id.IsWildcard())
}

func TestResourceExtractor_FromProto_StarField_Wildcard(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{FromRequestField: "*"},
	}
	id, ok := e.ExtractFromProto(&iamv1.AuthorizeCheckRequest{}, entry)
	require.True(t, ok)
	assert.True(t, id.IsWildcard())
}

func TestResourceExtractor_FromProto_NilRequest(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{FromRequestField: "subject"},
	}
	id, ok := e.ExtractFromProto(nil, entry)
	require.True(t, ok)
	assert.True(t, id.IsWildcard())
}

func TestResourceExtractor_FromHTTP_PathTemplate(t *testing.T) {
	e := middleware.NewResourceExtractor(map[string]string{
		"kacho.cloud.iam.v1.ProjectService/Get": "/iam/v1/projects/{project_id}",
	})
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			ObjectType:       "project",
			FromRequestField: "project_id",
		},
	}
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/projects/prj_alpha", nil)
	id, ok := e.ExtractFromHTTP(r, "kacho.cloud.iam.v1.ProjectService/Get", entry)
	require.True(t, ok)
	assert.Equal(t, "prj_alpha", id.String())
}

func TestResourceExtractor_FromHTTP_QueryStringFallback(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			FromRequestField: "folder_id",
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/vpc/v1/networks?folder_id=fld_x", nil)
	id, ok := e.ExtractFromHTTP(r, "kacho.cloud.vpc.v1.NetworkService/Create", entry)
	require.True(t, ok)
	assert.Equal(t, "fld_x", id.String())
}

func TestResourceExtractor_FromHTTP_ScopeIDFallback(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			FromRequestField: "some_field",
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/iam/v1/authorize:batchCheck?scope_id=prj_x", nil)
	id, ok := e.ExtractFromHTTP(r, "X/Y", entry)
	require.True(t, ok)
	assert.Equal(t, "prj_x", id.String())
}

func TestResourceExtractor_FromHTTP_NoMatch_Wildcard(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{
			FromRequestField: "missing",
		},
	}
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/something", nil)
	id, ok := e.ExtractFromHTTP(r, "X/Y", entry)
	require.True(t, ok)
	assert.True(t, id.IsWildcard())
}

func TestResourceExtractor_FromHTTP_NilRequest(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{FromRequestField: "subject"},
	}
	id, ok := e.ExtractFromHTTP(nil, "X/Y", entry)
	require.True(t, ok)
	assert.True(t, id.IsWildcard())
}

// dummyReq — non-proto struct to exercise the reflect fallback.
type dummyReq struct {
	NetworkID string
	FolderID  string
}

func TestResourceExtractor_FromProto_ReflectFallback(t *testing.T) {
	e := middleware.NewResourceExtractor(nil)
	entry := middleware.CatalogEntry{
		ScopeExtractor: middleware.ScopeExtractor{FromRequestField: "network_id"},
	}
	req := &dummyReq{NetworkID: "enp_x", FolderID: "fld_x"}
	id, ok := e.ExtractFromProto(req, entry)
	require.True(t, ok)
	assert.Equal(t, "enp_x", id.String())
}
