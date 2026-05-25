package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

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

// KAC-197 regression: grpc-gateway suffix-action path templates
// (`/<resource>/{id}:verb`) must extract the {id} placeholder. Prior to the
// fix the extractor rejected the last segment because it ended with the verb
// (`}` was no longer the last char), produced wildcard, and every mutating
// `:verb` RPC on a path-param resource (AddCidrBlocks / RemoveCidrBlocks /
// Move / Relocate / Activate / Cancel / …) returned 403 `no path: unscoped
// resource`. Discovered probe POST /vpc/v1/subnets/<id>:add-cidr-blocks.
func TestResourceExtractor_FromHTTP_PathTemplate_VerbSuffix(t *testing.T) {
	e := middleware.NewResourceExtractor(map[string]string{
		"kacho.cloud.vpc.v1.SubnetService/AddCidrBlocks": "/vpc/v1/subnets/{subnet_id}:add-cidr-blocks",
		"kacho.cloud.vpc.v1.SubnetService/Move":          "/vpc/v1/subnets/{subnet_id}:move",
		"kacho.cloud.iam.v1.ProjectService/Activate":     "/iam/v1/projects/{project_id}:activate",
	})
	cases := []struct {
		name, fqn, path, field, want string
	}{
		{"vpc-add-cidr-blocks", "kacho.cloud.vpc.v1.SubnetService/AddCidrBlocks", "/vpc/v1/subnets/e9b906y2arwnjg6g0gs8:add-cidr-blocks", "subnet_id", "e9b906y2arwnjg6g0gs8"},
		{"vpc-move", "kacho.cloud.vpc.v1.SubnetService/Move", "/vpc/v1/subnets/e9b906y2arwnjg6g0gs8:move", "subnet_id", "e9b906y2arwnjg6g0gs8"},
		{"iam-activate", "kacho.cloud.iam.v1.ProjectService/Activate", "/iam/v1/projects/prj_alpha:activate", "project_id", "prj_alpha"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := middleware.CatalogEntry{
				ScopeExtractor: middleware.ScopeExtractor{FromRequestField: tc.field},
			}
			r := httptest.NewRequest(http.MethodPost, tc.path, nil)
			id, ok := e.ExtractFromHTTP(r, tc.fqn, entry)
			require.True(t, ok)
			assert.Equal(t, tc.want, id.String(), "verb-suffix path placeholder must be extracted")
			assert.False(t, id.IsWildcard(), "must not fall back to wildcard")
		})
	}
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
