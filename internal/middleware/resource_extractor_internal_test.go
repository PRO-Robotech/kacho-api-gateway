// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// resource_extractor_internal_test.go — internal (same-package) tests for
// helpers that are not exported. Kept separate from the external _test.go
// so the public-API tests stay in `package middleware_test`.
package middleware

import "testing"

// TestExtractByPathTemplate_VerbSuffix — grpc-gateway `:verb` suffix-action
// segments (e.g. `/vpc/v1/subnets/{subnet_id}:add-cidr-blocks`) must match the
// segment-by-segment template matcher: the final segment
// `{subnet_id}:add-cidr-blocks` is split into placeholder + verb so the scope id
// is extracted instead of falling through to wildcard `*` (which would AUTHZ_DENY
// "no path: unscoped resource" 403 on AddCidrBlocks, RemoveCidrBlocks, etc).
func TestExtractByPathTemplate_VerbSuffix(t *testing.T) {
	cases := []struct {
		name     string
		template string
		path     string
		field    string
		wantID   string
		wantOK   bool
	}{
		{
			name:     "subnet AddCidrBlocks",
			template: "/vpc/v1/subnets/{subnet_id}:add-cidr-blocks",
			path:     "/vpc/v1/subnets/e9bqg6j72e6cjyv80gkf:add-cidr-blocks",
			field:    "subnet_id",
			wantID:   "e9bqg6j72e6cjyv80gkf",
			wantOK:   true,
		},
		{
			name:     "subnet RemoveCidrBlocks",
			template: "/vpc/v1/subnets/{subnet_id}:remove-cidr-blocks",
			path:     "/vpc/v1/subnets/sub_xyz:remove-cidr-blocks",
			field:    "subnet_id",
			wantID:   "sub_xyz",
			wantOK:   true,
		},
		{
			name:     "plain placeholder (no verb) still works",
			template: "/iam/v1/projects/{project_id}",
			path:     "/iam/v1/projects/prj_abc",
			field:    "project_id",
			wantID:   "prj_abc",
			wantOK:   true,
		},
		{
			name:     "verb mismatch — wrong verb rejects",
			template: "/vpc/v1/subnets/{subnet_id}:add-cidr-blocks",
			path:     "/vpc/v1/subnets/abc:remove-cidr-blocks",
			field:    "subnet_id",
			wantID:   "",
			wantOK:   false,
		},
		{
			name:     "collection-level :verb (no placeholder)",
			template: "/iam/v1/users:invite",
			path:     "/iam/v1/users:invite",
			field:    "user_id",
			wantID:   "",
			wantOK:   false,
		},
		{
			name:     "different segment count — no match",
			template: "/vpc/v1/subnets/{subnet_id}:add-cidr-blocks",
			path:     "/vpc/v1/subnets/abc/extra:add-cidr-blocks",
			field:    "subnet_id",
			wantID:   "",
			wantOK:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotOK := extractByPathTemplate(tc.path, tc.template, tc.field)
			if gotID != tc.wantID || gotOK != tc.wantOK {
				t.Fatalf("extractByPathTemplate(%q,%q,%q) = (%q,%v); want (%q,%v)",
					tc.path, tc.template, tc.field, gotID, gotOK, tc.wantID, tc.wantOK)
			}
		})
	}
}

// TestSplitVerbSuffix — basic boundary cases for the helper.
func TestSplitVerbSuffix(t *testing.T) {
	cases := []struct {
		in       string
		wantBase string
		wantVerb string
	}{
		{"x:add", "x", "add"},
		{"{subnet_id}:add-cidr-blocks", "{subnet_id}", "add-cidr-blocks"},
		{"users:invite", "users", "invite"},
		{"plain", "plain", ""},
		{"", "", ""},
		// leading colon — degenerate; treated as no verb.
		{":nothing", ":nothing", ""},
	}
	for _, tc := range cases {
		gotBase, gotVerb := splitVerbSuffix(tc.in)
		if gotBase != tc.wantBase || gotVerb != tc.wantVerb {
			t.Errorf("splitVerbSuffix(%q) = (%q,%q); want (%q,%q)",
				tc.in, gotBase, gotVerb, tc.wantBase, tc.wantVerb)
		}
	}
}
