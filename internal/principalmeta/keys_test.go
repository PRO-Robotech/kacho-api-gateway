// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package principalmeta_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/principalmeta"
)

// TestKeyForms_Consistent pins the three surface forms of each key to one
// another so a future edit cannot silently desync them (the exact break the
// package exists to prevent).
func TestKeyForms_Consistent(t *testing.T) {
	cases := []struct {
		header, grpcMeta, meta string
	}{
		{principalmeta.HeaderPrincipalType, principalmeta.HeaderGRPCMetaPrincipalType, principalmeta.MetaPrincipalType},
		{principalmeta.HeaderPrincipalID, principalmeta.HeaderGRPCMetaPrincipalID, principalmeta.MetaPrincipalID},
		{principalmeta.HeaderPrincipalDisplay, principalmeta.HeaderGRPCMetaPrincipalDisplay, principalmeta.MetaPrincipalDisplay},
		{principalmeta.HeaderTokenACR, principalmeta.HeaderGRPCMetaTokenACR, principalmeta.MetaTokenACR},
		{principalmeta.HeaderTokenJti, principalmeta.HeaderGRPCMetaTokenJti, principalmeta.MetaTokenJti},
		{principalmeta.HeaderTokenScope, principalmeta.HeaderGRPCMetaTokenScope, principalmeta.MetaTokenScope},
	}
	for _, c := range cases {
		// Grpc-Metadata- prefix.
		if want := "Grpc-Metadata-" + c.header; c.grpcMeta != want {
			t.Errorf("grpcMeta %q != %q", c.grpcMeta, want)
		}
		// Meta form is the lowercase of the canonical header.
		if want := strings.ToLower(c.header); c.meta != want {
			t.Errorf("meta %q != lowercase(header) %q", c.meta, want)
		}
		// Canonical form is what http.Header canonicalises to (round-trip).
		if got := http.CanonicalHeaderKey(c.header); got != c.header {
			t.Errorf("header %q is not canonical (http.CanonicalHeaderKey → %q)", c.header, got)
		}
	}
}

// TestHeaderTokenExp_Canonical pins the audit-only exp header's wire value.
// It has no Grpc-Metadata-/meta consumer form (producer-only, downstream
// audit), so it is asserted on its own rather than in the three-form table.
func TestHeaderTokenExp_Canonical(t *testing.T) {
	if got := http.CanonicalHeaderKey(principalmeta.HeaderTokenExp); got != principalmeta.HeaderTokenExp {
		t.Errorf("HeaderTokenExp %q is not canonical (http.CanonicalHeaderKey → %q)", principalmeta.HeaderTokenExp, got)
	}
}

// TestPrefixes match the meta forms.
func TestPrefixes(t *testing.T) {
	if !strings.HasPrefix(principalmeta.MetaPrincipalType, principalmeta.MetaPrincipalPrefix) {
		t.Errorf("MetaPrincipalType %q must start with prefix %q", principalmeta.MetaPrincipalType, principalmeta.MetaPrincipalPrefix)
	}
	if want := "grpc-metadata-" + principalmeta.MetaPrincipalPrefix; principalmeta.MetaGRPCPrincipalPrefix != want {
		t.Errorf("MetaGRPCPrincipalPrefix %q != %q", principalmeta.MetaGRPCPrincipalPrefix, want)
	}
}
