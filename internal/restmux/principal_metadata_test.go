// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package restmux

// principal_metadata_test.go — the internal-mux re-dial must forward the
// validated JWT acr (X-Kacho-Token-Acr, set by the public DPoP middleware)
// as x-kacho-token-acr metadata, alongside the existing x-kacho-principal-*
// headers, so the iam internal acr-floor can enforce required_acr_min on the
// :9091 path.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func newReqWithHeaders(h map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/iam/v1/internal/cluster/admins", nil)
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

// Principal metadata carries x-kacho-token-acr from the Grpc-Metadata-prefixed
// header the DPoP middleware sets.
func TestBuildPrincipalMetadata_ForwardsACR_GrpcPrefixed(t *testing.T) {
	md := buildPrincipalMetadata(newReqWithHeaders(map[string]string{
		"Grpc-Metadata-X-Kacho-Principal-Type": "user",
		"Grpc-Metadata-X-Kacho-Principal-Id":   "usr-alice",
		"Grpc-Metadata-X-Kacho-Token-Acr":      "2",
	}))
	require.Equal(t, []string{"user"}, md.Get("x-kacho-principal-type"))
	require.Equal(t, []string{"usr-alice"}, md.Get("x-kacho-principal-id"))
	require.Equal(t, []string{"2"}, md.Get("x-kacho-token-acr"),
		"the validated acr must be forwarded on the internal re-dial")
}

// The non-prefixed header variant is also accepted (robust).
func TestBuildPrincipalMetadata_ForwardsACR_PlainHeader(t *testing.T) {
	md := buildPrincipalMetadata(newReqWithHeaders(map[string]string{
		"X-Kacho-Principal-Type": "user",
		"X-Kacho-Principal-Id":   "usr-bob",
		"X-Kacho-Token-Acr":      "3",
	}))
	require.Equal(t, []string{"3"}, md.Get("x-kacho-token-acr"))
}

// Absent acr ⇒ the key is simply not appended (no empty value); the iam floor
// then treats it as acr=0 (fail-closed) — the gateway forwards only what the
// validated token carried.
func TestBuildPrincipalMetadata_NoACR_KeyOmitted(t *testing.T) {
	md := buildPrincipalMetadata(newReqWithHeaders(map[string]string{
		"Grpc-Metadata-X-Kacho-Principal-Type": "user",
		"Grpc-Metadata-X-Kacho-Principal-Id":   "usr-carol",
	}))
	require.Empty(t, md.Get("x-kacho-token-acr"), "absent acr ⇒ key not forwarded")
	// principal still forwarded as today.
	require.Equal(t, []string{"usr-carol"}, md.Get("x-kacho-principal-id"))
}
