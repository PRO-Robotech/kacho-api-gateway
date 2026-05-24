// authz_public_allowlist.go — fixed list of gRPC FQNs that bypass the
// per-RPC AuthZ middleware regardless of catalog content (KAC-127 Phase 3).
//
// Public allow-list rationale (acceptance §5.4 + design §17):
//
//	- Login / Register / Recovery flows MUST run pre-authn; the user has
//	  no subject yet.
//	- Back-channel logout (Hydra → kacho-iam) is HMAC-signed at a separate
//	  layer; subject-injection is unavailable.
//	- Health probes are infrastructure-internal — gating them would let an
//	  authz outage cascade into rolling-restart loops.
//	- OperationService.Get + List are intentionally cheap reads that the
//	  client polls many times; the catalog gates them at the resource-id
//	  level inside the IAM service itself rather than at the gateway edge.
//
// The list is intentionally short — every entry is a known-public RPC. Any
// additional bypass MUST go through the `authz_overrides.yaml` mechanism
// (auditable, hot-reloadable) instead of being baked into this code path.
package middleware

// DefaultPublicAllowlist returns the curated list of gRPC FQNs that pass
// through the AuthZ middleware without any AuthorizeService.Check call.
//
// Sorted alphabetically — keep that property when adding entries; tests
// rely on it.
func DefaultPublicAllowlist() []string {
	return []string{
		// gRPC health.
		"grpc.health.v1.Health/Check",
		"grpc.health.v1.Health/Watch",

		// gRPC reflection (only available cluster-internal anyway via the
		// gateway; included so internal admin tooling does not need an
		// authz token).
		"grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",

		// Phase 2 back-channel logout / token revocation flows — these
		// authenticate the *gateway* to Hydra, not the end-user.
		"kacho.cloud.iam.v1.BackChannelLogoutService/PushLogout",

		// OAuth/OIDC auth flows on the public RPC surface — kicked off by
		// an unauthenticated client; the IAM service enforces step-up at
		// its own layer.
		"kacho.cloud.iam.v1.AuthService/Login",
		"kacho.cloud.iam.v1.AuthService/Logout",
		"kacho.cloud.iam.v1.AuthService/Recovery",
		"kacho.cloud.iam.v1.AuthService/RecoveryFinalise",
		"kacho.cloud.iam.v1.AuthService/Register",

		// Operation polling — the catalog entries for OperationService use
		// permission "<exempt>" (require authentication, skip FGA Check).
		// These FQNs are NOT on the public allowlist; authentication is still
		// enforced via the catalog exempt path.  The allowlist entries here
		// were removed in KAC-127 because the proto package is
		// "kacho.cloud.operation" (no ".v1."), the old "v1" FQNs never
		// matched and silently left OperationService unprotected only at the
		// allowlist level — the catalog path continued to apply.

		// KAC-185 (F4): Internal IAM RPCs — cluster-internal listener callers
		// (api-gateway auth-interceptor self-call, admin tooling via port-forward,
		// kacho-iam subject-change drainer) DO NOT carry external user JWTs.
		// The catalog marks them `<exempt>` from FGA Check but the `<exempt>`
		// path STILL enforces authentication — so without an allowlist entry,
		// these unauth'd internal calls would fail with Unauthenticated/401.
		//
		// §«Запреты» #6 isolation is enforced at the LISTENER layer: the
		// external TLS listener (api.kacho.local:443) is firewalled / not
		// exposed to tenant networks; the gRPC director's HasInternalSuffix
		// blocks Internal* gRPC on the public listener. Adding these FQNs to
		// the public allowlist does NOT widen exposure — it only lets the
		// already-internal caller through the authz gate that the catalog
		// would otherwise close.
		"kacho.cloud.iam.v1.InternalIAMService/Check",
		"kacho.cloud.iam.v1.InternalIAMService/ListPermissions",
		"kacho.cloud.iam.v1.InternalIAMService/LookupSubject",
		"kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
	}
}
