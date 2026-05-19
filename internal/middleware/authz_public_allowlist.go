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

		// Operation polling — gated INSIDE the IAM/VPC/Compute services on
		// the underlying resource owner; running an extra Check here would
		// double-spend the budget for a noisy poll path.
		"kacho.cloud.operation.v1.OperationService/Get",
		"kacho.cloud.operation.v1.OperationService/List",
	}
}
