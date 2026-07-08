// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authz_public_allowlist.go — fixed list of gRPC FQNs that bypass the
// per-RPC AuthZ middleware regardless of catalog content.
//
// Public allow-list rationale:
//
//   - Login / Register / Recovery flows MUST run pre-authn; the user has
//     no subject yet.
//   - Back-channel logout (Hydra → kacho-iam) is HMAC-signed at a separate
//     layer; subject-injection is unavailable.
//   - Health probes are infrastructure-internal — gating them would let an
//     authz outage cascade into rolling-restart loops.
//
// NOTE: OperationService.Get/List are deliberately NOT on this allow-list.
// They are frequently polled but still require authentication — handled via
// the catalog "<exempt>" path (authenticate, skip the FGA Check), never a
// blanket per-RPC AuthZ bypass at the gateway edge (see the OperationService
// comment in DefaultPublicAllowlist below).
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

		// Back-channel logout / token revocation flows — these
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

		// OperationService polling is NOT on this public allowlist:
		// authentication is still enforced via the catalog "<exempt>" path
		// (require authentication, skip FGA Check). Its proto package is
		// "kacho.cloud.operation" (no ".v1."), so a stale "v1" allowlist entry
		// would never match and would only weaken the allowlist level while the
		// catalog path keeps applying.

		// SECURITY: Internal* FQNs are deliberately NOT on this global allowlist.
		//
		// The REST path serves both the internal and the advertised external
		// TLS listener from the SAME *http.Server, so a global FQN allowlist
		// would short-circuit decide() to ALLOW even for an UNAUTHENTICATED
		// caller hitting these RPCs from the edge — an authz-oracle /
		// user-enumeration / user-mutation priv-esc.
		//
		// Internal callers (api-gateway auth-interceptor self-call, admin tooling
		// via port-forward, kacho-iam subject-change drainer) still carry no
		// external user JWT — but they arrive on the cluster-internal listener.
		// They are admitted by the LISTENER-ORIGIN gate in decide()
		// (allowlist.HasInternalSuffix + !listenerorigin.IsExternal) instead of a
		// blanket FQN bypass, so an external caller of these is authN-required /
		// rejected while an internal caller still passes. Defense-in-depth: the
		// REST dispatcher additionally 404s Internal* paths on the external
		// listener (restmux.NewMux), and the gRPC routing layer blocks Internal*
		// gRPC everywhere (HasInternalSuffix).
	}
}
