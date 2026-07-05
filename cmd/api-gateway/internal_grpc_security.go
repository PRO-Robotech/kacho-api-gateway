// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_grpc_security.go — security posture for the cluster-internal gRPC
// listener (InternalAuthzCacheService, port 9091).
//
// security.md invariant #1/#4: the internal perimeter is NOT a trusted zone.
// Every listener — public AND internal — enforces mTLS transport (AuthN) plus a
// per-RPC authorization decision (AuthZ). Without this, any in-cluster caller
// could dial the listener and flush the api-gateway authz decision-cache
// (cache-flush DoS / IAM-amplification).
//
// This file assembles that posture from Config:
//   - mTLS server credentials: RequireAndVerifyClientCert against the internal CA
//     (grpcsrv.TLSServerCreds), config-gated so it is enforced in production while
//     dev/local may opt into an insecure listener.
//   - a per-RPC SPIFFE allow-list interceptor: the verified client cert SAN must
//     be on the caller allow-list (the iam push-drainer identity) — a verified but
//     non-allow-listed module identity is rejected (confused-deputy defence).
//   - a production guard: an insecure internal listener is refused under a
//     production-class env (secure-by-default; empty/unset env is production-class).
package main

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

// internalListenerSecurity carries the resolved security posture for the
// cluster-internal gRPC listener: mTLS server credentials, the SPIFFE-SAN
// allow-list authorising callers, and whether gRPC reflection is exposed.
type internalListenerSecurity struct {
	// mtlsEnabled gates transport security. false ⇒ insecure listener (dev/local
	// backward-compat), interceptors NOT mounted. true ⇒ serverCreds + allow-list
	// enforced.
	mtlsEnabled bool
	// serverCreds is the mTLS server-credentials option
	// (RequireAndVerifyClientCert against the internal CA). Non-nil ⇔ mtlsEnabled.
	serverCreds grpc.ServerOption
	// allowedSPIFFE is the set of verified client SANs authorised to invoke the
	// listener's RPCs (the iam push-drainer identity). Enforced only under mTLS.
	allowedSPIFFE map[string]struct{}
	// reflection exposes gRPC server-reflection when true (debug/incident only).
	reflection bool
}

// buildInternalListenerSecurity resolves the internal-listener security posture
// from Config. It is fail-fast: an enabled listener missing server cert/key/CA or
// with an empty caller allow-list aborts the build (the process must not come up
// half-secured). When disabled it returns the insecure posture (dev/local); the
// production guard (validateProductionInternalListener) refuses that posture in a
// production-class env.
func buildInternalListenerSecurity(cfg config.Config) (internalListenerSecurity, error) {
	sec := internalListenerSecurity{reflection: cfg.InternalGRPCReflection}
	if !cfg.InternalGRPCMTLSEnable {
		// Insecure listener — dev/local only. cert material NOT consulted.
		return sec, nil
	}

	if cfg.InternalGRPCTLSCertFile == "" || cfg.InternalGRPCTLSKeyFile == "" || cfg.MTLSCAFile == "" {
		return internalListenerSecurity{}, fmt.Errorf(
			"internal grpc mTLS enabled but server cert/key or client-CA missing " +
				"(KACHO_API_GATEWAY_INTERNAL_GRPC_TLS_CERT_FILE / _KEY_FILE + KACHO_API_GATEWAY_MTLS_CA_FILE)")
	}

	allowed := cfg.InternalGRPCAllowedSPIFFESet()
	if len(allowed) == 0 {
		return internalListenerSecurity{}, fmt.Errorf(
			"internal grpc mTLS enabled but no caller SPIFFE allow-list set " +
				"(KACHO_API_GATEWAY_INTERNAL_GRPC_ALLOWED_SPIFFE — the iam push-drainer identity)")
	}

	credsOpt, err := grpcsrv.TLSServerCreds(grpcsrv.TLSServer{
		Enable:        true,
		CertFile:      cfg.InternalGRPCTLSCertFile,
		KeyFile:       cfg.InternalGRPCTLSKeyFile,
		ClientCAFiles: []string{cfg.MTLSCAFile},
	})
	if err != nil {
		return internalListenerSecurity{}, fmt.Errorf("internal grpc mTLS server creds: %w", err)
	}

	sec.mtlsEnabled = true
	sec.serverCreds = credsOpt
	sec.allowedSPIFFE = allowed
	return sec, nil
}

// serverOptions returns the grpc.ServerOptions that carry this posture's mTLS
// transport creds + the SPIFFE allow-list interceptor chain. Empty when the
// listener is insecure (dev/local) — the caller keeps only its keepalive opts.
func (s internalListenerSecurity) serverOptions(logger *slog.Logger) []grpc.ServerOption {
	if !s.mtlsEnabled {
		return nil
	}
	return []grpc.ServerOption{
		s.serverCreds,
		grpc.ChainUnaryInterceptor(spiffeAllowlistUnaryInterceptor(s.allowedSPIFFE, logger)),
		grpc.ChainStreamInterceptor(spiffeAllowlistStreamInterceptor(s.allowedSPIFFE, logger)),
	}
}

// validateProductionInternalListener refuses to start when the internal gRPC
// listener runs insecure (no mTLS) under a production-class env. Only the explicit
// dev-class labels ("dev" / "local" / "test") tolerate an insecure listener; every
// other value — including an empty/unset label — is production-class and fails
// closed, mirroring validateProductionAuthzConfig (secure-by-default, CWE-1188).
func validateProductionInternalListener(env string, mtlsEnabled bool) error {
	if mtlsEnabled {
		return nil
	}
	switch env {
	case "dev", "local", "test":
		return nil
	default:
		return fmt.Errorf(
			"internal gRPC listener mTLS disabled in %q env: it hosts "+
				"InternalAuthzCacheService.InvalidateSubject and MUST enforce mTLS + a caller "+
				"allow-list in production (set KACHO_API_GATEWAY_INTERNAL_GRPC_MTLS_ENABLE=true; "+
				"only dev/local/test may run insecure)", env)
	}
}

// spiffeAllowlistUnaryInterceptor authorises the caller of a unary RPC: the peer
// must be mTLS-verified AND its module SPIFFE SAN must be on the allow-list.
func spiffeAllowlistUnaryInterceptor(allowed map[string]struct{}, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if err := authorizeInternalCaller(ctx, allowed, info.FullMethod, logger); err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
}

// spiffeAllowlistStreamInterceptor is the stream analogue. The internal listener
// currently hosts only unary RPCs; the stream guard is defence-in-depth so a
// future streaming Internal* RPC is authorised by default rather than open.
func spiffeAllowlistStreamInterceptor(allowed map[string]struct{}, logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		if err := authorizeInternalCaller(ss.Context(), allowed, info.FullMethod, logger); err != nil {
			return err
		}
		return h(srv, ss)
	}
}

// authorizeInternalCaller enforces: verified mTLS peer with a kacho.cloud module
// SAN (else Unauthenticated) whose SAN is on the allow-list (else PermissionDenied).
func authorizeInternalCaller(ctx context.Context, allowed map[string]struct{}, method string, logger *slog.Logger) error {
	san, err := verifiedPeerSPIFFE(ctx)
	if err != nil {
		return err
	}
	if _, ok := allowed[san]; !ok {
		if logger != nil {
			logger.Warn("internal gRPC caller rejected: SAN not on allow-list",
				slog.String("peer_san", san), slog.String("method", method))
		}
		return status.Errorf(codes.PermissionDenied,
			"caller identity %q is not authorized for the internal authz-cache listener", san)
	}
	return nil
}

// verifiedPeerSPIFFE returns the kacho.cloud module SPIFFE SAN of the verified
// mTLS client peer, or an Unauthenticated status when the peer is not mutually
// authenticated / carries no recognisable module identity.
func verifiedPeerSPIFFE(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", status.Error(codes.Unauthenticated, "no mutually-authenticated peer")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "connection is not TLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "no verified client certificate")
	}
	san := grpcsrv.CertIdentity(tlsInfo.State.VerifiedChains[0][0])
	if san == "" {
		return "", status.Error(codes.Unauthenticated, "client certificate carries no kacho.cloud SPIFFE identity")
	}
	return san, nil
}
