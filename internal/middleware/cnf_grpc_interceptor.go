// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cnf_grpc_interceptor.go — enforce sender-constrained token binding (RFC 7800
// `cnf`) on the NATIVE gRPC surface, mirroring the REST DPoPMiddleware.
//
// The REST path (dpop_http_middleware.go) validates `cnf.jkt` (DPoP proof) and
// `cnf.x5t#S256` (mTLS-bound) before forwarding. The native gRPC interceptor
// chain historically did NOT — the auth interceptor verifies the JWT signature
// and claims but never inspects `cnf`, so a stolen sender-constrained token
// could be replayed as a plain bearer over gRPC, silently defeating the binding
// that DPoP / mTLS-binding exists to guarantee (CWE-294 capture-replay).
//
// This interceptor closes that gap on the gRPC surface:
//
//   - cnf.x5t#S256 (mTLS-bound, RFC 8705): validated against the verified peer
//     client certificate — well-defined over gRPC via peer.FromContext — by
//     reusing the same MTLSBoundValidator the REST path uses.
//   - cnf.jkt (DPoP-bound, RFC 9449): a DPoP proof carries `htm`/`htu` bound to
//     an HTTP method + URI; there is no defined DPoP binding for a native gRPC
//     invocation, so a DPoP-bound token presented on the gRPC surface is
//     REJECTED fail-closed rather than accepted unbound. DPoP-bound clients use
//     the REST surface, whose middleware validates the proof.
//   - no cnf (plain bearer) / no token / dev-HMAC token: pass through unchanged
//     (the auth interceptor remains the authority for those).
//
// Wired only when KACHO_API_GATEWAY_AUTHN_ENABLE_DPOP=true (parity with the REST
// DPoPMiddleware, which is likewise feature-gated); when disabled the gateway
// issues no bound tokens and this interceptor is not mounted.
package middleware

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// CnfBindingInterceptor enforces RFC 7800 `cnf` binding on the gRPC surface.
type CnfBindingInterceptor struct {
	verifier TokenVerifier
	mtls     *MTLSBoundValidator
	logger   *slog.Logger
}

// NewCnfBindingInterceptor constructs the interceptor. verifier + logger are
// required; a nil mtls validator falls back to a fresh stateless one.
func NewCnfBindingInterceptor(verifier TokenVerifier, mtls *MTLSBoundValidator, logger *slog.Logger) (*CnfBindingInterceptor, error) {
	if verifier == nil {
		return nil, errors.New("cnf interceptor: verifier is required")
	}
	if logger == nil {
		return nil, errors.New("cnf interceptor: logger is required")
	}
	if mtls == nil {
		mtls = NewMTLSBoundValidator()
	}
	return &CnfBindingInterceptor{verifier: verifier, mtls: mtls, logger: logger}, nil
}

// Unary — gRPC unary server interceptor.
func (c *CnfBindingInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := c.enforce(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream — gRPC stream server interceptor.
func (c *CnfBindingInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := c.enforce(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// enforce inspects the presented bearer and enforces its cnf binding.
func (c *CnfBindingInterceptor) enforce(ctx context.Context, fullMethod string) error {
	bearer := extractBearer(ctx)
	if bearer == "" {
		return nil // no token — the auth interceptor injects anon / rejects per mode
	}
	if !isAsymmetricJWT(bearer) {
		return nil // dev HMAC tokens carry no cnf; the auth interceptor handles them
	}
	vt, err := c.verifier.Verify(ctx, bearer)
	if err != nil {
		// A present-but-invalid asymmetric token is rejected authoritatively by
		// the auth interceptor (Unauthenticated). Do not double-handle here.
		return nil
	}
	switch {
	case vt.Cnf.HasX5tS:
		if verr := c.mtls.Validate(vt, peerTLSState(ctx), nil); verr != nil {
			c.logger.Warn("cnf-grpc: mTLS-bound token validation failed",
				"method", fullMethod, "err", verr)
			return status.Errorf(codes.Unauthenticated,
				"sender-constrained token validation failed: %v", verr)
		}
	case vt.Cnf.HasJkt:
		// DPoP proof has no defined binding over native gRPC → fail closed.
		c.logger.Warn("cnf-grpc: DPoP-bound token presented on native gRPC surface; rejected (use REST endpoint)",
			"method", fullMethod)
		return status.Error(codes.Unauthenticated,
			"DPoP-bound token cannot be validated on the native gRPC surface; use the REST endpoint")
	}
	return nil
}

// peerTLSState returns the TLS connection state of the gRPC peer, or nil when
// the connection is not TLS (e.g. cluster-internal plaintext).
func peerTLSState(ctx context.Context) *tls.ConnectionState {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return &tlsInfo.State
}
