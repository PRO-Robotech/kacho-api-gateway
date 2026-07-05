// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// internal_grpc_listener_w1_2_test.go — covers the dedicated internal gRPC
// listener that hosts InternalAuthzCacheService (port 9091). iam's push-drainer
// dials KACHO_API_GATEWAY_INTERNAL_GRPC_ADDR and invokes InvalidateSubject.
//
// SECURITY (sec-hardening-r7): the internal listener is NOT an unauthenticated
// trust zone. When mTLS is enabled it presents a server cert, requires a verified
// client cert (RequireAndVerifyClientCert against the internal CA), AND enforces
// that the verified client SPIFFE SAN is on the caller allow-list (the iam
// push-drainer identity). These tests therefore dial the HAPPY path WITH a valid
// drainer client cert, and prove the NEGATIVE paths — a non-mTLS caller, a caller
// whose cert carries no kacho.cloud SPIFFE identity, and a valid-but-non-allow-
// listed caller — are all rejected before InvalidateSubject runs.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/handler"
	apigatewayv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/apigateway/v1"
)

const (
	// internalListenerServerName — the SNI/server-name the drainer pins and the
	// DNS SAN baked into the listener's server cert.
	internalListenerServerName = "kacho-api-gateway-internal"
	// iamDrainerSPIFFE — the identity of the kacho-iam subject_change push-drainer;
	// the ONLY identity allow-listed to invoke InvalidateSubject.
	iamDrainerSPIFFE = "spiffe://kacho.cloud/ns/kacho-iam/sa/kacho-iam"
)

// fakeInvalidator — records InvalidateSubject calls so the test can assert
// the wired gRPC path reaches the cache.
type fakeInvalidator struct {
	calls    int
	subjects []string
}

func (f *fakeInvalidator) InvalidateSubject(s string) int {
	f.calls++
	f.subjects = append(f.subjects, s)
	// Return >0 so the handler returns OK (not NotFound on idempotent miss).
	return 1
}
func (f *fakeInvalidator) Invalidate() {}

// mtlsInternalSecurityFromFiles wires the internal-listener mTLS security through
// the PRODUCTION config path (config.Load → buildInternalListenerSecurity) so the
// test exercises the real env contract, not a hand-rolled struct.
func mtlsInternalSecurityFromFiles(t *testing.T, serverCert, serverKey, caFile string, allowed ...string) internalListenerSecurity {
	t.Helper()
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_MTLS_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_TLS_CERT_FILE", serverCert)
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_TLS_KEY_FILE", serverKey)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", caFile)
	t.Setenv("KACHO_API_GATEWAY_INTERNAL_GRPC_ALLOWED_SPIFFE", strings.Join(allowed, ","))
	cfg, err := config.Load()
	require.NoError(t, err)
	sec, err := buildInternalListenerSecurity(cfg)
	require.NoError(t, err, "buildInternalListenerSecurity must succeed with full mTLS material")
	require.True(t, sec.mtlsEnabled, "mTLS must be enabled")
	return sec
}

// startSecuredInternalListener starts the wiring helper on an ephemeral port with
// the given security posture and returns the listener addr for the test to dial.
func startSecuredInternalListener(t *testing.T, inv handler.Invalidator, sec internalListenerSecurity) string {
	t.Helper()
	externalSrv := grpc.NewServer()
	t.Cleanup(externalSrv.Stop)

	srv, lis, err := startInternalGRPCListener(":0", inv, externalSrv, sec, nil)
	require.NoError(t, err, "startInternalGRPCListener must succeed on :0")
	require.NotNil(t, srv, "must return *grpc.Server")
	require.NotNil(t, lis, "must return net.Listener")
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = lis.Close()
	})
	go func() { _ = srv.Serve(lis) }()

	// Internal admin service must NOT be registered on the external server.
	const fqn = "kacho.cloud.apigateway.v1.InternalAuthzCacheService"
	_, externalHas := externalSrv.GetServiceInfo()[fqn]
	assert.False(t, externalHas,
		"InternalAuthzCacheService must NOT be on the external server (internal-only)")

	return lis.Addr().String()
}

// mtlsClientDialCreds builds mTLS dial credentials presenting clientCert/clientKey
// and verifying the server against caFile with the pinned server-name.
func mtlsClientDialCreds(t *testing.T, caFile, clientCert, clientKey, serverName string) grpc.DialOption {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	require.NoError(t, err)
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "load internal CA")
	return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}))
}

// TestW1_2_InternalGRPCListener_MTLS_ServesInvalidateSubject — HAPPY PATH.
// The drainer dials the mTLS listener WITH a valid client cert whose SPIFFE SAN
// is on the allow-list; InvalidateSubject reaches the supplied Invalidator.
func TestW1_2_InternalGRPCListener_MTLS_ServesInvalidateSubject(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srvCert, srvKey := ca.issueLeaf(t, leafOpts{
		commonName: internalListenerServerName,
		dnsNames:   []string{internalListenerServerName},
		isServer:   true,
	})
	cliCert, cliKey := ca.issueLeaf(t, leafOpts{
		commonName: "kacho-iam",
		uriSANs:    []string{iamDrainerSPIFFE},
	})
	caFile := ca.caFile(t)

	sec := mtlsInternalSecurityFromFiles(t, srvCert, srvKey, caFile, iamDrainerSPIFFE)
	inv := &fakeInvalidator{}
	addr := startSecuredInternalListener(t, inv, sec)

	conn, err := grpc.NewClient(addr,
		mtlsClientDialCreds(t, caFile, cliCert, cliKey, internalListenerServerName))
	require.NoError(t, err, "dial internal listener with drainer client cert")
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{
		Subject:   "user:usr_kac138_target",
		EventType: "binding_revoke",
	})
	require.NoError(t, err, "InvalidateSubject must succeed end-to-end over mTLS for an allow-listed caller")

	require.Equal(t, 1, inv.calls, "invalidator must be called exactly once")
	require.Equal(t, []string{"user:usr_kac138_target"}, inv.subjects)
}

// TestW1_2_InternalGRPCListener_MTLS_RejectsEmptySubject — the handler's
// InvalidArgument contract survives the mTLS + allow-list interceptor chain (the
// interceptor authorises the caller, then the handler validates the payload).
func TestW1_2_InternalGRPCListener_MTLS_RejectsEmptySubject(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srvCert, srvKey := ca.issueLeaf(t, leafOpts{
		commonName: internalListenerServerName,
		dnsNames:   []string{internalListenerServerName},
		isServer:   true,
	})
	cliCert, cliKey := ca.issueLeaf(t, leafOpts{
		commonName: "kacho-iam",
		uriSANs:    []string{iamDrainerSPIFFE},
	})
	caFile := ca.caFile(t)

	sec := mtlsInternalSecurityFromFiles(t, srvCert, srvKey, caFile, iamDrainerSPIFFE)
	inv := &fakeInvalidator{}
	addr := startSecuredInternalListener(t, inv, sec)

	conn, err := grpc.NewClient(addr,
		mtlsClientDialCreds(t, caFile, cliCert, cliKey, internalListenerServerName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{Subject: ""})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"empty subject must map to InvalidArgument even through the authz interceptor")
	require.Equal(t, 0, inv.calls, "handler must reject before touching the invalidator")
}

// TestW1_2_InternalGRPCListener_MTLS_RejectsNonMTLSCaller — an unauthenticated /
// non-mTLS caller (plaintext insecure creds) cannot invoke InvalidateSubject: the
// RequireAndVerifyClientCert transport rejects the handshake (no silent plaintext
// fallback), so the cache is never flushed.
func TestW1_2_InternalGRPCListener_MTLS_RejectsNonMTLSCaller(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srvCert, srvKey := ca.issueLeaf(t, leafOpts{
		commonName: internalListenerServerName,
		dnsNames:   []string{internalListenerServerName},
		isServer:   true,
	})
	caFile := ca.caFile(t)

	sec := mtlsInternalSecurityFromFiles(t, srvCert, srvKey, caFile, iamDrainerSPIFFE)
	inv := &fakeInvalidator{}
	addr := startSecuredInternalListener(t, inv, sec)

	// Plaintext / non-mTLS dial — no client cert presented.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{Subject: "user:usr_x"})
	require.Error(t, err, "a non-mTLS caller must NOT be able to flush the authz cache")
	require.Equal(t, codes.Unavailable, status.Code(err),
		"mTLS transport must reject the plaintext handshake (fail-closed)")
	require.Equal(t, 0, inv.calls, "cache must never be flushed by an unauthenticated caller")
}

// TestW1_2_InternalGRPCListener_MTLS_RejectsNonAllowlistedCaller — a caller with
// a VALID client cert (signed by the internal CA, handshake succeeds) but whose
// SPIFFE SAN is NOT on the allow-list is rejected with PermissionDenied before
// InvalidateSubject runs (defence against confused-deputy: any in-cluster module
// with a valid mesh cert must not be able to flush the authz cache).
func TestW1_2_InternalGRPCListener_MTLS_RejectsNonAllowlistedCaller(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srvCert, srvKey := ca.issueLeaf(t, leafOpts{
		commonName: internalListenerServerName,
		dnsNames:   []string{internalListenerServerName},
		isServer:   true,
	})
	// Valid internal-CA cert, but a DIFFERENT module identity (kacho-vpc).
	cliCert, cliKey := ca.issueLeaf(t, leafOpts{
		commonName: "kacho-vpc",
		uriSANs:    []string{"spiffe://kacho.cloud/ns/kacho-vpc/sa/kacho-vpc"},
	})
	caFile := ca.caFile(t)

	sec := mtlsInternalSecurityFromFiles(t, srvCert, srvKey, caFile, iamDrainerSPIFFE)
	inv := &fakeInvalidator{}
	addr := startSecuredInternalListener(t, inv, sec)

	conn, err := grpc.NewClient(addr,
		mtlsClientDialCreds(t, caFile, cliCert, cliKey, internalListenerServerName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{Subject: "user:usr_x"})
	require.Error(t, err, "a non-allow-listed module identity must be rejected")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"a valid-but-non-allow-listed SPIFFE SAN must map to PermissionDenied")
	require.Equal(t, 0, inv.calls, "cache must never be flushed by an unauthorized caller")
}

// TestW1_2_InternalGRPCListener_MTLS_RejectsNonSpiffeCaller — a caller presenting
// a valid internal-CA client cert that carries NO kacho.cloud SPIFFE identity
// (no recognisable module SAN) is rejected with Unauthenticated: the handshake
// verifies but there is no identity to authorise.
func TestW1_2_InternalGRPCListener_MTLS_RejectsNonSpiffeCaller(t *testing.T) {
	ca := newTestCA(t, "kacho-internal-ca")
	srvCert, srvKey := ca.issueLeaf(t, leafOpts{
		commonName: internalListenerServerName,
		dnsNames:   []string{internalListenerServerName},
		isServer:   true,
	})
	// Valid internal-CA cert but no SPIFFE URI SAN → no module identity.
	cliCert, cliKey := ca.issueLeaf(t, leafOpts{commonName: "anonymous-leaf"})
	caFile := ca.caFile(t)

	sec := mtlsInternalSecurityFromFiles(t, srvCert, srvKey, caFile, iamDrainerSPIFFE)
	inv := &fakeInvalidator{}
	addr := startSecuredInternalListener(t, inv, sec)

	conn, err := grpc.NewClient(addr,
		mtlsClientDialCreds(t, caFile, cliCert, cliKey, internalListenerServerName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{Subject: "user:usr_x"})
	require.Error(t, err, "a cert without a kacho.cloud SPIFFE identity must be rejected")
	require.Equal(t, codes.Unauthenticated, status.Code(err),
		"a verified cert with no module SAN must map to Unauthenticated")
	require.Equal(t, 0, inv.calls, "cache must never be flushed by an unidentified caller")
}

// TestW1_2_InternalGRPCListener_InsecureDev_BackwardCompat — with mTLS disabled
// (the dev/local opt-in default) the listener stays insecure so local stands and
// existing dev flows keep working: an insecure caller can invoke InvalidateSubject.
// The production guard (validateProductionInternalListener) is what forbids this
// posture under a production-class env; that guard is unit-tested separately.
func TestW1_2_InternalGRPCListener_InsecureDev_BackwardCompat(t *testing.T) {
	cfg, err := config.Load() // all mTLS envs unset ⇒ InternalGRPCMTLSEnable=false
	require.NoError(t, err)
	sec, err := buildInternalListenerSecurity(cfg)
	require.NoError(t, err)
	require.False(t, sec.mtlsEnabled, "default posture is insecure (dev/local opt-in)")

	inv := &fakeInvalidator{}
	addr := startSecuredInternalListener(t, inv, sec)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{Subject: "user:usr_dev"})
	require.NoError(t, err, "insecure dev listener stays reachable for backward-compat")
	require.Equal(t, 1, inv.calls)
}

// Compile-time guard — fakeInvalidator must satisfy handler.Invalidator.
var _ handler.Invalidator = (*fakeInvalidator)(nil)
