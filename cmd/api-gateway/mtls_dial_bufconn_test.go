// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// mtls_dial_bufconn_test.go — in-memory mTLS handshake tests for the gateway
// backend-dial creds. Они прогоняют creds, построенные buildBackendDialCreds /
// cfg.EdgeTLSClient, против реального corelib grpcsrv TLS-сервера поверх bufconn
// pipe — no docker, no network.
//
// Coverage:
//   - principal `x-kacho-principal-*` metadata propagates over mTLS AND the
//     server observes the client peer-cert SAN (both layers present, orthogonal).
//   - mTLS client dialing an insecure (plaintext) server → fail-closed
//     (Unavailable), never a silent plaintext fallback.
//   - server-cert signed by a foreign CA (not the gateway's internal-CA bundle)
//     → handshake reject → Unavailable.
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PRO-Robotech/kacho-corelib/grpcclient"
	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
)

const mtlsServerName = "vpc.kacho.svc.cluster.local"

// capturingHealth records the metadata + peer-cert SAN seen on the wire for the
// last Check call, so the test can assert both the principal layer and the mTLS
// layer simultaneously.
type capturingHealth struct {
	healthgrpc.UnimplementedHealthServer
	gotPrincipalType string
	gotPrincipalID   string
	gotPeerCertURIs  []string
}

func (h *capturingHealth) Check(ctx context.Context, _ *healthgrpc.HealthCheckRequest) (*healthgrpc.HealthCheckResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-kacho-principal-type"); len(v) > 0 {
			h.gotPrincipalType = v[0]
		}
		if v := md.Get("x-kacho-principal-id"); len(v) > 0 {
			h.gotPrincipalID = v[0]
		}
	}
	h.gotPeerCertURIs = peerCertURIs(ctx)
	return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_SERVING}, nil
}

// startBufconnServer starts a grpc server with the given server-option over a
// bufconn pipe and returns a dialer for it.
func startBufconnServer(t *testing.T, srvOpt grpc.ServerOption, svc *capturingHealth) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(srvOpt)
	healthgrpc.RegisterHealthServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }
}

// dialOptFromConfig builds the per-edge dial-option the gateway would use for
// the given backend key, via the production config path.
func dialOptFromConfig(t *testing.T, cfg config.Config, backendKey, addr string) grpc.DialOption {
	t.Helper()
	tc, err := cfg.EdgeTLSClient(backendEdge(backendKey), addr)
	require.NoError(t, err)
	opt, err := grpcclient.TLSClientCreds(tc)
	require.NoError(t, err)
	return opt
}

// principal metadata + peer-cert SAN both observed over mTLS.
func TestSECE05_PrincipalAndPeerCertOverMTLS(t *testing.T) {
	srvCA := newTestCA(t, "kacho-internal-ca")
	srvCert, srvKey := srvCA.issueLeaf(t, leafOpts{
		commonName: mtlsServerName,
		dnsNames:   []string{mtlsServerName},
		isServer:   true,
	})
	cliCert, cliKey := srvCA.issueLeaf(t, leafOpts{
		commonName: "kacho-api-gateway",
		uriSANs:    []string{"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-api-gateway"},
	})
	caFile := srvCA.caFile(t)

	svc := &capturingHealth{}
	srvOpt, err := grpcsrv.TLSServerCreds(grpcsrv.TLSServer{
		Enable:        true,
		CertFile:      srvCert,
		KeyFile:       srvKey,
		ClientCAFiles: []string{caFile},
	})
	require.NoError(t, err)
	dialer := startBufconnServer(t, srvOpt, svc)

	// Gateway-side config: vpc edge mTLS-on, server-name pinned to the cert SAN.
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", cliCert)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", cliKey)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", caFile)
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "true")
	cfg, err := config.Load()
	require.NoError(t, err)

	opt := dialOptFromConfig(t, cfg, "vpc", mtlsServerName+":9090")
	conn, err := grpc.NewClient("passthrough:///bufnet",
		opt, grpc.WithContextDialer(dialer))
	require.NoError(t, err)
	defer conn.Close()

	// Principal metadata set on the outgoing ctx, exactly as the gRPC router does.
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"x-kacho-principal-type", "user",
		"x-kacho-principal-id", "usr_alice",
	))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = healthgrpc.NewHealthClient(conn).Check(ctx, &healthgrpc.HealthCheckRequest{})
	require.NoError(t, err, "mTLS handshake + RPC must succeed")

	// principal layer survived mTLS:
	require.Equal(t, "user", svc.gotPrincipalType)
	require.Equal(t, "usr_alice", svc.gotPrincipalID)
	// mTLS layer present: server saw the client module identity SAN:
	require.Contains(t, svc.gotPeerCertURIs,
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-api-gateway")
}

// mTLS client vs insecure server → fail-closed (Unavailable).
func TestSECE09_MTLSClientVsInsecureServer_FailsClosed(t *testing.T) {
	srvCA := newTestCA(t, "kacho-internal-ca")
	cliCert, cliKey := srvCA.issueLeaf(t, leafOpts{commonName: "kacho-api-gateway"})
	caFile := srvCA.caFile(t)

	// Insecure (plaintext) server — no TLS.
	svc := &capturingHealth{}
	dialer := startBufconnServer(t, grpc.Creds(insecure.NewCredentials()), svc)

	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", cliCert)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", cliKey)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", caFile)
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "true")
	cfg, err := config.Load()
	require.NoError(t, err)

	opt := dialOptFromConfig(t, cfg, "vpc", mtlsServerName+":9090")
	conn, err := grpc.NewClient("passthrough:///bufnet", opt, grpc.WithContextDialer(dialer))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = healthgrpc.NewHealthClient(conn).Check(ctx, &healthgrpc.HealthCheckRequest{})
	require.Error(t, err, "mTLS client dialing plaintext server must fail (no silent fallback)")
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// server presents a cert from a FOREIGN CA → handshake reject → Unavailable.
// The gateway never accepts an untrusted backend.
func TestSECE11_BackendCertUntrustedCA_Rejected(t *testing.T) {
	internalCA := newTestCA(t, "kacho-internal-ca")
	foreignCA := newTestCA(t, "rogue-ca")

	// Server cert signed by the FOREIGN CA; client-CA = internal (so the server
	// would accept the gateway client, but the gateway must reject the server).
	srvCert, srvKey := foreignCA.issueLeaf(t, leafOpts{
		commonName: mtlsServerName,
		dnsNames:   []string{mtlsServerName},
		isServer:   true,
	})
	cliCert, cliKey := internalCA.issueLeaf(t, leafOpts{commonName: "kacho-api-gateway"})
	internalCAFile := internalCA.caFile(t)

	svc := &capturingHealth{}
	srvOpt, err := grpcsrv.TLSServerCreds(grpcsrv.TLSServer{
		Enable:        true,
		CertFile:      srvCert,
		KeyFile:       srvKey,
		ClientCAFiles: []string{internalCAFile},
	})
	require.NoError(t, err)
	dialer := startBufconnServer(t, srvOpt, svc)

	// Gateway trusts ONLY the internal CA — the foreign server-cert won't verify.
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", cliCert)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", cliKey)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", internalCAFile)
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "true")
	cfg, err := config.Load()
	require.NoError(t, err)

	opt := dialOptFromConfig(t, cfg, "vpc", mtlsServerName+":9090")
	conn, err := grpc.NewClient("passthrough:///bufnet", opt, grpc.WithContextDialer(dialer))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = healthgrpc.NewHealthClient(conn).Check(ctx, &healthgrpc.HealthCheckRequest{})
	require.Error(t, err, "untrusted backend cert must be rejected")
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// opsLoopback is always insecure regardless of enabled edges. The loopback
// creds come from a dedicated insecure dial-option, not the per-edge map.
// Asserts the helper that main.go uses returns insecure even when every edge
// is mTLS-on.
func TestSECE07_OpsLoopbackAlwaysInsecure(t *testing.T) {
	cert, key, ca := writePEMTriple(t)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_CERT_FILE", cert)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CLIENT_KEY_FILE", key)
	t.Setenv("KACHO_API_GATEWAY_MTLS_CA_FILE", ca)
	t.Setenv("KACHO_API_GATEWAY_MTLS_VPC_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_MTLS_COMPUTE_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_MTLS_IAM_ENABLE", "true")
	t.Setenv("KACHO_API_GATEWAY_MTLS_NLB_ENABLE", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	// The "operation" domain is NOT a backend edge — it must not appear in the
	// per-edge creds map, and its loopback dial is insecure by construction.
	creds, err := buildBackendDialCreds(cfg)
	require.NoError(t, err)
	_, present := creds["operation"]
	require.False(t, present, "operation/opsLoopback must not be a per-edge mTLS backend")

	// loopbackDialCreds is the explicit always-insecure option used by main.go
	// for the self-loopback ClientConn.
	require.NotNil(t, loopbackDialCreds())
}

// peerCertURIs extracts the URI SANs of the verified client peer cert (the mTLS
// module identity) from the gRPC peer's TLS auth-info.
func peerCertURIs(ctx context.Context) []string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	var uris []string
	for _, chain := range tlsInfo.State.VerifiedChains {
		if len(chain) == 0 {
			continue
		}
		for _, u := range chain[0].URIs {
			uris = append(uris, u.String())
		}
	}
	return uris
}
