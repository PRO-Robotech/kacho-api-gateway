// mux_mtls_test.go — SEC-K REST-mux → backend mTLS tests (acceptance §3,
// Capability 1, A-1a/A-1b/A-1c).
//
// The 503-bug: NewMux built ONE insecure []grpc.DialOption and passed it to
// every RegisterXServiceHandlerFromEndpoint. After the backends flipped to
// tls.RequireAndVerifyClientCert, every REST call → mux → backend handshake was
// reset (503 "connection reset by peer / error reading server preface"). These
// RED-first tests stand up a REAL mTLS gRPC NetworkService over a TCP listener
// and prove:
//
//   - A-1c: enable=false / nil per-backend creds → insecure dial (back-compat).
//   - A-1a: with the gateway client-cert + correct per-backend ServerName the
//     REST call reaches the mTLS backend and returns 200 (no 503/reset).
//   - the bug-repro: insecure creds against a require-and-verify backend → the
//     handshake is reset → grpc-gateway surfaces a 5xx (NOT 200).
//   - A-1b: wrong ServerName (foreign edge SNI) → server-cert SAN check fails →
//     handshake reject → NOT 200.
package restmux

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-corelib/grpcclient"
	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"

	vpcpb "github.com/PRO-Robotech/kacho-vpc/proto/gen/go/kacho/cloud/vpc/v1"
)

// stubNetworkService serves a deterministic List response so the REST round-trip
// can assert a real 200 body (proving the mTLS handshake + RPC both succeeded).
type stubNetworkService struct {
	vpcpb.UnimplementedNetworkServiceServer
}

func (stubNetworkService) List(context.Context, *vpcpb.ListNetworksRequest) (*vpcpb.ListNetworksResponse, error) {
	return &vpcpb.ListNetworksResponse{
		Networks: []*vpcpb.Network{{Id: "net-sec-k", Name: "sec-k"}},
	}, nil
}

// startMTLSVPCBackend starts a real require-and-verify mTLS gRPC server hosting
// NetworkService, signed by the given CA with the given server SAN. Returns the
// listener address ("host:port").
func startMTLSVPCBackend(t *testing.T, ca *muxTestCA, serverSAN string) string {
	t.Helper()
	srvCert, srvKey := ca.issueLeaf(t, muxLeaf{
		commonName: serverSAN,
		dnsNames:   []string{serverSAN},
		isServer:   true,
	})
	srvOpt, err := grpcsrv.TLSServerCreds(grpcsrv.TLSServer{
		Enable:        true,
		CertFile:      srvCert,
		KeyFile:       srvKey,
		ClientCAFiles: []string{ca.caFile(t)},
	})
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(srvOpt)
	vpcpb.RegisterNetworkServiceServer(srv, stubNetworkService{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// gatewayClientCreds builds the per-backend dial-option the gateway uses for a
// vpc-edge mTLS dial, with the given ServerName (SNI). Mirrors the production
// path: cfg.EdgeTLSClient → grpcclient.TLSClientCreds.
func gatewayClientCreds(t *testing.T, ca *muxTestCA, serverName string) grpc.DialOption {
	t.Helper()
	cliCert, cliKey := ca.issueLeaf(t, muxLeaf{
		commonName: "kacho-api-gateway",
		uriSANs:    []string{"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-api-gateway"},
	})
	opt, err := grpcclient.TLSClientCreds(grpcclient.TLSClient{
		Enable:     true,
		CertFile:   cliCert,
		KeyFile:    cliKey,
		CAFiles:    []string{ca.caFile(t)},
		ServerName: serverName,
	})
	require.NoError(t, err)
	return opt
}

const muxTestServerSAN = "vpc.kacho.svc.cluster.local"

// A-1a — with the gateway client-cert + correct per-backend ServerName the REST
// call reaches the mTLS backend and returns 200 (no 503, no reset). This is the
// regression-fix: NewMux must thread per-backend dial creds, not a single
// insecure opts.
func TestSECK_RESTMux_MTLSBackend_ListNetworks_200(t *testing.T) {
	ca := newMuxTestCA(t, "kacho-internal-ca")
	addr := startMTLSVPCBackend(t, ca, muxTestServerSAN)

	addrs := map[string]string{"vpc": addr}
	dialOpts := map[string]grpc.DialOption{
		"vpc": gatewayClientCreds(t, ca, muxTestServerSAN),
	}

	h, err := NewMux(context.Background(), addrs, nil /* conns */, dialOpts)
	require.NoError(t, err)

	rec := doMuxGET(t, h, "/vpc/v1/networks?projectId=prj-1")
	require.Equal(t, http.StatusOK, rec.Code,
		"mTLS REST round-trip must succeed (no 503/reset); body=%s", rec.Body.String())

	var got struct {
		Networks []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"networks"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Networks, 1)
	require.Equal(t, "net-sec-k", got.Networks[0].ID)
}

// bug-repro — insecure dial creds (the OLD single-insecure-opts behavior) against
// a require-and-verify mTLS backend → handshake reset → grpc-gateway surfaces a
// 5xx, NOT 200. Documents the 503 this sub-phase fixes.
func TestSECK_RESTMux_InsecureDialVsMTLSBackend_Not200(t *testing.T) {
	ca := newMuxTestCA(t, "kacho-internal-ca")
	addr := startMTLSVPCBackend(t, ca, muxTestServerSAN)

	addrs := map[string]string{"vpc": addr}
	// No per-backend creds for vpc → NewMux must fall back to insecure (which is
	// exactly the pre-fix behavior). Against an mTLS backend this fails the call.
	h, err := NewMux(context.Background(), addrs, nil, nil /* dialOpts */)
	require.NoError(t, err)

	rec := doMuxGET(t, h, "/vpc/v1/networks?projectId=prj-1")
	require.NotEqual(t, http.StatusOK, rec.Code,
		"insecure dial against an mTLS backend must NOT return 200 (this is the 503 bug)")
}

// A-1b — wrong ServerName (foreign-edge SNI) → server-cert SAN check fails →
// handshake reject → NOT 200. Proves per-backend ServerName is actually pinned.
func TestSECK_RESTMux_WrongServerName_HandshakeRejected(t *testing.T) {
	ca := newMuxTestCA(t, "kacho-internal-ca")
	addr := startMTLSVPCBackend(t, ca, muxTestServerSAN)

	addrs := map[string]string{"vpc": addr}
	dialOpts := map[string]grpc.DialOption{
		// SNI of a DIFFERENT edge — does not match the vpc server-cert SAN.
		"vpc": gatewayClientCreds(t, ca, "iam.kacho.svc.cluster.local"),
	}

	h, err := NewMux(context.Background(), addrs, nil, dialOpts)
	require.NoError(t, err)

	rec := doMuxGET(t, h, "/vpc/v1/networks?projectId=prj-1")
	require.NotEqual(t, http.StatusOK, rec.Code,
		"mismatched ServerName must fail the server-cert SAN check (NOT 200)")
}

// A-1c — nil per-backend creds → insecure dial, identical to pre-fix dev. An
// insecure plaintext backend still answers, proving back-compat is preserved.
func TestSECK_RESTMux_NilCreds_InsecureBackend_200(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer() // plaintext
	vpcpb.RegisterNetworkServiceServer(srv, stubNetworkService{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	addrs := map[string]string{"vpc": lis.Addr().String()}
	h, err := NewMux(context.Background(), addrs, nil, nil /* dialOpts → insecure */)
	require.NoError(t, err)

	rec := doMuxGET(t, h, "/vpc/v1/networks?projectId=prj-1")
	require.Equal(t, http.StatusOK, rec.Code,
		"nil creds → insecure dial against a plaintext backend must still work; body=%s", rec.Body.String())
}

// doMuxGET fires a GET through the mux dispatcher with a short timeout so a
// failed handshake surfaces promptly rather than hanging the test.
func doMuxGET(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- ephemeral test CA (mirrors cmd/api-gateway/mtls_testcerts_test.go) ---

type muxTestCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newMuxTestCA(t *testing.T, commonName string) *muxTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &muxTestCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *muxTestCA) caFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(p, ca.certPEM, 0o600))
	return p
}

type muxLeaf struct {
	commonName string
	dnsNames   []string
	uriSANs    []string
	isServer   bool
}

func (ca *muxTestCA) issueLeaf(t *testing.T, o muxLeaf) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	uris := make([]*url.URL, 0, len(o.uriSANs))
	for _, raw := range o.uriSANs {
		u, perr := url.Parse(raw)
		require.NoError(t, perr)
		uris = append(uris, u)
	}
	eku := x509.ExtKeyUsageClientAuth
	if o.isServer {
		eku = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: o.commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     o.dnsNames,
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "leaf.crt")
	keyFile = filepath.Join(dir, "leaf.key")
	require.NoError(t, os.WriteFile(certFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}
