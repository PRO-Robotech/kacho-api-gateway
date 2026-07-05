// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/soheilhy/cmux"
	"golang.org/x/net/http2"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/restmux"
)

// internalRESTProbePath is a real Internal* REST path (AddressPool admin,
// isInternalPath → internal sub-mux). It MUST 404 on any external listener and
// be reachable (non-404 — a downstream gRPC error against the unreachable
// backend) only on the dedicated internal admin listener.
const internalRESTProbePath = "/vpc/v1/addressPools"

// wiringMuxAddrs — full backend address map so all Internal* routes register.
// 127.0.0.1:1 is intentionally unreachable: a route that IS found yields a
// downstream gRPC error, never a route-level 404 — so 404 unambiguously means
// "rejected by the internal-path gate".
func wiringMuxAddrs() map[string]string {
	return map[string]string{
		"vpc": "127.0.0.1:1", "vpcInternal": "127.0.0.1:1",
		"compute": "127.0.0.1:1", "computeInternal": "127.0.0.1:1",
		"iam": "127.0.0.1:1", "iamInternal": "127.0.0.1:1",
		"loadbalancer": "127.0.0.1:1", "loadbalancerInternal": "127.0.0.1:1",
	}
}

// TestExternalIsolationWiring_EndToEnd wires the FULL production listener
// topology used in main() and drives the REAL restmux dispatcher over it, to
// prove — fail-closed — that an Internal* REST path 404s on the ingress-facing
// listener regardless of TLS, while remaining reachable on the dedicated
// cluster-internal admin listener.
//
// One shared *http.Server (ConnContext = listenerorigin.InternalConnContext)
// fronts THREE listeners, exactly as main() does after the r3 inversion:
//
//   - plaintext cmux listener        (Service `cmux` :8080 — what the ingress
//     targets)                         → UNwrapped → external → Internal* 404
//   - external TLS + cmux listener   (:8443)  → UNwrapped → external → Internal* 404
//   - InternalListener-wrapped plain (:8081 admin)  → internal → Internal* served
//
// The plaintext-listener assertion is the regression guard for the HIGH finding:
// under the old model the ingress-facing plaintext listener was treated as
// internal and served Internal* REST to the edge.
func TestExternalIsolationWiring_EndToEnd(t *testing.T) {
	dispatcher, err := restmux.NewMux(context.Background(), wiringMuxAddrs(), nil, nil)
	if err != nil {
		t.Fatalf("NewMux: %v", err)
	}

	httpSrv := &http.Server{
		Handler:     dispatcher,
		ReadTimeout: 5 * time.Second,
		// The single production ConnContext: marks ONLY InternalListener conns.
		ConnContext: listenerorigin.InternalConnContext,
	}
	_ = http2.ConfigureServer(httpSrv, &http2.Server{})

	// --- ingress-facing plaintext cmux listener (external, the fail-closed default) ---
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("plain listen: %v", err)
	}
	defer plainLn.Close()
	plainCmux := cmux.New(plainLn)
	plainHTTPL := plainCmux.Match(cmux.Any())
	go func() { _ = httpSrv.Serve(plainHTTPL) }()
	go func() { _ = plainCmux.Serve() }()

	// --- dedicated internal admin listener (InternalListener-wrapped → internal) ---
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("admin listen: %v", err)
	}
	defer adminLn.Close()
	go func() { _ = httpSrv.Serve(listenerorigin.InternalListener(adminLn)) }()

	// --- external TLS + cmux listener (UNwrapped → external) ---
	cert := selfSignedCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	rawTLS, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer rawTLS.Close()
	tlsCmux := cmux.New(rawTLS)
	tlsHTTPL := tlsCmux.Match(cmux.Any())
	go func() { _ = httpSrv.Serve(tlsHTTPL) }()
	go func() { _ = tlsCmux.Serve() }()

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test self-signed
		},
		Timeout: 2 * time.Second,
	}
	plainClient := &http.Client{Timeout: 2 * time.Second}

	waitHTTPReady(t, plainClient, "http://"+plainLn.Addr().String()+"/healthz")
	waitHTTPReady(t, plainClient, "http://"+adminLn.Addr().String()+"/healthz")
	waitHTTPReady(t, tlsClient, "https://"+rawTLS.Addr().String()+"/healthz")

	// CRITICAL (HIGH finding): Internal* REST 404s on the ingress-facing
	// plaintext listener — the exact listener the shipped ingress targets.
	t.Run("plaintext ingress-facing listener → Internal* 404", func(t *testing.T) {
		_, code := doGetClient(t, plainClient, "http://"+plainLn.Addr().String()+internalRESTProbePath)
		if code != http.StatusNotFound {
			t.Fatalf("Internal* %s on ingress-facing plaintext listener: got %d, want 404 (CRITICAL: Internal* exposed at the edge)", internalRESTProbePath, code)
		}
	})

	// Internal* REST 404s on the external TLS listener too.
	t.Run("external TLS listener → Internal* 404", func(t *testing.T) {
		_, code := doGetClient(t, tlsClient, "https://"+rawTLS.Addr().String()+internalRESTProbePath)
		if code != http.StatusNotFound {
			t.Fatalf("Internal* %s on external TLS listener: got %d, want 404", internalRESTProbePath, code)
		}
	})

	// Internal* REST reachable on the dedicated internal admin listener: the
	// route IS found (marker survives InternalListener), the unreachable backend
	// yields a downstream error — NOT a route-level 404.
	t.Run("internal admin listener → Internal* served", func(t *testing.T) {
		_, code := doGetClient(t, plainClient, "http://"+adminLn.Addr().String()+internalRESTProbePath)
		if code == http.StatusNotFound {
			t.Fatalf("Internal* %s on internal admin listener: got 404 — route rejected, admin/UI/port-forward broken", internalRESTProbePath)
		}
	})

	// Public REST stays served on the ingress-facing plaintext listener.
	t.Run("plaintext ingress-facing listener → public served", func(t *testing.T) {
		_, code := doGetClient(t, plainClient, "http://"+plainLn.Addr().String()+"/vpc/v1/networks")
		if code == http.StatusNotFound {
			t.Fatalf("public /vpc/v1/networks on ingress-facing listener: got 404 — public route wrongly rejected")
		}
	})

	_ = context.Background()
}

// waitHTTPReady polls url with the given client until it gets any HTTP response
// (the serve goroutine + cmux are up) or a deadline elapses.
func waitHTTPReady(t *testing.T, c *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := c.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener not ready after 3s: GET %s: %v", url, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func doGetClient(t *testing.T, c *http.Client, url string) (string, int) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

// selfSignedCert mints an ephemeral self-signed leaf for the loopback external
// TLS listener used in TestExternalIsolationWiring_EndToEnd.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
