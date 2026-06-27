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
)

// TestExternalIsolationWiring_EndToEnd verifies the FULL listener topology used
// in main(): an external TLS listener wrapped by listenerorigin.ExternalListener,
// fronted by cmux, served by a shared *http.Server whose ConnContext is
// listenerorigin.ExternalConnContext. It proves the external-origin marker
// survives the tls.Conn + cmux.MuxConn wrapping chain and reaches the handler —
// without which the REST dispatcher's external-404 gate is dead code.
//
// Two listeners share ONE http.Server (as in production):
//   - plaintext (internal origin)  → handler sees IsExternal=false
//   - TLS+ExternalListener (edge)  → handler sees IsExternal=true
func TestExternalIsolationWiring_EndToEnd(t *testing.T) {
	// The shared handler echoes the resolved listener origin.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if listenerorigin.IsExternal(r.Context()) {
			w.WriteHeader(http.StatusForbidden) // stand-in for "external → would 404 Internal*"
			_, _ = io.WriteString(w, "external")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "internal")
	})

	httpSrv := &http.Server{
		Handler:     handler,
		ReadTimeout: 5 * time.Second,
		ConnContext: listenerorigin.ExternalConnContext,
	}
	_ = http2.ConfigureServer(httpSrv, &http2.Server{})

	// --- internal plaintext listener + cmux + httpSrv ---
	intLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("internal listen: %v", err)
	}
	defer intLn.Close()
	intCmux := cmux.New(intLn)
	intHTTPL := intCmux.Match(cmux.Any())
	go func() { _ = httpSrv.Serve(intHTTPL) }()
	go func() { _ = intCmux.Serve() }()

	// --- external TLS listener wrapped + cmux + same httpSrv ---
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
	extCmux := cmux.New(rawTLS)
	extHTTPL := extCmux.Match(cmux.Any())
	// Wrap the HTTP sub-listener so ConnContext sees externalConn as the OUTERMOST
	// type — robust against cmux/tls conn wrapping (matches main.go wiring).
	go func() { _ = httpSrv.Serve(listenerorigin.ExternalListener(extHTTPL)) }()
	go func() { _ = extCmux.Serve() }()

	time.Sleep(100 * time.Millisecond) // let goroutines start

	// Internal call → IsExternal=false → 200 "internal".
	t.Run("internal listener → origin internal", func(t *testing.T) {
		body, code := doGet(t, "http://"+intLn.Addr().String()+"/probe", nil)
		if code != http.StatusOK || body != "internal" {
			t.Fatalf("internal listener: got code=%d body=%q, want 200 internal", code, body)
		}
	})

	// External TLS call → IsExternal=true → 403 "external" (marker survived tls+cmux).
	t.Run("external TLS listener → origin external", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test self-signed
			},
			Timeout: 5 * time.Second,
		}
		body, code := doGetClient(t, client, "https://"+rawTLS.Addr().String()+"/probe")
		if code != http.StatusForbidden || body != "external" {
			t.Fatalf("external listener: got code=%d body=%q, want 403 external (origin marker lost through tls/cmux)", code, body)
		}
	})

	_ = context.Background()
}

func doGet(t *testing.T, url string, _ http.RoundTripper) (string, int) {
	t.Helper()
	return doGetClient(t, &http.Client{Timeout: 5 * time.Second}, url)
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
