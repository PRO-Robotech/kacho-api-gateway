// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package listenerorigin_test

import (
	"context"
	"net"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
)

// TestIsExternal_DefaultExternal — a bare context (no marker) is EXTERNAL origin
// (fail-closed). This is the inverted default: any listener that does not
// explicitly mark its connections internal is treated as the untrusted edge.
func TestIsExternal_DefaultExternal(t *testing.T) {
	if !listenerorigin.IsExternal(context.Background()) {
		t.Fatal("bare context must be EXTERNAL origin (IsExternal=true, fail-closed)")
	}
	if !listenerorigin.IsExternal(nil) { //nolint:staticcheck // intentionally exercises nil-context handling
		t.Fatal("nil context must be EXTERNAL origin (IsExternal=true, fail-closed)")
	}
}

// TestWithInternal_Marks — WithInternal flips the marker to internal.
func TestWithInternal_Marks(t *testing.T) {
	ctx := listenerorigin.WithInternal(context.Background())
	if listenerorigin.IsExternal(ctx) {
		t.Fatal("WithInternal context must report IsExternal=false")
	}
}

// fakeConn is a minimal net.Conn for ConnContext tests. It simulates a
// connection accepted on the plaintext/ingress-facing listener (NOT wrapped by
// InternalListener), which must stay external.
type fakeConn struct{ net.Conn }

// tlsLikeConn mimics crypto/tls.Conn's NetConn() unwrap so InternalConnContext
// can see through TLS/cmux to the wrapped internal listener conn.
type tlsLikeConn struct {
	net.Conn
	inner net.Conn
}

func (c tlsLikeConn) NetConn() net.Conn { return c.inner }

// TestInternalConnContext_TagsInternalListenerConn — a conn accepted via
// InternalListener is tagged internal, even through a TLS/cmux-like wrapper.
func TestInternalConnContext_TagsInternalListenerConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	in := listenerorigin.InternalListener(ln)

	done := make(chan net.Conn, 1)
	go func() {
		c, aerr := in.Accept()
		if aerr != nil {
			done <- nil
			return
		}
		done <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	srvConn := <-done
	if srvConn == nil {
		t.Fatal("accept failed")
	}
	defer srvConn.Close()

	// Direct internal conn → tagged internal (IsExternal=false).
	ctx := listenerorigin.InternalConnContext(context.Background(), srvConn)
	if listenerorigin.IsExternal(ctx) {
		t.Fatal("conn from InternalListener must be tagged internal (IsExternal=false)")
	}

	// Through a TLS/cmux-like wrapper (NetConn unwraps to the internal conn) → tagged.
	wrapped := tlsLikeConn{inner: srvConn}
	ctx2 := listenerorigin.InternalConnContext(context.Background(), wrapped)
	if listenerorigin.IsExternal(ctx2) {
		t.Fatal("wrapped internal conn must be tagged internal (NetConn unwrap)")
	}
}

// TestInternalConnContext_DoesNotTagPlainConn — a conn NOT from the internal
// listener (the plaintext/ingress-facing listener) stays EXTERNAL origin. This
// is the core fail-closed guarantee: the ingress-facing listener is external.
func TestInternalConnContext_DoesNotTagPlainConn(t *testing.T) {
	ctx := listenerorigin.InternalConnContext(context.Background(), fakeConn{})
	if !listenerorigin.IsExternal(ctx) {
		t.Fatal("non-internal conn (ingress-facing listener) must stay EXTERNAL (IsExternal=true)")
	}
}
