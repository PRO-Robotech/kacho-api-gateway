package listenerorigin_test

import (
	"context"
	"net"
	"testing"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/listenerorigin"
)

// TestIsExternal_DefaultInternal — a bare context (no marker) is internal origin.
func TestIsExternal_DefaultInternal(t *testing.T) {
	if listenerorigin.IsExternal(context.Background()) {
		t.Fatal("bare context must be internal origin (IsExternal=false)")
	}
	if listenerorigin.IsExternal(nil) {
		t.Fatal("nil context must be internal origin (IsExternal=false)")
	}
}

// TestWithExternal_Marks — WithExternal flips the marker.
func TestWithExternal_Marks(t *testing.T) {
	ctx := listenerorigin.WithExternal(context.Background())
	if !listenerorigin.IsExternal(ctx) {
		t.Fatal("WithExternal context must report IsExternal=true")
	}
}

// fakeConn is a minimal net.Conn for ConnContext tests.
type fakeConn struct{ net.Conn }

// tlsLikeConn mimics crypto/tls.Conn's NetConn() unwrap so ExternalConnContext
// can see through TLS to the wrapped external listener conn.
type tlsLikeConn struct {
	net.Conn
	inner net.Conn
}

func (c tlsLikeConn) NetConn() net.Conn { return c.inner }

// TestExternalConnContext_TagsExternalListenerConn — a conn accepted via
// ExternalListener is tagged external, even through a TLS-like wrapper.
func TestExternalConnContext_TagsExternalListenerConn(t *testing.T) {
	// Build a listener-pair to obtain a real conn, then wrap with ExternalListener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ext := listenerorigin.ExternalListener(ln)

	done := make(chan net.Conn, 1)
	go func() {
		c, aerr := ext.Accept()
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

	// Direct external conn → tagged.
	ctx := listenerorigin.ExternalConnContext(context.Background(), srvConn)
	if !listenerorigin.IsExternal(ctx) {
		t.Fatal("conn from ExternalListener must be tagged external")
	}

	// Through a TLS-like wrapper (NetConn unwraps to the external conn) → tagged.
	wrapped := tlsLikeConn{inner: srvConn}
	ctx2 := listenerorigin.ExternalConnContext(context.Background(), wrapped)
	if !listenerorigin.IsExternal(ctx2) {
		t.Fatal("TLS-wrapped external conn must be tagged external (NetConn unwrap)")
	}
}

// TestExternalConnContext_DoesNotTagInternalConn — a conn NOT from the external
// listener stays internal origin.
func TestExternalConnContext_DoesNotTagInternalConn(t *testing.T) {
	ctx := listenerorigin.ExternalConnContext(context.Background(), fakeConn{})
	if listenerorigin.IsExternal(ctx) {
		t.Fatal("non-external conn must NOT be tagged external")
	}
}
