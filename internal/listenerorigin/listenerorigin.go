// Package listenerorigin carries the listener-origin of an inbound request
// (external advertised TLS endpoint vs cluster-internal listener) through the
// request context, so downstream HTTP handlers / middleware can enforce
// Internal-vs-external isolation (workspace CLAUDE.md §запрет #6,
// security.md §AuthN+AuthZ).
//
// # Why a per-listener marker
//
// api-gateway serves the SAME *http.Server (and the SAME REST dispatcher) on
// BOTH the plaintext cluster-internal listener (KACHO_API_GATEWAY_LISTEN_ADDR,
// e.g. :8080 — port-forwarded for UI / admin-tooling / newman baseUrl) AND the
// advertised external TLS listener (KACHO_API_GATEWAY_TLS_LISTEN_ADDR,
// api.kacho.local:443 — externalBaseUrl). The REST mux isInternalPath only
// selects the JSON marshaller; it never rejects by listener. So Internal* REST
// routes (/iam/v1/internal/*, /vpc/v1/addressPools,
// /vpc/v1/networks/{id}/internal, ...) were reachable on the EXTERNAL endpoint —
// the gRPC director blocks Internal* via HasInternalSuffix, but the REST path
// had no equivalent gate.
//
// This package mirrors the gRPC-director pattern for REST: the external TLS
// listener is wrapped so every connection it accepts is tagged; the shared
// http.Server.ConnContext propagates the tag into each request context; the
// dispatcher then rejects Internal* paths arriving from the external origin with
// 404 (existence-hiding). The internal listener is left untagged
// (IsExternal == false) so UI / admin / port-forward / service self-calls keep
// working unchanged.
package listenerorigin

import (
	"context"
	"net"
)

// originKey is the unexported context key carrying the listener-origin marker.
// A dedicated empty-struct type avoids collisions with other packages' context
// keys (Go idiom).
type originKey struct{}

// markExternal is the sentinel stored under originKey for external-listener
// connections. Absence of the key (the default) means internal origin —
// fail-closed for legitimate callers: any request whose origin was NOT
// explicitly marked external is treated as internal (the trusted side), so a
// missing marker never accidentally 404s an internal caller. The EXTERNAL side
// is the one that must opt in to the marker, and the external listener wiring is
// the single place that does.
type markExternal struct{}

// IsExternal reports whether the request arrived on the advertised external TLS
// listener. Returns false when the marker is absent (internal origin).
func IsExternal(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(originKey{}).(markExternal)
	return ok
}

// WithExternal returns a copy of ctx tagged as external-listener origin. Exposed
// for tests; production marks origin via the listener wrapper + ConnContext.
func WithExternal(ctx context.Context) context.Context {
	return context.WithValue(ctx, originKey{}, markExternal{})
}

// externalConn wraps a net.Conn accepted on the external TLS listener so that
// ExternalConnContext can recognise it and tag the request context.
type externalConn struct {
	net.Conn
}

// ExternalListener wraps lis so every connection it accepts is tagged as
// external origin (recognisable by ExternalConnContext). Wrap ONLY the external
// TLS listener; leave the cluster-internal listener unwrapped.
func ExternalListener(lis net.Listener) net.Listener {
	return &externalListener{Listener: lis}
}

type externalListener struct {
	net.Listener
}

func (l *externalListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &externalConn{Conn: c}, nil
}

// ExternalConnContext is an http.Server.ConnContext hook: it marks the request
// context as external origin when the connection was accepted on a listener
// wrapped by ExternalListener. Connections from any other (internal) listener
// pass through unmarked.
//
// The same http.Server serves both listeners; ConnContext is invoked per
// connection with the concrete net.Conn, so this is the one place that can tell
// external from internal without splitting into two http.Server instances.
func ExternalConnContext(ctx context.Context, c net.Conn) context.Context {
	if isExternalConn(c) {
		return WithExternal(ctx)
	}
	return ctx
}

// isExternalConn unwraps the conn chain (crypto/tls wraps the underlying conn)
// to find the externalConn marker.
func isExternalConn(c net.Conn) bool {
	type wrappedConn interface {
		NetConn() net.Conn
	}
	for c != nil {
		if _, ok := c.(*externalConn); ok {
			return true
		}
		// crypto/tls.Conn exposes the underlying connection via NetConn().
		if w, ok := c.(wrappedConn); ok {
			c = w.NetConn()
			continue
		}
		break
	}
	return false
}
