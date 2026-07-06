// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package proxy_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// rawMsg is a raw byte frame that implements the legacy proto.Message +
// Marshal/Unmarshal interface, so grpc's default codec passes the payload
// through untouched — mirroring the gateway's internal emptyFrame. This lets the
// test drive arbitrary request/response bytes across the transparent proxy
// without any generated proto type.
type rawMsg struct{ data []byte }

func (m *rawMsg) Reset()                   {}
func (m *rawMsg) String() string           { return "" }
func (m *rawMsg) ProtoMessage()            {}
func (m *rawMsg) Marshal() ([]byte, error) { return m.data, nil }
func (m *rawMsg) Unmarshal(d []byte) error { m.data = append([]byte(nil), d...); return nil }

const (
	echoMethod = "/kacho.cloud.vpc.v1.NetworkService/Get"
	boomMethod = "/kacho.cloud.vpc.v1.NetworkService/Delete"
)

// newFakeBackend serves every method via an UnknownServiceHandler: it always
// sets a response header + trailer (so the test can assert propagation), returns
// FailedPrecondition for boomMethod, and otherwise echoes the request bytes.
func newFakeBackend(t *testing.T) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(ss)
		_ = ss.SetHeader(metadata.Pairs("x-backend-header", "hval"))
		ss.SetTrailer(metadata.Pairs("x-backend-trailer", "tval"))
		if method == boomMethod {
			return status.Error(codes.FailedPrecondition, "backend boom")
		}
		var f rawMsg
		for {
			if err := ss.RecvMsg(&f); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if err := ss.SendMsg(&f); err != nil {
				return err
			}
		}
	}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis
}

func dialBufconn(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestShimProxy_ForwardsThroughGateway exercises the production external data
// path: client → proxy.NewServer(Resolver) → backend, over bufconn. It guards
// (1) byte-accurate round-trip + backend header/trailer propagation, (2) blocked
// / unknown methods map to NotFound (not Unimplemented — Internal*-hiding),
// and (3) backend error-status propagation.
func TestShimProxy_ForwardsThroughGateway(t *testing.T) {
	backendConn := dialBufconn(t, newFakeBackend(t))

	backends := proxy.Backends{"vpc": backendConn}
	gwSrv := proxy.NewServer(proxy.Resolver(backends))
	gwLis := bufconn.Listen(1 << 20)
	go func() { _ = gwSrv.Serve(gwLis) }()
	t.Cleanup(gwSrv.Stop)

	gwConn := dialBufconn(t, gwLis)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("known RPC round-trips bytes and backend header/trailer reach client", func(t *testing.T) {
		req := &rawMsg{data: []byte("hello-request-bytes")}
		resp := &rawMsg{}
		var hdr, tlr metadata.MD
		if err := gwConn.Invoke(ctx, echoMethod, req, resp, grpc.Header(&hdr), grpc.Trailer(&tlr)); err != nil {
			t.Fatalf("invoke echo: %v", err)
		}
		if string(resp.data) != "hello-request-bytes" {
			t.Errorf("response bytes = %q, want echo of request", resp.data)
		}
		if got := hdr.Get("x-backend-header"); len(got) != 1 || got[0] != "hval" {
			t.Errorf("backend response header not propagated to client: %v", hdr)
		}
		if got := tlr.Get("x-backend-trailer"); len(got) != 1 || got[0] != "tval" {
			t.Errorf("backend trailer not propagated to client: %v", tlr)
		}
	})

	t.Run("blocked Internal* method → NotFound (not Unimplemented)", func(t *testing.T) {
		err := gwConn.Invoke(ctx, "/kacho.cloud.vpc.v1.NetworkInternalService/Exists", &rawMsg{}, &rawMsg{})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("blocked Internal* method code = %v, want NotFound", status.Code(err))
		}
	})

	t.Run("unknown domain → NotFound", func(t *testing.T) {
		err := gwConn.Invoke(ctx, "/kacho.cloud.unknown.v1.FooService/Bar", &rawMsg{}, &rawMsg{})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("unknown-domain method code = %v, want NotFound", status.Code(err))
		}
	})

	t.Run("backend error status propagates", func(t *testing.T) {
		err := gwConn.Invoke(ctx, boomMethod, &rawMsg{data: []byte("x")}, &rawMsg{})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("backend error code = %v, want FailedPrecondition", status.Code(err))
		}
	})
}
