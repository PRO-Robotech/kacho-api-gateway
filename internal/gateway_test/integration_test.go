package gateway_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	rmv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/resourcemanager/v1"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/health"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/middleware"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/restmux"
)

// mockOrgServer — простой mock OrganizationService для тестов.
type mockOrgServer struct {
	rmv1.UnimplementedOrganizationServiceServer
}

func (m *mockOrgServer) List(_ context.Context, _ *rmv1.ListOrganizationsRequest) (*rmv1.ListOrganizationsResponse, error) {
	return &rmv1.ListOrganizationsResponse{}, nil
}

// mockHealthServer — mock grpc.health.v1.Health для backends.
type mockHealthServer struct {
	healthpb.UnimplementedHealthServer
}

func (m *mockHealthServer) Check(_ context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// setupMockBackend запускает mock gRPC-backend и возвращает его адрес.
func setupMockBackend(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock backend: %v", err)
	}
	srv := grpc.NewServer()
	rmv1.RegisterOrganizationServiceServer(srv, &mockOrgServer{})
	healthpb.RegisterHealthServer(srv, &mockHealthServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.GracefulStop)
	return lis.Addr().String()
}

// setupGateway запускает полный gateway и возвращает адрес.
func setupGateway(t *testing.T, backends proxy.Backends) string {
	t.Helper()

	director := proxy.NewDirector(backends)
	grpcSrv := proxy.NewServer(director,
		grpc.ChainUnaryInterceptor(middleware.UnaryRequestID),
		grpc.ChainStreamInterceptor(middleware.StreamRequestID),
	)
	health.RegisterGRPCHealth(grpcSrv, backends)

	ctx := context.Background()
	// conns=nil → OperationService регистрируется через Unimplemented (тесты без operations)
	restHandler, err := restmux.NewMux(ctx, nil, nil)
	if err != nil {
		t.Fatalf("rest mux: %v", err)
	}
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", health.HTTPHealthz)
	httpMux.Handle("/readyz", health.HTTPReadyz(backends, nil))
	httpMux.Handle("/", restHandler)

	httpSrv := &http.Server{Handler: middleware.HTTPRequestID(httpMux)}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}

	muxer := cmux.New(lis)
	grpcL := muxer.MatchWithWriters(
		cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
	)
	httpL := muxer.Match(cmux.Any())

	go grpcSrv.Serve(grpcL)
	go httpSrv.Serve(httpL)
	go muxer.Serve()

	t.Cleanup(func() {
		grpcSrv.GracefulStop()
		httpSrv.Close()
	})

	addr := lis.Addr().String()
	// Ждём готовности
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return addr
}

// TestGateway_A1_GrpcProxyForwardsToBackend проверяет сценарий A1:
// gateway проксирует запрос на правильный backend.
func TestGateway_A1_GrpcProxyForwardsToBackend(t *testing.T) {
	backendAddr := setupMockBackend(t)

	conn, err := grpc.NewClient(backendAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	backends := proxy.Backends{"resourcemanager": conn}
	gwAddr := setupGateway(t, backends)

	gwConn, err := grpc.NewClient(gwAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { gwConn.Close() })

	client := rmv1.NewOrganizationServiceClient(gwConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.List(ctx, &rmv1.ListOrganizationsRequest{})
	if err != nil {
		t.Fatalf("List через gateway: %v", err)
	}
	if resp == nil {
		t.Fatal("ответ не должен быть nil")
	}
}

// TestGateway_A5_UnknownDomainReturnsNotFound проверяет сценарий A5.
func TestGateway_A5_UnknownDomainReturnsNotFound(t *testing.T) {
	conn, _ := grpc.NewClient("localhost:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { conn.Close() })

	backends := proxy.Backends{"resourcemanager": conn}
	gwAddr := setupGateway(t, backends)

	gwConn, err := grpc.NewClient(gwAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { gwConn.Close() })

	// Вызываем неизвестный метод через raw invoker
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = gwConn.Invoke(ctx, "/kacho.cloud.unknown.v1.FooService/Bar",
		&rmv1.ListOrganizationsRequest{}, &rmv1.ListOrganizationsResponse{})
	if err == nil {
		t.Fatal("ожидали ошибку NOT_FOUND")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Errorf("ожидали NOT_FOUND, получили %v", err)
	}
}

// TestGateway_E1_InternalServiceBlockedAtGateway проверяет сценарий E1:
// InternalService метод блокируется до обращения к backend.
func TestGateway_E1_InternalServiceBlockedAtGateway(t *testing.T) {
	backendAddr := setupMockBackend(t)
	conn, _ := grpc.NewClient(backendAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { conn.Close() })

	backends := proxy.Backends{"resourcemanager": conn}
	gwAddr := setupGateway(t, backends)

	gwConn, err := grpc.NewClient(gwAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { gwConn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = gwConn.Invoke(ctx, "/kacho.cloud.resourcemanager.v1.FolderInternalService/Exists",
		&rmv1.ListOrganizationsRequest{}, &rmv1.ListOrganizationsResponse{})
	if err == nil {
		t.Fatal("ожидали NOT_FOUND для InternalService")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Errorf("ожидали NOT_FOUND, получили %v", err)
	}
}

// TestGateway_G1_HealthzReturns200 проверяет сценарий G1.
func TestGateway_G1_HealthzReturns200(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	health.HTTPHealthz(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz: ожидали 200, получили %d", rec.Code)
	}
}

// TestGateway_G5_GrpcHealthCheck проверяет сценарий G5: gRPC Health.Check возвращает SERVING.
func TestGateway_G5_GrpcHealthCheck(t *testing.T) {
	backendAddr := setupMockBackend(t)
	conn, err := grpc.NewClient(backendAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	backends := proxy.Backends{"resourcemanager": conn}
	gwAddr := setupGateway(t, backends)

	gwConn, err := grpc.NewClient(gwAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { gwConn.Close() })

	client := healthpb.NewHealthClient(gwConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health.Check: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("ожидали SERVING, получили %s", resp.Status)
	}
}

// TestGateway_J5_ConcurrentRequestsNoRace проверяет сценарий J5 (race detector).
func TestGateway_J5_ConcurrentRequestsNoRace(t *testing.T) {
	backendAddr := setupMockBackend(t)
	conn, err := grpc.NewClient(backendAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	backends := proxy.Backends{"resourcemanager": conn}
	gwAddr := setupGateway(t, backends)

	gwConn, err := grpc.NewClient(gwAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { gwConn.Close() })

	client := rmv1.NewOrganizationServiceClient(gwConn)

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := client.List(ctx, &rmv1.ListOrganizationsRequest{})
			errs <- err
		}()
	}

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent request %d failed: %v", i, err)
		}
	}
}
