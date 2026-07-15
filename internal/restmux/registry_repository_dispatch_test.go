// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package restmux

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
	registrypb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// repoRecorderSrv — записывает, какой RegistryService-метод фактически вызвал
// grpc-gateway для данного REST-пути (+ извлечённое repository-значение). Нужен,
// чтобы проверить не только «route зарегистрирован» (non-404), но и что путь
// диспатчится в ПРАВИЛЬНЫЙ gRPC-метод (иначе `{repository=**}` catch-all мог бы
// незаметно перехватить более специфичный маршрут).
type repoRecorderSrv struct {
	registrypb.UnimplementedRegistryServiceServer
	called chan string
}

func (s *repoRecorderSrv) GetRepository(_ context.Context, r *registrypb.GetRepositoryRequest) (*registrypb.Repository, error) {
	s.called <- "GetRepository:" + r.GetRepository()
	return &registrypb.Repository{}, nil
}

func (s *repoRecorderSrv) ListReferrers(_ context.Context, r *registrypb.ListReferrersRequest) (*registrypb.ListReferrersResponse, error) {
	s.called <- "ListReferrers:" + r.GetRepository()
	return &registrypb.ListReferrersResponse{}, nil
}

func (s *repoRecorderSrv) CreateRepository(_ context.Context, r *registrypb.CreateRepositoryRequest) (*operationpb.Operation, error) {
	s.called <- "CreateRepository:" + r.GetRepository()
	return &operationpb.Operation{}, nil
}

func (s *repoRecorderSrv) UpdateRepository(_ context.Context, r *registrypb.UpdateRepositoryRequest) (*operationpb.Operation, error) {
	s.called <- "UpdateRepository:" + r.GetRepository()
	return &operationpb.Operation{}, nil
}

func (s *repoRecorderSrv) DeleteRepository(_ context.Context, r *registrypb.DeleteRepositoryRequest) (*operationpb.Operation, error) {
	s.called <- "DeleteRepository:" + r.GetRepository()
	return &operationpb.Operation{}, nil
}

func (s *repoRecorderSrv) RenameRepository(_ context.Context, r *registrypb.RenameRepositoryRequest) (*operationpb.Operation, error) {
	s.called <- "RenameRepository:" + r.GetRepository()
	return &operationpb.Operation{}, nil
}

// TestRegistry_RepositoryRoutes_DispatchToOwnHandler — 6 новых public RPC RG-1
// маршрутизируются grpc-gateway в СВОЙ gRPC-метод (не перехвачены соседними
// маршрутами). Поднимает in-process RegistryService (bufconn) и проверяет
// фактически вызванный метод — сильнее, чем route-presence (non-404), т.к. ловит
// перехват пути соседним pattern'ом.
//
// Пути с сегментом-слэшем (`backend/api`, `{repository=**}` wildcard) намеренно
// НЕ пересекают `/tags`-сегмент. Причина: grpc-gateway `ServeMux.Handle`
// PREPEND-ит хендлеры (newest-first, runtime/mux.go), а RG-1-proto объявляет
// `{repository=**}` catch-all'ы (GetRepository/DeleteRepository) ПОСЛЕ
// tag-маршрутов (ListTags/DeleteTag) → catch-all перехватывает `…/{repo}/tags`
// и `…/{repo}/tags/{tag}` (REST-shadow). Это дефект ПОРЯДКА объявления RPC в
// kacho-proto (registry_service.proto), НЕ решаемый в api-gateway (precedence
// зашит в сгенерированный stub); фиксится реордером RPC в proto. Данный тест
// проверяет корректность диспатча самих 6 новых маршрутов на не-колли­зирующих
// путях; tag-shadow отслеживается на стороне proto.
func TestRegistry_RepositoryRoutes_DispatchToOwnHandler(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	rec := &repoRecorderSrv{called: make(chan string, 1)}
	registrypb.RegisterRegistryServiceServer(gs, rec)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	mux := runtime.NewServeMux()
	if err := registrypb.RegisterRegistryServiceHandler(context.Background(), mux, conn); err != nil {
		t.Fatalf("RegisterRegistryServiceHandler: %v", err)
	}

	cases := []struct {
		name, method, path, want string
	}{
		{"GetRepository", "GET", "/registry/v1/registries/reg-1/repositories/backend/api", "GetRepository:backend/api"},
		{"ListReferrers", "GET", "/registry/v1/registries/reg-1/repositories/backend/api/referrers", "ListReferrers:backend/api"},
		{"CreateRepository", "POST", "/registry/v1/registries/reg-1/repositories", "CreateRepository:"},
		{"UpdateRepository", "PATCH", "/registry/v1/registries/reg-1/repositories/backend/api", "UpdateRepository:backend/api"},
		{"DeleteRepository", "DELETE", "/registry/v1/registries/reg-1/repositories/backend/api", "DeleteRepository:backend/api"},
		{"RenameRepository", "POST", "/registry/v1/registries/reg-1/repositories/backend/api:rename", "RenameRepository:backend/api"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, http.NoBody)
			rec2 := httptest.NewRecorder()
			mux.ServeHTTP(rec2, req)
			var got string
			select {
			case got = <-rec.called:
			default:
				t.Fatalf("%s %s: no RegistryService method invoked (http %d) — route not dispatched",
					tc.method, tc.path, rec2.Code)
			}
			if got != tc.want {
				t.Errorf("%s %s dispatched to %q, want %q — RG-1 route hijacked by a neighbouring pattern",
					tc.method, tc.path, got, tc.want)
			}
		})
	}
}
