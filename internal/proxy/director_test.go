package proxy_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

func makeTestBackends(t *testing.T, domains []string) proxy.Backends {
	t.Helper()
	backends := make(proxy.Backends, len(domains))
	for _, d := range domains {
		conn, err := grpc.NewClient("localhost:1",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			t.Fatalf("NewClient для %s: %v", d, err)
		}
		t.Cleanup(func() { conn.Close() })
		backends[d] = conn
	}
	return backends
}

// TestGateway_A2_DirectorRoutesToIAM — маршрутизация Account/Project (KAC-124: заменили resourcemanager).
func TestGateway_A2_DirectorRoutesToIAM(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	director := proxy.NewDirector(backends)

	_, conn, err := director(context.Background(), "/kacho.cloud.iam.v1.AccountService/List")
	if err != nil {
		t.Fatalf("ожидали успех: %v", err)
	}
	if conn != backends["iam"] {
		t.Error("директор должен вернуть iam-backend")
	}

	// UserService.Update — публичная async-мутация (labels-only User), parity с
	// RoleService/ServiceAccountService Update. Должна маршрутизироваться на
	// iam-backend (allowlist пропускает; HasInternalSuffix не ловит — сервис
	// публичный, не Internal*).
	_, conn, err = director(context.Background(), "/kacho.cloud.iam.v1.UserService/Update")
	if err != nil {
		t.Fatalf("ожидали успех для iam UserService.Update: %v", err)
	}
	if conn != backends["iam"] {
		t.Error("директор должен вернуть iam-backend для UserService.Update")
	}
}

// TestGateway_A3_DirectorRoutesToVPC проверяет маршрутизацию на vpc.
func TestGateway_A3_DirectorRoutesToVPC(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	director := proxy.NewDirector(backends)

	_, conn, err := director(context.Background(), "/kacho.cloud.vpc.v1.NetworkService/List")
	if err != nil {
		t.Fatalf("ожидали успех: %v", err)
	}
	if conn != backends["vpc"] {
		t.Error("директор должен вернуть vpc-backend")
	}
}

// TestGateway_A5_DirectorUnknownDomainNotFound проверяет сценарий A5.
func TestGateway_A5_DirectorUnknownDomainNotFound(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	director := proxy.NewDirector(backends)

	_, _, err := director(context.Background(), "/kacho.cloud.unknown.v1.FooService/Bar")
	if err == nil {
		t.Fatal("ожидали ошибку NOT_FOUND")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("ожидали gRPC status, получили: %T", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("ожидали NOT_FOUND, получили %s", st.Code())
	}
}

// TestGateway_A5b_RemovedResourceManagerMethodsBlocked — KAC-124: resourcemanager/organizationmanager
// удалены из allowlist; их методы → 404 NOT_FOUND (как unknown method).
func TestGateway_A5b_RemovedResourceManagerMethodsBlocked(t *testing.T) {
	removed := []string{
		"/kacho.cloud.resourcemanager.v1.CloudService/List",
		"/kacho.cloud.resourcemanager.v1.FolderService/Get",
		"/kacho.cloud.organizationmanager.v1.OrganizationService/List",
	}
	backends := makeTestBackends(t, []string{"iam", "vpc"})
	director := proxy.NewDirector(backends)
	for _, m := range removed {
		m := m
		t.Run(m, func(t *testing.T) {
			_, _, err := director(context.Background(), m)
			if err == nil {
				t.Fatalf("удалённый метод %q должен быть заблокирован", m)
			}
			st, _ := status.FromError(err)
			if st.Code() != codes.NotFound {
				t.Errorf("ожидали NOT_FOUND, получили %s", st.Code())
			}
		})
	}
}

// TestGateway_A6_LoadbalancerRoutesToBackend (KAC-161) — публичные nlb-RPC
// маршрутизируются на loadbalancer-backend (kacho-nlb), а Internal*-методы nlb
// блокируются HasInternalSuffix (запрет #6).
//
// До KAC-161 loadbalancer был заморожен (предыдущий тест проверял,
// что все методы возвращают NOT_FOUND). После регистрации kacho-nlb публичные
// RPC должны проксироваться, internal — оставаться заблокированными.
func TestGateway_A6_LoadbalancerRoutesToBackend(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute", "loadbalancer"})
	director := proxy.NewDirector(backends)

	// Public nlb-методы → loadbalancer-backend
	publicMethods := []string{
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/Create",
		"/kacho.cloud.loadbalancer.v1.ListenerService/Create",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/Get",
		"/kacho.cloud.loadbalancer.v1.TargetGroupService/AddTargets",
	}
	for _, m := range publicMethods {
		m := m
		t.Run("public/"+m, func(t *testing.T) {
			_, conn, err := director(context.Background(), m)
			if err != nil {
				t.Fatalf("ожидали успех для public nlb-метода %q: %v", m, err)
			}
			if conn != backends["loadbalancer"] {
				t.Errorf("метод %q: директор должен вернуть loadbalancer-backend", m)
			}
		})
	}

	// Internal nlb-методы блокируются HasInternalSuffix → NOT_FOUND
	for _, m := range []string{
		"/kacho.cloud.loadbalancer.v1.InternalResourceLifecycleService/Subscribe",
	} {
		m := m
		t.Run("internal/"+m, func(t *testing.T) {
			_, _, err := director(context.Background(), m)
			if err == nil {
				t.Fatalf("Internal nlb-метод %q должен быть заблокирован", m)
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.NotFound {
				t.Errorf("метод %q: ожидали NOT_FOUND, получили %v", m, err)
			}
		})
	}
}

// TestGateway_A6b_ComputeRoutesToBackend проверяет, что публичные compute-RPC
// маршрутизируются на compute-backend, а Internal*-методы compute блокируются.
func TestGateway_A6b_ComputeRoutesToBackend(t *testing.T) {
	backends := makeTestBackends(t, []string{"iam", "vpc", "compute"})
	director := proxy.NewDirector(backends)

	_, conn, err := director(context.Background(), "/kacho.cloud.compute.v1.InstanceService/Get")
	if err != nil {
		t.Fatalf("ожидали успех для compute InstanceService.Get: %v", err)
	}
	if conn != backends["compute"] {
		t.Error("директор должен вернуть compute-backend")
	}

	for _, m := range []string{
		"/kacho.cloud.compute.v1.InternalDiskTypeService/Create",
		"/kacho.cloud.compute.v1.InternalDiskTypeService/Delete",
		"/kacho.cloud.compute.v1.InternalWatchService/Watch",
	} {
		m := m
		t.Run(m, func(t *testing.T) {
			_, _, err := director(context.Background(), m)
			if err == nil {
				t.Fatalf("Internal compute-метод %q должен быть заблокирован", m)
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.NotFound {
				t.Errorf("метод %q: ожидали NOT_FOUND, получили %v", m, err)
			}
		})
	}
}

// TestGateway_E1_DirectorBlocksInternalService проверяет, что InternalService-методы блокируются.
func TestGateway_E1_DirectorBlocksInternalService(t *testing.T) {
	internalMethods := []string{
		"/kacho.cloud.vpc.v1.NetworkInternalService/Exists",
		"/kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
	}

	backends := makeTestBackends(t, []string{"iam", "vpc"})
	director := proxy.NewDirector(backends)

	for _, m := range internalMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			_, _, err := director(context.Background(), m)
			if err == nil {
				t.Fatalf("метод %q должен быть заблокирован", m)
			}
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.NotFound {
				t.Errorf("метод %q: ожидали NOT_FOUND, получили %v", m, err)
			}
		})
	}
}

// TestGateway_J3_MalformedMethodPathNotFound проверяет сценарий J3.
func TestGateway_J3_MalformedMethodPathNotFound(t *testing.T) {
	backends := makeTestBackends(t, []string{"vpc"})
	director := proxy.NewDirector(backends)

	_, _, err := director(context.Background(), "//BadPath")
	if err == nil {
		t.Fatal("ожидали ошибку для malformed path")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Errorf("ожидали NOT_FOUND, получили %v", err)
	}
}

// Обеспечиваем, что NewDirector совместим с proxy.Backends через интерфейс.
var _ func(context.Context, string) (context.Context, grpc.ClientConnInterface, error) = proxy.NewDirector(nil)
