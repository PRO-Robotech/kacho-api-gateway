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

// TestGateway_A2_DirectorRoutesToResourceManager проверяет маршрутизацию на resource-manager.
func TestGateway_A2_DirectorRoutesToResourceManager(t *testing.T) {
	backends := makeTestBackends(t, []string{"resourcemanager", "organizationmanager", "vpc"})
	director := proxy.NewDirector(backends)

	_, conn, err := director(context.Background(), "/kacho.cloud.resourcemanager.v1.CloudService/List")
	if err != nil {
		t.Fatalf("ожидали успех: %v", err)
	}
	if conn != backends["resourcemanager"] {
		t.Error("директор должен вернуть resourcemanager-backend")
	}
}

// TestGateway_A2b_DirectorRoutesOrganizationManagerToRM проверяет маршрутизацию OrganizationService.
func TestGateway_A2b_DirectorRoutesOrganizationManagerToRM(t *testing.T) {
	backends := makeTestBackends(t, []string{"resourcemanager", "organizationmanager", "vpc"})
	director := proxy.NewDirector(backends)

	_, conn, err := director(context.Background(), "/kacho.cloud.organizationmanager.v1.OrganizationService/List")
	if err != nil {
		t.Fatalf("ожидали успех: %v", err)
	}
	if conn != backends["organizationmanager"] {
		t.Error("директор должен вернуть organizationmanager-backend (alias resource-manager)")
	}
}

// TestGateway_A3_DirectorRoutesToVPC проверяет маршрутизацию на vpc.
func TestGateway_A3_DirectorRoutesToVPC(t *testing.T) {
	backends := makeTestBackends(t, []string{"resourcemanager", "organizationmanager", "vpc"})
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
	backends := makeTestBackends(t, []string{"resourcemanager", "organizationmanager", "vpc"})
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

// TestGateway_A6_ComputeLoadbalancerFrozenBlocked проверяет, что compute/lb заморожены.
func TestGateway_A6_ComputeLoadbalancerFrozenBlocked(t *testing.T) {
	frozenMethods := []string{
		"/kacho.cloud.compute.v1.InstanceService/Get",
		"/kacho.cloud.loadbalancer.v1.NetworkLoadBalancerService/List",
	}
	backends := makeTestBackends(t, []string{"resourcemanager", "organizationmanager", "vpc"})
	director := proxy.NewDirector(backends)

	for _, m := range frozenMethods {
		m := m
		t.Run(m, func(t *testing.T) {
			_, _, err := director(context.Background(), m)
			if err == nil {
				t.Fatalf("замороженный метод %q должен быть заблокирован", m)
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
		"/kacho.cloud.resourcemanager.v1.FolderInternalService/Exists",
		"/kacho.cloud.organizationmanager.v1.OrganizationInternalService/HasDependents",
		"/kacho.cloud.vpc.v1.NetworkInternalService/Exists",
	}

	backends := makeTestBackends(t, []string{"resourcemanager", "organizationmanager", "vpc"})
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
