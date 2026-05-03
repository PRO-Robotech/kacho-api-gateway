package config

import corecfg "github.com/PRO-Robotech/kacho-corelib/config"

// Config хранит конфигурацию api-gateway.
// Переменные окружения:
//
//	KACHO_API_GATEWAY_LISTEN_ADDR   — адрес для cmux listener (default: :8080)
//	KACHO_RESOURCE_MANAGER_GRPC     — адрес backend resource-manager (default: resource-manager.kacho.svc.cluster.local:9090)
//	KACHO_VPC_GRPC                  — адрес backend vpc
//	KACHO_COMPUTE_GRPC              — адрес backend compute
//	KACHO_LOADBALANCER_GRPC         — адрес backend loadbalancer
type Config struct {
	ListenAddr          string `envconfig:"KACHO_API_GATEWAY_LISTEN_ADDR" default:":8080"`
	ResourceManagerAddr string `envconfig:"KACHO_RESOURCE_MANAGER_GRPC"    default:"resource-manager.kacho.svc.cluster.local:9090"`
	VPCAddr             string `envconfig:"KACHO_VPC_GRPC"                 default:"vpc.kacho.svc.cluster.local:9090"`
	ComputeAddr         string `envconfig:"KACHO_COMPUTE_GRPC"             default:"compute.kacho.svc.cluster.local:9090"`
	LoadbalancerAddr    string `envconfig:"KACHO_LOADBALANCER_GRPC"        default:"loadbalancer.kacho.svc.cluster.local:9090"`
}

// BackendAddrs возвращает карту domain → адрес для инициализации Backends.
func (c Config) BackendAddrs() map[string]string {
	return map[string]string{
		"resourcemanager": c.ResourceManagerAddr,
		"vpc":             c.VPCAddr,
		"compute":         c.ComputeAddr,
		"loadbalancer":    c.LoadbalancerAddr,
	}
}

// Load читает конфигурацию из переменных окружения.
func Load() (Config, error) {
	var cfg Config
	if err := corecfg.Load(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
