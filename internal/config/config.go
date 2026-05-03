package config

import corecfg "github.com/PRO-Robotech/kacho-corelib/config"

// Config хранит конфигурацию api-gateway.
// Переменные окружения:
//
//	KACHO_API_GATEWAY_LISTEN_ADDR         — адрес для cmux listener (default: :8080)
//	KACHO_API_GATEWAY_RESOURCEMANAGER_GRPC — адрес backend resource-manager
//	KACHO_API_GATEWAY_VPC_GRPC            — адрес backend vpc
//
// Compute и loadbalancer заморожены — env vars удалены.
type Config struct {
	ListenAddr          string `envconfig:"KACHO_API_GATEWAY_LISTEN_ADDR"          default:":8080"`
	ResourceManagerAddr string `envconfig:"KACHO_API_GATEWAY_RESOURCEMANAGER_GRPC"  default:"resource-manager.kacho.svc.cluster.local:9090"`
	VPCAddr             string `envconfig:"KACHO_API_GATEWAY_VPC_GRPC"              default:"vpc.kacho.svc.cluster.local:9090"`
}

// BackendAddrs возвращает карту domain → адрес для инициализации Backends.
// "organizationmanager" → тот же resource-manager (реализует OrganizationService).
func (c Config) BackendAddrs() map[string]string {
	return map[string]string{
		"resourcemanager":     c.ResourceManagerAddr,
		"organizationmanager": c.ResourceManagerAddr,
		"vpc":                 c.VPCAddr,
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
