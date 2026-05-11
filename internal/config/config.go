package config

import corecfg "github.com/PRO-Robotech/kacho-corelib/config"

// Config хранит конфигурацию api-gateway.
// Переменные окружения:
//
//	KACHO_API_GATEWAY_LISTEN_ADDR         — адрес для cmux listener (default: :8080)
//	KACHO_API_GATEWAY_TLS_LISTEN_ADDR     — адрес для TLS listener (default: пусто — TLS отключён)
//	KACHO_API_GATEWAY_TLS_CERT_FILE       — путь к TLS-сертификату (PEM)
//	KACHO_API_GATEWAY_TLS_KEY_FILE        — путь к TLS-приватному ключу (PEM)
//	KACHO_API_GATEWAY_RESOURCEMANAGER_GRPC — адрес backend resource-manager
//	KACHO_API_GATEWAY_VPC_GRPC            — адрес backend vpc
//	KACHO_API_GATEWAY_COMPUTE_GRPC        — адрес backend compute (public, port 9090)
//	KACHO_API_GATEWAY_COMPUTE_INTERNAL_GRPC — адрес backend compute internal-port (9091)
//
// TLS требуется для совместимости с CLI-клиентами (yc CLI hardcoded требует TLS).
// Когда TLS_LISTEN_ADDR пустой — TLS не запускается; plain-cmux на ListenAddr.
//
// loadbalancer заморожен — env vars удалены.
type Config struct {
	ListenAddr          string `envconfig:"KACHO_API_GATEWAY_LISTEN_ADDR"          default:":8080"`
	TLSListenAddr       string `envconfig:"KACHO_API_GATEWAY_TLS_LISTEN_ADDR"      default:""`
	TLSCertFile         string `envconfig:"KACHO_API_GATEWAY_TLS_CERT_FILE"        default:""`
	TLSKeyFile          string `envconfig:"KACHO_API_GATEWAY_TLS_KEY_FILE"         default:""`
	ResourceManagerAddr string `envconfig:"KACHO_API_GATEWAY_RESOURCEMANAGER_GRPC"  default:"resource-manager.kacho.svc.cluster.local:9090"`
	VPCAddr             string `envconfig:"KACHO_API_GATEWAY_VPC_GRPC"              default:"vpc.kacho.svc.cluster.local:9090"`
	// VPCInternalAddr — admin-only internal-port (9091) of vpc backend.
	// Routes Region/Zone/AddressPool RESTful endpoints (kacho-only, NOT YC-verbatim).
	VPCInternalAddr string `envconfig:"KACHO_API_GATEWAY_VPC_INTERNAL_GRPC" default:"vpc.kacho.svc.cluster.local:9091"`
	// ComputeAddr — public gRPC backend of kacho-compute (Disk/Image/Snapshot/Instance/DiskType/Zone).
	ComputeAddr string `envconfig:"KACHO_API_GATEWAY_COMPUTE_GRPC" default:"compute.kacho.svc.cluster.local:9090"`
	// ComputeInternalAddr — admin-only internal-port (9091) of compute backend.
	// Routes InternalDiskType/InternalZone RESTful endpoints (kacho-only, NOT YC-verbatim).
	ComputeInternalAddr string `envconfig:"KACHO_API_GATEWAY_COMPUTE_INTERNAL_GRPC" default:"compute.kacho.svc.cluster.local:9091"`

	// AdvertisedEndpointAddr — host:port that the api-gateway advertises in
	// the yc CLI compatibility shim (yandex.cloud.endpoint.ApiEndpointService).
	// External clients dial this address. Defaults to api.kacho.local:443.
	AdvertisedEndpointAddr string `envconfig:"KACHO_API_GATEWAY_ADVERTISED_ENDPOINT" default:"api.kacho.local:443"`
}

// TLSEnabled возвращает true, если TLS-listener должен быть запущен.
// Требует одновременно TLS_LISTEN_ADDR + TLS_CERT_FILE + TLS_KEY_FILE.
func (c Config) TLSEnabled() bool {
	return c.TLSListenAddr != "" && c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// AdvertisedEndpoint returns the host:port to advertise in the yc CLI
// compatibility shim (ApiEndpointService.List response).
func (c Config) AdvertisedEndpoint() string {
	return c.AdvertisedEndpointAddr
}

// BackendAddrs возвращает карту domain → адрес для инициализации Backends.
// "organizationmanager" → тот же resource-manager (реализует OrganizationService).
func (c Config) BackendAddrs() map[string]string {
	return map[string]string{
		"resourcemanager":     c.ResourceManagerAddr,
		"organizationmanager": c.ResourceManagerAddr,
		"vpc":                 c.VPCAddr,
		"vpcInternal":         c.VPCInternalAddr,
		"compute":             c.ComputeAddr,
		"computeInternal":     c.ComputeInternalAddr,
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
