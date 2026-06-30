module github.com/PRO-Robotech/kacho-api-gateway

go 1.26.4

require (
	github.com/PRO-Robotech/kacho-compute v1.0.2
	github.com/PRO-Robotech/kacho-corelib v1.0.3-0.20260629221224-9ee70b8d274e
	github.com/PRO-Robotech/kacho-geo v1.0.2
	github.com/PRO-Robotech/kacho-iam v1.0.2
	github.com/PRO-Robotech/kacho-nlb v1.0.3
	github.com/PRO-Robotech/kacho-vpc v1.0.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	github.com/soheilhy/cmux v0.1.5
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.56.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260427160629-7cedc36a6bc4
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260427160629-7cedc36a6bc4 // indirect
)

replace github.com/PRO-Robotech/kacho-vpc => github.com/PRO-Robotech/kacho-vpc v0.0.0-20260630130935-c708a07015e8

replace github.com/PRO-Robotech/kacho-nlb => github.com/PRO-Robotech/kacho-nlb v1.0.4-0.20260630131214-6c47bb3a3491
