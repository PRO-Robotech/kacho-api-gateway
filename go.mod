module github.com/PRO-Robotech/kacho-api-gateway

go 1.25.11

replace github.com/PRO-Robotech/kacho-corelib => ../kacho-corelib

replace github.com/PRO-Robotech/kacho-compute => ../kacho-compute

replace github.com/PRO-Robotech/kacho-geo => ../kacho-geo

replace github.com/PRO-Robotech/kacho-nlb => ../kacho-nlb

replace github.com/PRO-Robotech/kacho-vpc => ../kacho-vpc

replace github.com/PRO-Robotech/kacho-proto => ../kacho-proto

require (
	github.com/PRO-Robotech/kacho-compute v0.0.0
	github.com/PRO-Robotech/kacho-corelib v0.1.1-0.20260618025241-a8dbc86653dc
	github.com/PRO-Robotech/kacho-geo v0.0.0
	github.com/PRO-Robotech/kacho-nlb v0.0.0
	github.com/PRO-Robotech/kacho-proto v0.1.1-0.20260624203923-05d1904e3797
	github.com/PRO-Robotech/kacho-vpc v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	github.com/soheilhy/cmux v0.1.5
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.55.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260427160629-7cedc36a6bc4
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260427160629-7cedc36a6bc4 // indirect
)
