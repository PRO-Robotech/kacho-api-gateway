module github.com/PRO-Robotech/kacho-api-gateway

go 1.25.0

replace github.com/PRO-Robotech/kacho-corelib => ../kacho-corelib

replace github.com/PRO-Robotech/kacho-proto => ../kacho-proto

require (
	github.com/PRO-Robotech/kacho-corelib v0.0.0
	github.com/PRO-Robotech/kacho-proto v0.0.0
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	github.com/mwitkow/grpc-proxy v0.0.0-20250813121105-2866842de9a5
	github.com/soheilhy/cmux v0.1.5
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260427160629-7cedc36a6bc4
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260427160629-7cedc36a6bc4 // indirect
)
