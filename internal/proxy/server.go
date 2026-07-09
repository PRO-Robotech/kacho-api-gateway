// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"strings"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/allowlist"
)

// Backends — карта «доменное имя → долгоживущий *grpc.ClientConn».
// Ключи: "iam", "vpc", "compute", "geo", "loadbalancer".
type Backends map[string]*grpc.ClientConn

// MethodResolver — re-export of local proxy MethodResolver type signature.
type MethodResolver = methodResolverInternal

// Resolver builds a MethodResolver for the unknown-service handler installed
// on the gRPC server. Behaviour:
//
//  1. /kacho.cloud.<rest>   — passes through the allowlist + backend lookup.
//  2. anything else (blocked / Internal* / unknown method) — returns ok=false,
//     which Handler (shimproxy.go) maps to codes.NotFound, NOT Unimplemented.
//     NotFound is load-bearing: it makes Internal* and unknown methods
//     indistinguishable from "method does not exist", so the external listener
//     is not an existence-oracle for admin endpoints ("exists but unimplemented"
//     would leak reconnaissance). Keep parity with the shimproxy.go contract.
//
// Маршрутизируются только нативные kacho.cloud.* сервисы; backends не
// expose'ят посторонних сервисов.
func Resolver(backends Backends) MethodResolver {
	return func(fullMethod string) (string, grpc.ClientConnInterface, bool) {
		method := fullMethod
		if !strings.HasPrefix(method, "/kacho.cloud.") {
			return "", nil, false
		}
		if allowlist.HasInternalSuffix(method) || !allowlist.IsAllowed(method) {
			return "", nil, false
		}
		// Parse domain from "/kacho.cloud.<domain>.<...>/<Method>".
		parts := strings.SplitN(method, "/", 3)
		if len(parts) < 3 || parts[1] == "" {
			return "", nil, false
		}
		pkgParts := strings.Split(parts[1], ".")
		if len(pkgParts) < 4 {
			return "", nil, false
		}
		conn, ok := backends[pkgParts[2]]
		if !ok {
			return "", nil, false
		}
		return method, conn, true
	}
}

// NewServer creates a gRPC server whose UnknownServiceHandler routes
// kacho.cloud.* traffic to the appropriate backend.
//
// Native services registered on this server (Health, OperationService) take
// precedence over the unknown-service handler, as per gRPC dispatch
// semantics.
func NewServer(resolve MethodResolver, opts ...grpc.ServerOption) *grpc.Server {
	base := []grpc.ServerOption{
		grpc.UnknownServiceHandler(Handler(resolve)),
	}
	return grpc.NewServer(append(base, opts...)...)
}
