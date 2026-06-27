// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// mtls_config.go — per-edge backend-dial credential selection.
//
// The gateway opens one long-lived ClientConn per backend-domain key (vpc /
// vpcInternal / compute / … — see config.BackendAddrs). Each key is mapped to
// its mTLS *edge* (vpc | compute | iam | nlb | geo), then per-edge transport
// credentials are built: the shared "api-gateway" client-cert (TLS) when the
// edge is enabled, or insecure when it is not (dev backward-compat).
//
// Contract:
//   - every edge disabled (default) ⇒ every dial insecure, identical to dev.
//   - an edge enabled with full cert material ⇒ TLS creds for every backend key
//     on that edge; other edges stay insecure.
//   - an edge enabled with missing/partial cert material ⇒ error (fail-fast);
//     main.go log.Fatalf's so the process does not start with a silent insecure
//     fallback.
//   - the "operation" self-loopback is NOT a backend edge — it is dialed
//     in-process and is always insecure.

import (
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/PRO-Robotech/kacho-corelib/grpcclient"

	"github.com/PRO-Robotech/kacho-api-gateway/internal/config"
	"github.com/PRO-Robotech/kacho-api-gateway/internal/proxy"
)

// backendKeepalive — keep idle inter-service conns warm (idle conns are killed
// faster than a 30s interval). Shared by every backend dial.
func backendKeepalive() keepalive.ClientParameters {
	return keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}
}

// dialBackends is the composition-root helper that opens one lazy ClientConn
// per backend-domain key with that key's per-edge transport creds (mTLS when its
// MTLS_<EDGE>_ENABLE flag is set + cert material present, else insecure — dev
// backward-compat), plus the always-insecure "operation" self-loopback
// ClientConn (in-process, never crosses a pod boundary).
//
// It is fail-fast: an enabled edge missing cert material aborts the whole build
// (the process must not come up half-secured); main.go log.Fatalf's on the
// returned error. Each ClientConn carries the shared keepalive + round-robin
// service-config.
//
// The returned cleanup closes every opened ClientConn; main.go defers it.
func dialBackends(cfg config.Config) (proxy.Backends, func(), error) {
	creds, err := buildBackendDialCreds(cfg)
	if err != nil {
		return nil, nil, err
	}

	kp := grpc.WithKeepaliveParams(backendKeepalive())
	rr := grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`)

	backends := make(proxy.Backends, len(creds)+1)
	opened := make([]*grpc.ClientConn, 0, len(creds)+1)
	cleanup := func() {
		for _, c := range opened {
			_ = c.Close()
		}
	}

	for key, addr := range cfg.BackendAddrs() {
		conn, dialErr := grpc.NewClient(addr, creds[key], kp, rr)
		if dialErr != nil {
			cleanup()
			return nil, nil, fmt.Errorf("dial %s (%s): %w", key, addr, dialErr)
		}
		opened = append(opened, conn)
		backends[key] = conn
	}

	// operation self-loopback — always insecure (in-process re-entry).
	loopbackAddr := cfg.ListenAddr
	if len(loopbackAddr) > 0 && loopbackAddr[0] == ':' {
		loopbackAddr = "127.0.0.1" + loopbackAddr
	}
	opsLoopback, dialErr := grpc.NewClient(loopbackAddr, loopbackDialCreds(), kp, rr)
	if dialErr != nil {
		cleanup()
		return nil, nil, fmt.Errorf("dial operation self-loopback (%s): %w", loopbackAddr, dialErr)
	}
	opened = append(opened, opsLoopback)
	backends["operation"] = opsLoopback

	return backends, cleanup, nil
}

// backendEdge maps a backend-domain key (as produced by config.BackendAddrs) to
// its mTLS edge name. The public and internal ports of a service share one edge
// (one backend identity, one enable flag): "vpc"+"vpcInternal" → "vpc", etc.
// "loadbalancer"+"loadbalancerInternal" → "nlb" (the nlb service is keyed
// "loadbalancer" in BackendAddrs to match its proto package).
// "geo"+"geoInternal" → "geo".
func backendEdge(backendKey string) string {
	switch backendKey {
	case "vpc", "vpcInternal":
		return "vpc"
	case "compute", "computeInternal":
		return "compute"
	case "iam", "iamInternal":
		return "iam"
	case "loadbalancer", "loadbalancerInternal":
		return "nlb"
	case "geo", "geoInternal":
		return "geo"
	default:
		// Unknown keys (e.g. "operation" self-loopback) have no cross-pod edge.
		// They are never passed here in the production wiring; returning "" makes
		// EdgeTLSClient reject them so a future map-key drift fails loudly.
		return ""
	}
}

// buildBackendDialCreds returns one transport-credentials dial-option per
// backend-domain key in config.BackendAddrs, selecting TLS vs insecure per edge.
//
// It is fail-fast: if any enabled edge lacks cert material the whole build
// returns an error (the process must not start half-secured). The returned map
// has exactly the keys of BackendAddrs; the "operation" loopback is intentionally
// absent (it is dialed separately via loopbackDialCreds).
func buildBackendDialCreds(cfg config.Config) (map[string]grpc.DialOption, error) {
	addrs := cfg.BackendAddrs()
	creds := make(map[string]grpc.DialOption, len(addrs))
	for key, addr := range addrs {
		edge := backendEdge(key)
		if edge == "" {
			return nil, fmt.Errorf("backend %q has no known mTLS edge", key)
		}
		tc, err := cfg.EdgeTLSClient(edge, addr)
		if err != nil {
			return nil, fmt.Errorf("backend %q (edge %s): %w", key, edge, err)
		}
		opt, err := grpcclient.TLSClientCreds(tc)
		if err != nil {
			return nil, fmt.Errorf("backend %q (edge %s) tls creds: %w", key, edge, err)
		}
		creds[key] = opt
	}
	return creds, nil
}

// loopbackDialCreds returns the always-insecure transport-credentials dial-option
// for the operation-domain self-loopback ClientConn. The loopback re-enters the
// gateway on 127.0.0.1 in-process; it never crosses a pod boundary, so mTLS does
// not apply regardless of which edges are enabled.
func loopbackDialCreds() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// iamEdgeDialCreds returns the transport-credentials dial-option for the
// gateway→iam edge, used by the two standalone iam dials (iam-subject and
// iam-authorize) that live outside the backends map. Both are the gateway→iam
// edge and share MTLS_IAM_ENABLE. Fail-fast on misconfig.
func iamEdgeDialCreds(cfg config.Config, addr string) (grpc.DialOption, error) {
	tc, err := cfg.EdgeTLSClient("iam", addr)
	if err != nil {
		return nil, fmt.Errorf("iam edge: %w", err)
	}
	opt, err := grpcclient.TLSClientCreds(tc)
	if err != nil {
		return nil, fmt.Errorf("iam edge tls creds: %w", err)
	}
	return opt, nil
}
