// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// render_geo_test.go — deploy render-guard for the geo backend cutover.
//
// The api-gateway dials the kacho-geo gRPC backend by host:port. The geo k8s
// Service is "kacho-geo" (public) / "kacho-geo-internal" (internal); the bare
// "geo.kacho.svc.cluster.local" host does NOT resolve (NXDOMAIN) → the grpc
// balancer reports "no children to pick from" → every authenticated /geo/v1/*
// request returns 503. This guard renders the helm chart and asserts the chart
// emits the correct dial host (and the geo mTLS edge env when the edge is on),
// so a future stale-host regression fails the build, not production.
package deploy_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// helmTemplate renders deploy/ with the given --set overrides. On a dev machine
// without helm the render-guard is skipped (keeps `go test ./...` green), but in
// CI (env CI set — GitHub Actions sets it) a missing helm binary is a hard
// FAILURE, not a skip: the render guards must never silently become inert on the
// job that gates merge. The CI job installs helm (azure/setup-helm), so this
// path only fires if that step is dropped.
func helmTemplate(t *testing.T, sets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("helm binary not on PATH in CI — render-guard must run, not skip (add azure/setup-helm to the job)")
		}
		t.Skip("helm binary not on PATH — skipping deploy render-guard")
	}
	args := []string{"template", "."}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command("helm", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestRender_GeoBackendHost — the rendered Deployment must set the geo gRPC
// backend env to the real Service host (kacho-geo / kacho-geo-internal), never
// the NXDOMAIN "geo.kacho.svc.cluster.local".
func TestRender_GeoBackendHost(t *testing.T) {
	out := helmTemplate(t)

	mustContain(t, out, "KACHO_API_GATEWAY_GEO_GRPC")
	mustContain(t, out, "kacho-geo.kacho.svc.cluster.local:9090")
	mustContain(t, out, "KACHO_API_GATEWAY_GEO_INTERNAL_GRPC")
	mustContain(t, out, "kacho-geo-internal.kacho.svc.cluster.local:9091")

	if strings.Contains(out, "geo.kacho.svc.cluster.local") &&
		!strings.Contains(out, "kacho-geo.kacho.svc.cluster.local") {
		t.Fatalf("stale NXDOMAIN geo host rendered; want kacho-geo.*")
	}
	// Belt-and-suspenders: the bare "geo." host (not prefixed by kacho-) must be
	// absent from the geo env value lines.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "value:") && strings.Contains(line, " geo.kacho.svc.cluster.local") {
			t.Fatalf("stale geo host in rendered env line: %q", strings.TrimSpace(line))
		}
	}
}

// TestRender_GeoMTLSEdgeEnabled — when the geo mTLS edge is enabled the chart
// must emit KACHO_API_GATEWAY_MTLS_GEO_ENABLE=true (so dialOpts["geo"] /
// dialOpts["geoInternal"] carry the gateway client cert). Mirrors the compute
// edge wiring. SERVER_NAME stays unset (derived per dial-host like iam/nlb).
func TestRender_GeoMTLSEdgeEnabled(t *testing.T) {
	out := helmTemplate(t, "mtls.enable=true", "mtls.edges.geo=true")
	mustContain(t, out, "KACHO_API_GATEWAY_MTLS_GEO_ENABLE")
	// the geo backend host must still be correct under the mTLS profile.
	mustContain(t, out, "kacho-geo.kacho.svc.cluster.local:9090")
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("rendered manifest missing %q", needle)
	}
}
