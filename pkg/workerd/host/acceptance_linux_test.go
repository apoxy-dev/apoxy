// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux && acceptance

// Package host acceptance tests drive the real gVisor/runsc sandbox via
// host.NewRuntime, so they run only on a privileged, runsc-capable linux host
// and only under `-tags acceptance`. The posture mirrors clrk's privileged
// sandbox tests: CAP_SYS_ADMIN, cgroup v2, and the ability to `runsc create`.
//
// Supply a real, digest-pinned workerd bundle via the environment:
//
//	APOXY_WORKERD_ACCEPTANCE_REPO    e.g. reg.example.com/acme/api
//	APOXY_WORKERD_ACCEPTANCE_DIGEST  e.g. sha256:deadbeef...
//
// Scope note: these assert the lifecycle the extracted sandbox core can
// guarantee — create/start, make-before-break reload, and per-tenant isolation
// (distinct in-Sentry SandboxIPs). They deliberately do NOT curl the workerd
// fetch socket: under sentrystack that socket binds inside the in-Sentry
// netstack and there is no host route to Resident.SandboxIP. Reaching it needs
// the host->sandbox ingress forwarder (APO-628), at which point the gated
// fetch assertion below is unskipped.
package host_test

import (
	"context"
	"os"
	"testing"
	"time"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/clrk/pkg/sandbox"
)

func acceptanceBundle(t *testing.T) computev1alpha1.BundleRef {
	t.Helper()
	repo := os.Getenv("APOXY_WORKERD_ACCEPTANCE_REPO")
	digest := os.Getenv("APOXY_WORKERD_ACCEPTANCE_DIGEST")
	if repo == "" || digest == "" {
		t.Skip("set APOXY_WORKERD_ACCEPTANCE_REPO and APOXY_WORKERD_ACCEPTANCE_DIGEST to a workerd bundle")
	}
	return computev1alpha1.BundleRef{Repo: repo, Digest: digest}
}

func acceptanceRuntime(t *testing.T) *host.Runtime {
	t.Helper()
	dir := t.TempDir()
	rt, err := host.NewRuntime(host.Config{
		StateDir:     dir + "/state",
		RootDir:      dir + "/root",
		ImageBaseDir: dir + "/images",
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	t.Cleanup(func() { _ = rt.Cleanup(context.Background()) })
	return rt
}

func acceptanceRef(tenant, revision string, b computev1alpha1.BundleRef) host.ResidentRef {
	return host.ResidentRef{
		Tenant:   tenant,
		Revision: revision,
		Bundle:   b,
		Socket:   host.SocketSpec{Kind: host.HTTPSocket, Addr: "*:8080"},
	}
}

// TestAcceptance_EnsureRunsAndReloads boots a resident, then reloads it to a new
// revision and asserts make-before-break: the new sandbox is the sole live
// resident and the old one has been torn down.
func TestAcceptance_EnsureRunsAndReloads(t *testing.T) {
	b := acceptanceBundle(t)
	rt := acceptanceRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	r1, err := rt.Ensure(ctx, acceptanceRef("acme", "r1", b))
	if err != nil {
		t.Fatalf("Ensure r1: %v", err)
	}
	if r1.Phase != sandbox.SandboxRunning {
		t.Fatalf("r1 phase = %v, want Running", r1.Phase)
	}
	if !r1.SandboxIP.IsValid() {
		t.Fatalf("r1 has no SandboxIP")
	}

	r2, err := rt.Ensure(ctx, acceptanceRef("acme", "r2", b))
	if err != nil {
		t.Fatalf("Ensure r2 (reload): %v", err)
	}
	if r2.SandboxID == r1.SandboxID {
		t.Fatalf("reload reused the sandbox id %q; revisions must get distinct sandboxes", r1.SandboxID)
	}
	if live := rt.List(); len(live) != 1 || live[0].Revision != "r2" {
		t.Fatalf("after reload the sole live resident should be r2, got %+v", live)
	}

	// TODO(APO-628): once the host->sandbox ingress forwarder lands, dial
	// r2.SandboxIP:8080 and assert the worker's fetch handler responds.

	if err := rt.Stop(ctx, "acme"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if live := rt.List(); len(live) != 0 {
		t.Fatalf("Stop should leave no live residents, got %+v", live)
	}
}

// TestAcceptance_TwoTenantsIsolated asserts two tenants get two distinct
// gVisor sandboxes with distinct in-Sentry IPs — per-customer isolation by
// construction.
func TestAcceptance_TwoTenantsIsolated(t *testing.T) {
	b := acceptanceBundle(t)
	rt := acceptanceRuntime(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	a, err := rt.Ensure(ctx, acceptanceRef("acme", "r1", b))
	if err != nil {
		t.Fatalf("Ensure acme: %v", err)
	}
	g, err := rt.Ensure(ctx, acceptanceRef("globex", "r1", b))
	if err != nil {
		t.Fatalf("Ensure globex: %v", err)
	}

	if a.SandboxID == g.SandboxID {
		t.Fatalf("tenants share sandbox id %q", a.SandboxID)
	}
	if a.SandboxIP == g.SandboxIP {
		t.Fatalf("tenants share SandboxIP %v; sandboxes are not isolated", a.SandboxIP)
	}
	if live := rt.List(); len(live) != 2 {
		t.Fatalf("want 2 live residents, got %d", len(live))
	}

	_ = rt.Stop(ctx, "acme")
	_ = rt.Stop(ctx, "globex")
}
