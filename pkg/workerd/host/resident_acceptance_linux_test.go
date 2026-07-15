// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux && acceptance

// Resident-path acceptance: boots resident workerds (the stock-workerd
// dispatcher, APO-796) on the real gVisor/runsc sandbox and asserts they serve
// the dispatcher health endpoint through the APO-694 inbound forwarder. This is
// the in-tree end-to-end proof that the dispatcher config (workerLoader binding
// + --experimental + the manager external service) boots under real workerd and
// that the inbound path reaches it — including the per-tenant topology, where
// each tenant's resident gets its own sandbox id, inbound socket, and control
// address.
//
// Supply a stock upstream workerd image (no customer code; the dispatcher source
// is inlined into the config) via:
//
//	APOXY_WORKERD_ACCEPTANCE_IMAGE  e.g. reg.example.com/apoxy/workerd:1.20260617.1
//
// Scope note: the FULL demux path (request with x-apoxy-service -> isolate
// loaded from the manager) additionally requires the clrk control forwarder
// (the guest->host channel the dispatcher's MANAGER service dials; see
// docs/workerd-runtime-mvp.md). This file asserts only the manager-independent
// health path; the demux subtest skips with a clear message.
package host_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

func acceptanceWorkerdImage(t *testing.T) string {
	t.Helper()
	img := os.Getenv("APOXY_WORKERD_ACCEPTANCE_IMAGE")
	if img == "" {
		t.Skip("set APOXY_WORKERD_ACCEPTANCE_IMAGE to a stock workerd OCI image")
	}
	return img
}

func acceptanceFactory(t *testing.T) *host.ResidentFactory {
	t.Helper()
	// A persistent workdir (APOXY_ACC_WORKDIR) keeps the runsc/Sentry debug logs
	// around after the test for diagnostics; otherwise use an auto-removed temp.
	dir := os.Getenv("APOXY_ACC_WORKDIR")
	if dir == "" {
		dir = t.TempDir()
	}
	stateDir, rootDir, imageDir := dir+"/state", dir+"/root", dir+"/images"
	// Mirror the production manager, which pre-creates these dirs at startup
	// (pkg/workerd/manager/run.go): the ImageStore only MkdirTemps INSIDE
	// ImageBaseDir, so the base must already exist before the first pull.
	for _, d := range []string{stateDir, rootDir, imageDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("creating %s: %v", d, err)
		}
	}
	f, err := host.NewResidentFactory(host.ResidentConfig{
		StateDir:     stateDir,
		RootDir:      rootDir,
		ImageBaseDir: imageDir,
		WorkerdImage: acceptanceWorkerdImage(t),
	})
	if err != nil {
		t.Fatalf("NewResidentFactory: %v", err)
	}
	if err := f.CleanupOrphans(context.Background()); err != nil {
		t.Fatalf("CleanupOrphans: %v", err)
	}
	return f
}

// reserveLoopbackAddr binds an ephemeral loopback port and returns its address,
// mirroring how the manager allocates per-tenant control addresses. The
// listener stays open for the test's lifetime so the port stays reserved.
func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving loopback port: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// bootResident brings a tenant's resident up and returns the running instance.
func bootResident(ctx context.Context, t *testing.T, f *host.ResidentFactory, tenant, controlAddr string) (host.ResidentRuntime, *host.ResidentInstance) {
	t.Helper()
	rh, err := f.NewResident(tenant, controlAddr)
	if err != nil {
		t.Fatalf("NewResident(%q): %v", tenant, err)
	}
	inst, err := rh.EnsureResident(ctx)
	if err != nil {
		t.Fatalf("EnsureResident(%q): %v", tenant, err)
	}
	if inst.InboundSocket == "" {
		t.Fatalf("resident %q has no InboundSocket; the ingress forwarder did not open the host socket", tenant)
	}
	t.Cleanup(func() { _ = rh.Stop(context.Background()) })
	return rh, inst
}

func healthClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
}

// awaitHealth polls the dispatcher health endpoint through the inbound socket.
func awaitHealth(t *testing.T, sock string) {
	t.Helper()
	client := healthClient(sock)
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := client.Get("http://resident/__apoxy/health")
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status = %d (body %q), want 200", resp.StatusCode, body)
			}
			t.Logf("resident dispatcher healthy through %s: HTTP %d %q", sock, resp.StatusCode, body)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("health endpoint never came up on %s: %v", sock, err)
		}
		time.Sleep(time.Second)
	}
}

// TestAcceptance_ResidentServesHealth boots the single-project resident (the
// empty tenant, legacy naming) and curls its health endpoint through the host
// inbound socket.
func TestAcceptance_ResidentServesHealth(t *testing.T) {
	f := acceptanceFactory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, inst := bootResident(ctx, t, f, "", "127.0.0.1:2024")
	awaitHealth(t, inst.InboundSocket)

	// A request carrying a service header needs the manager control channel,
	// which depends on the clrk control forwarder (not exercised here). Document
	// the gap rather than asserting a path that cannot work in this harness.
	t.Run("demux", func(t *testing.T) {
		t.Skip("full demux requires the clrk control forwarder (guest->host); see docs/workerd-runtime-mvp.md")
	})
}

// TestAcceptance_TwoTenantResidents boots two tenants' residents over one
// shared core — each with an ephemeral (non-2024) control address, as the
// shared-backplane manager allocates them — and asserts distinct per-tenant
// sockets serve health independently: stopping tenant A leaves tenant B up.
// The non-default control ports also prove the sandbox spec accepts an
// arbitrary ControlHostAddr (only 127.0.0.1:2024 had ever been exercised).
func TestAcceptance_TwoTenantResidents(t *testing.T) {
	const tenantA = "7ce458d7-e20c-443c-aeeb-dbc5663c1240"
	const tenantB = "11111111-2222-4333-8444-555555555555"

	f := acceptanceFactory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ra, ia := bootResident(ctx, t, f, tenantA, reserveLoopbackAddr(t))
	_, ib := bootResident(ctx, t, f, tenantB, reserveLoopbackAddr(t))

	if ia.SandboxID != names.ResidentID(tenantA) || ib.SandboxID != names.ResidentID(tenantB) {
		t.Fatalf("sandbox ids = %q/%q, want per-tenant names", ia.SandboxID, ib.SandboxID)
	}
	if ia.InboundSocket == ib.InboundSocket {
		t.Fatalf("tenants share an inbound socket %q; per-tenant sockets must differ", ia.InboundSocket)
	}

	awaitHealth(t, ia.InboundSocket)
	awaitHealth(t, ib.InboundSocket)

	if err := ra.Stop(context.Background()); err != nil {
		t.Fatalf("stopping tenant A: %v", err)
	}
	awaitHealth(t, ib.InboundSocket)
	if _, err := healthClient(ia.InboundSocket).Get("http://resident/__apoxy/health"); err == nil {
		t.Fatal("tenant A's socket still serves after Stop")
	}

	// Stop-then-recreate on the REAL core: a disengaged tenant that re-engages
	// gets a fresh resident under the same deterministic sandbox id. This is
	// the flow that wedges on ErrAlreadyExists if Purge fails to release the
	// id from the manager's in-memory registration.
	_, ia2 := bootResident(ctx, t, f, tenantA, reserveLoopbackAddr(t))
	awaitHealth(t, ia2.InboundSocket)
}
