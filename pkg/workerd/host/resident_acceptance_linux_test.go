// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux && acceptance

// Resident-path acceptance: boots the single shared resident workerd (the
// stock-workerd dispatcher, APO-796) on the real gVisor/runsc sandbox and
// asserts it serves the dispatcher health endpoint through the APO-694 inbound
// forwarder. This is the in-tree end-to-end proof that the dispatcher config
// (workerLoader binding + --experimental + the manager external service) boots
// under real workerd and that the inbound path reaches it.
//
// Supply a stock upstream workerd image (no customer code; the dispatcher source
// is inlined into the config) via:
//
//	APOXY_WORKERD_ACCEPTANCE_IMAGE  e.g. reg.example.com/apoxy/workerd:1.20260617.1
//
// Scope note: the FULL demux path (request with x-apoxy-service -> isolate
// loaded from the manager) additionally requires the clrk control forwarder
// (the guest->host channel the dispatcher's MANAGER service dials; see
// docs/workerd-runtime-mvp.md). Until that lands, this asserts only the
// manager-independent health path; the demux subtest skips with a clear message.
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
)

func acceptanceWorkerdImage(t *testing.T) string {
	t.Helper()
	img := os.Getenv("APOXY_WORKERD_ACCEPTANCE_IMAGE")
	if img == "" {
		t.Skip("set APOXY_WORKERD_ACCEPTANCE_IMAGE to a stock workerd OCI image")
	}
	return img
}

func acceptanceResident(t *testing.T) *host.ResidentHost {
	t.Helper()
	dir := t.TempDir()
	rh, err := host.NewResidentHost(host.ResidentConfig{
		StateDir:        dir + "/state",
		RootDir:         dir + "/root",
		ImageBaseDir:    dir + "/images",
		WorkerdImage:    acceptanceWorkerdImage(t),
		ControlHostAddr: "127.0.0.1:2024",
	})
	if err != nil {
		t.Fatalf("NewResidentHost: %v", err)
	}
	t.Cleanup(func() { _ = rh.Cleanup(context.Background()) })
	return rh
}

// TestAcceptance_ResidentServesHealth boots the resident dispatcher and curls
// its health endpoint through the host inbound socket.
func TestAcceptance_ResidentServesHealth(t *testing.T) {
	rh := acceptanceResident(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	inst, err := rh.EnsureResident(ctx)
	if err != nil {
		t.Fatalf("EnsureResident: %v", err)
	}
	if inst.InboundSocket == "" {
		t.Fatal("resident has no InboundSocket; the ingress forwarder did not open the host socket")
	}
	t.Cleanup(func() { _ = rh.Stop(context.Background()) })

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", inst.InboundSocket)
			},
		},
	}

	// The dispatcher answers /__apoxy/health without loading any isolate, so it
	// is reachable even with the control channel absent.
	var resp *http.Response
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err = client.Get("http://resident/__apoxy/health")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("health endpoint never came up: %v", err)
		}
		time.Sleep(time.Second)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d (body %q), want 200", resp.StatusCode, body)
	}
	t.Logf("resident dispatcher healthy through ingress socket: HTTP %d %q", resp.StatusCode, body)

	// A request carrying a service header needs the manager control channel,
	// which depends on the clrk control forwarder (not yet present). Document the
	// gap rather than asserting a path that cannot work yet.
	t.Run("demux", func(t *testing.T) {
		t.Skip("full demux requires the clrk control forwarder (guest->host); see docs/workerd-runtime-mvp.md")
	})
}
