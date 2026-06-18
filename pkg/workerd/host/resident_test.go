// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errStartBoom = errors.New("boom")

// readStagedResidentConfig reads the dispatcher capnp config EnsureResident
// staged under rootDir for the single resident sandbox.
func readStagedResidentConfig(t *testing.T, rootDir string) string {
	t.Helper()
	path := filepath.Join(rootDir, sanitizeID(residentSandboxID), configFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading staged resident config: %v", err)
	}
	return string(b)
}

func testResidentConfig() ResidentConfig {
	return ResidentConfig{
		WorkerdImage:      "reg.example.com/apoxy/workerd:stock",
		ControlSocketPath: "/run/workerd-manager/control.sock",
		RootDir:           "", // set per-test via newResidentHostWithCore + t.TempDir
	}
}

func newTestResidentHost(t *testing.T, core *fakeCore) *ResidentHost {
	t.Helper()
	cfg := testResidentConfig()
	cfg.RootDir = t.TempDir()
	return newResidentHostWithCore(core, cfg)
}

func TestNewResidentHost_RequiresImageAndControlSocket(t *testing.T) {
	cases := []struct {
		name string
		cfg  ResidentConfig
	}{
		{"no image", ResidentConfig{ControlSocketPath: "/c.sock"}},
		{"no control socket", ResidentConfig{WorkerdImage: "img"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewResidentHost(tc.cfg); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestEnsureResident_CreatesAndStartsTheDispatcher(t *testing.T) {
	core := &fakeCore{}
	h := newTestResidentHost(t, core)

	inst, err := h.EnsureResident(context.Background())
	if err != nil {
		t.Fatalf("EnsureResident: %v", err)
	}
	if inst.SandboxID != residentSandboxID {
		t.Errorf("SandboxID = %q, want %q", inst.SandboxID, residentSandboxID)
	}
	if inst.InboundSocket == "" {
		t.Errorf("InboundSocket not surfaced for the dispatcher http socket")
	}

	wantEvents := []string{"create:" + string(residentSandboxID), "start:" + string(residentSandboxID)}
	if !equalStrs(core.eventLog(), wantEvents) {
		t.Errorf("events = %v, want %v", core.eventLog(), wantEvents)
	}

	if len(core.created) != 1 {
		t.Fatalf("created %d specs, want 1", len(core.created))
	}
	spec := core.created[0]
	if spec.Image != "reg.example.com/apoxy/workerd:stock" {
		t.Errorf("Image = %q", spec.Image)
	}
	cmd := strings.Join(spec.Command, " ")
	if cmd != "workerd serve /worker/config.capnp --experimental --platform=systrap" {
		t.Errorf("Command = %q", cmd)
	}
	// Exactly one mount: the dispatcher config. The control socket is NOT a bind
	// mount (clrk has no host-UDS); it rides the control forwarder instead.
	if len(spec.Mounts) != 1 {
		t.Fatalf("want 1 mount (config only), got %d: %+v", len(spec.Mounts), spec.Mounts)
	}
	if spec.Mounts[0].Destination != "/worker/config.capnp" || !hasOpt(spec.Mounts[0].Options, "ro") {
		t.Errorf("config mount wrong: %+v", spec.Mounts[0])
	}
	if spec.InboundListenAddr != "127.0.0.1:8080" {
		t.Errorf("InboundListenAddr = %q, want 127.0.0.1:8080", spec.InboundListenAddr)
	}
	if spec.Stdio {
		t.Errorf("Stdio should be false for the resident dispatcher")
	}
}

func TestEnsureResident_Idempotent(t *testing.T) {
	core := &fakeCore{}
	h := newTestResidentHost(t, core)
	ctx := context.Background()

	first, err := h.EnsureResident(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.EnsureResident(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("EnsureResident should return the same instance when already up")
	}
	// Only one create+start: the second Ensure is a no-op.
	wantEvents := []string{"create:" + string(residentSandboxID), "start:" + string(residentSandboxID)}
	if !equalStrs(core.eventLog(), wantEvents) {
		t.Errorf("a second EnsureResident must not recreate the sandbox; events = %v", core.eventLog())
	}
}

func TestEnsureResident_RecreatesAfterCrash(t *testing.T) {
	core := &fakeCore{}
	h := newTestResidentHost(t, core)
	ctx := context.Background()

	first, err := h.EnsureResident(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The resident's workerd process dies out from under the host.
	core.crash(residentSandboxID)

	second, err := h.EnsureResident(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("EnsureResident should recreate a crashed resident, not return the dead instance")
	}
	// The stale sandbox is purged before a fresh create+start.
	wantEvents := []string{
		"create:" + string(residentSandboxID), "start:" + string(residentSandboxID),
		"purge:" + string(residentSandboxID),
		"create:" + string(residentSandboxID), "start:" + string(residentSandboxID),
	}
	if !equalStrs(core.eventLog(), wantEvents) {
		t.Errorf("events = %v, want %v", core.eventLog(), wantEvents)
	}
}

func TestEnsureResident_StartFailurePurges(t *testing.T) {
	core := &fakeCore{startErr: errStartBoom}
	h := newTestResidentHost(t, core)

	if _, err := h.EnsureResident(context.Background()); err == nil {
		t.Fatal("want error when Start fails")
	}
	wantEvents := []string{"create:" + string(residentSandboxID), "purge:" + string(residentSandboxID)}
	if !equalStrs(core.eventLog(), wantEvents) {
		t.Errorf("a failed Start should purge the half-created resident; events = %v", core.eventLog())
	}
	// A failed Ensure leaves no recorded instance, so a retry re-creates.
	if _, err := h.EnsureResident(context.Background()); err == nil {
		t.Fatal("retry after a failed Start should attempt create again")
	}
}

func TestResidentStop_DrainsAndForgets(t *testing.T) {
	core := &fakeCore{}
	h := newTestResidentHost(t, core)
	ctx := context.Background()
	if _, err := h.EnsureResident(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	// A second Stop is a no-op (nothing tracked).
	if err := h.Stop(ctx); err != nil {
		t.Errorf("Stop with no resident should be a no-op, got %v", err)
	}
	// After Stop, EnsureResident creates again.
	if _, err := h.EnsureResident(ctx); err != nil {
		t.Fatal(err)
	}
	wantEvents := []string{
		"create:" + string(residentSandboxID), "start:" + string(residentSandboxID),
		"stop:" + string(residentSandboxID), "purge:" + string(residentSandboxID),
		"create:" + string(residentSandboxID), "start:" + string(residentSandboxID),
	}
	if !equalStrs(core.eventLog(), wantEvents) {
		t.Errorf("events = %v, want %v", core.eventLog(), wantEvents)
	}
}

func TestHostInboundAddr(t *testing.T) {
	cases := []struct {
		name string
		sock SocketSpec
		want string
	}{
		{"wildcard http", SocketSpec{Kind: HTTPSocket, Addr: "*:8080"}, "127.0.0.1:8080"},
		{"explicit host http", SocketSpec{Kind: HTTPSocket, Addr: "127.0.0.1:9000"}, "127.0.0.1:9000"},
		{"unix listener has no tcp ingress", SocketSpec{Kind: HTTPSocket, Addr: "unix:/run/w.sock"}, ""},
		{"non-http socket", SocketSpec{Kind: FilterSocket, Addr: "*:8080"}, ""},
		{"unparseable addr", SocketSpec{Kind: HTTPSocket, Addr: "garbage"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostInboundAddr(tc.sock); got != tc.want {
				t.Errorf("hostInboundAddr(%+v) = %q, want %q", tc.sock, got, tc.want)
			}
		})
	}
}

// TestEnsureResident_DispatcherConfigDialsControlForwardAddr asserts the staged
// dispatcher config points the MANAGER external service at the in-sandbox
// control-forward TCP address (not a unix path), which the clrk control
// forwarder routes to the host control socket.
func TestEnsureResident_DispatcherConfigDialsControlForwardAddr(t *testing.T) {
	core := &fakeCore{}
	h := newTestResidentHost(t, core)
	if _, err := h.EnsureResident(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The config is staged at <rootDir>/<sanitized id>/config.capnp.
	got := readStagedResidentConfig(t, h.rootDir)
	if !strings.Contains(got, `external = (address = "127.0.0.2:80", http = ())`) {
		t.Errorf("dispatcher config should dial the control-forward TCP addr:\n%s", got)
	}
	if strings.Contains(got, "unix:") {
		t.Errorf("dispatcher config must not use a unix manager address (clrk has no host-UDS):\n%s", got)
	}
}
