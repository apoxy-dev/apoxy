// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/clrk/pkg/sandbox"
)

// fakeCore is an in-memory sandbox.Runtime that records the lifecycle calls in
// order, so the wrapper's make-before-break sequencing can be asserted.
type fakeCore struct {
	mu        sync.Mutex
	events    []string
	created   []sandbox.Spec
	createErr error
	startErr  error
}

func (f *fakeCore) Create(ctx context.Context, spec sandbox.Spec) (*sandbox.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.events = append(f.events, "create:"+string(spec.ID))
	f.created = append(f.created, spec)
	inst := &sandbox.Instance{
		ID:        spec.ID,
		Phase:     sandbox.SandboxReady,
		SandboxIP: netip.AddrFrom4([4]byte{10, 88, byte(len(f.created)), 2}),
	}
	// Model the core surfacing the ingress socket for an inbound-enabled
	// sandbox (the real manager sets this at Start on the same instance).
	if spec.InboundListenAddr != "" {
		inst.InboundSocket = "/fake/" + strings.ReplaceAll(string(spec.ID), "/", "_") + ".in.sock"
	}
	return inst, nil
}

func (f *fakeCore) Start(ctx context.Context, id sandbox.SandboxID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.events = append(f.events, "start:"+string(id))
	return nil
}

func (f *fakeCore) Stop(ctx context.Context, id sandbox.SandboxID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "stop:"+string(id))
	return nil
}

func (f *fakeCore) Kill(ctx context.Context, id sandbox.SandboxID) error { return nil }

func (f *fakeCore) Wait(ctx context.Context, id sandbox.SandboxID) (int, error) { return 0, nil }

func (f *fakeCore) Delete(ctx context.Context, id sandbox.SandboxID) error { return nil }

func (f *fakeCore) Purge(ctx context.Context, id sandbox.SandboxID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "purge:"+string(id))
}

func (f *fakeCore) Status(ctx context.Context, id sandbox.SandboxID) (*sandbox.Instance, error) {
	return &sandbox.Instance{ID: id, Phase: sandbox.SandboxRunning}, nil
}

func (f *fakeCore) List() []*sandbox.Instance { return nil }

func (f *fakeCore) Cleanup(ctx context.Context) error { return nil }

func (f *fakeCore) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

// fixedManifest returns a manifest fetcher that always yields a single-esModule
// bundle, ignoring the ref.
func fixedManifest() func(context.Context, string) (computev1alpha1.BundleManifest, error) {
	return func(_ context.Context, _ string) (computev1alpha1.BundleManifest, error) {
		return computev1alpha1.BundleManifest{
			Modules:           []computev1alpha1.Module{{Name: "index.js", Type: computev1alpha1.ESModule, Path: "index.js"}},
			CompatibilityDate: "2024-01-01",
		}, nil
	}
}

func newTestRuntime(t *testing.T, core sandbox.Runtime) *Runtime {
	t.Helper()
	return newRuntimeWithCore(core, t.TempDir(), fixedManifest())
}

func ref(tenant, revision string) ResidentRef {
	return ResidentRef{
		Tenant:   tenant,
		Revision: revision,
		Bundle:   computev1alpha1.BundleRef{Repo: "reg.example.com/acme/api", Digest: "sha256:abc123"},
		Config:   computev1alpha1.ServiceConfigSpec{},
		Socket:   SocketSpec{Kind: HTTPSocket, Addr: "*:8080"},
	}
}

func TestEnsure_CreatesAndStarts(t *testing.T) {
	core := &fakeCore{}
	rt := newTestRuntime(t, core)

	res, err := rt.Ensure(context.Background(), ref("acme", "r1"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if res.SandboxID != "acme/r1" {
		t.Errorf("SandboxID = %q, want acme/r1", res.SandboxID)
	}
	if !res.SandboxIP.IsValid() {
		t.Errorf("SandboxIP not surfaced from the created instance: %v", res.SandboxIP)
	}
	if res.InboundSocket == "" {
		t.Errorf("InboundSocket not surfaced for an HTTP-socket resident")
	}
	if want := []string{"create:acme/r1", "start:acme/r1"}; !equalStrs(core.eventLog(), want) {
		t.Errorf("events = %v, want %v", core.eventLog(), want)
	}
	if len(core.created) != 1 {
		t.Fatalf("created %d specs, want 1", len(core.created))
	}
	spec := core.created[0]
	if spec.Image != "reg.example.com/acme/api@sha256:abc123" {
		t.Errorf("Image = %q", spec.Image)
	}
	if got := strings.Join(spec.Command, " "); got != "workerd serve /worker/config.capnp --platform=systrap" {
		t.Errorf("Command = %q", got)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Destination != "/worker/config.capnp" || !hasOpt(spec.Mounts[0].Options, "ro") {
		t.Errorf("config mount wrong: %+v", spec.Mounts)
	}
	if !reflect.DeepEqual(spec.Egress, sandbox.EgressInit{}) {
		t.Errorf("Egress should be zero for M1 backend mode, got %+v", spec.Egress)
	}
	if spec.InboundListenAddr != "127.0.0.1:8080" {
		t.Errorf("InboundListenAddr = %q, want 127.0.0.1:8080 (derived from the http socket)", spec.InboundListenAddr)
	}
	if spec.Stdio {
		t.Errorf("Stdio should be false for a resident socket server")
	}
}

func TestEnsure_SameRevisionNoOp(t *testing.T) {
	core := &fakeCore{}
	rt := newTestRuntime(t, core)
	ctx := context.Background()

	if _, err := rt.Ensure(ctx, ref("acme", "r1")); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Ensure(ctx, ref("acme", "r1")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"create:acme/r1", "start:acme/r1"}; !equalStrs(core.eventLog(), want) {
		t.Errorf("a same-revision Ensure should be a no-op; events = %v", core.eventLog())
	}
}

func TestEnsure_ReloadMakeBeforeBreak(t *testing.T) {
	core := &fakeCore{}
	rt := newTestRuntime(t, core)
	ctx := context.Background()

	if _, err := rt.Ensure(ctx, ref("acme", "r1")); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Ensure(ctx, ref("acme", "r2")); err != nil {
		t.Fatal(err)
	}
	// The new revision must be fully up (create+start) BEFORE the old one is
	// stopped — make-before-break.
	want := []string{
		"create:acme/r1", "start:acme/r1",
		"create:acme/r2", "start:acme/r2",
		"stop:acme/r1", "purge:acme/r1",
	}
	if !equalStrs(core.eventLog(), want) {
		t.Errorf("reload order wrong:\n got %v\nwant %v", core.eventLog(), want)
	}
	if live := rt.List(); len(live) != 1 || live[0].Revision != "r2" {
		t.Errorf("after reload the live revision should be r2, got %+v", live)
	}
}

func TestEnsure_StartFailurePurges(t *testing.T) {
	core := &fakeCore{startErr: fmt.Errorf("boom")}
	rt := newTestRuntime(t, core)

	if _, err := rt.Ensure(context.Background(), ref("acme", "r1")); err == nil {
		t.Fatal("want error when Start fails")
	}
	if want := []string{"create:acme/r1", "purge:acme/r1"}; !equalStrs(core.eventLog(), want) {
		t.Errorf("a failed Start should purge the half-created sandbox; events = %v", core.eventLog())
	}
	if len(rt.List()) != 0 {
		t.Errorf("a failed Ensure should not record a resident")
	}
}

func TestStop_DrainsAndForgets(t *testing.T) {
	core := &fakeCore{}
	rt := newTestRuntime(t, core)
	ctx := context.Background()
	if _, err := rt.Ensure(ctx, ref("acme", "r1")); err != nil {
		t.Fatal(err)
	}
	if err := rt.Stop(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if len(rt.List()) != 0 {
		t.Errorf("Stop should forget the slot")
	}
	if err := rt.Stop(ctx, "acme"); err != nil {
		t.Errorf("Stop on an unknown tenant should be a no-op, got %v", err)
	}
}

func TestBundleImageRef(t *testing.T) {
	cases := []struct {
		name    string
		ref     computev1alpha1.BundleRef
		want    string
		wantErr bool
	}{
		{"digest preferred", computev1alpha1.BundleRef{Repo: "r/x", Digest: "sha256:d", Tag: "latest"}, "r/x@sha256:d", false},
		{"tag fallback", computev1alpha1.BundleRef{Repo: "r/x", Tag: "v1"}, "r/x:v1", false},
		{"no repo", computev1alpha1.BundleRef{Tag: "v1"}, "", true},
		{"neither digest nor tag", computev1alpha1.BundleRef{Repo: "r/x"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bundleImageRef(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}
