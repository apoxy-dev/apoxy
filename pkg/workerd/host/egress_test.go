// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"errors"
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// newRunningResident builds a ResidentHost over an egress-wrapped fake core
// and brings its resident up.
func newRunningResident(t *testing.T, core *fakeCore) (*ResidentHost, *egressCore) {
	t.Helper()
	ec := newEgressCore(core)
	cfg := testResidentConfig()
	cfg.RootDir = t.TempDir()
	h := newResidentHostWithCore(ec, cfg)
	if _, err := h.EnsureResident(context.Background()); err != nil {
		t.Fatalf("EnsureResident: %v", err)
	}
	return h, ec
}

func TestEgressCore_StateLifecycle(t *testing.T) {
	ctx := context.Background()
	const id = sandbox.SandboxID("sb-egress")
	spec := sandbox.Spec{ID: id, Image: "img"}

	cases := []struct {
		name string
		run  func(t *testing.T, ec *egressCore)
	}{
		{
			name: "setters on an uncreated sandbox return ErrNotFound",
			run: func(t *testing.T, ec *egressCore) {
				if err := ec.SetEgressBackends(id, nil); !errors.Is(err, sandbox.ErrNotFound) {
					t.Errorf("SetEgressBackends = %v; want ErrNotFound", err)
				}
				if err := ec.SetEgressPolicy(id, nil); !errors.Is(err, sandbox.ErrNotFound) {
					t.Errorf("SetEgressPolicy = %v; want ErrNotFound", err)
				}
				if err := ec.SetInvocationID(id, "inv"); !errors.Is(err, sandbox.ErrNotFound) {
					t.Errorf("SetInvocationID = %v; want ErrNotFound", err)
				}
			},
		},
		{
			name: "create registers state and setters land",
			run: func(t *testing.T, ec *egressCore) {
				if _, err := ec.Create(ctx, spec); err != nil {
					t.Fatalf("Create: %v", err)
				}
				backends := []sandbox.BackendListener{{Name: "eg", Addr: "127.0.0.1:8093"}}
				pol := &sandbox.Policy{DefaultDeny: true}
				if err := ec.SetEgressBackends(id, backends); err != nil {
					t.Fatalf("SetEgressBackends: %v", err)
				}
				if err := ec.SetEgressPolicy(id, pol); err != nil {
					t.Fatalf("SetEgressPolicy: %v", err)
				}
				if err := ec.SetInvocationID(id, "inv-1"); err != nil {
					t.Fatalf("SetInvocationID: %v", err)
				}
				st, ok := ec.LookupEgressState(id)
				if !ok {
					t.Fatal("LookupEgressState: state missing after setters")
				}
				if len(st.Backends) != 1 || st.Backends[0].Name != "eg" {
					t.Errorf("Backends = %+v; want the applied listener", st.Backends)
				}
				if st.Policy == nil || !st.Policy.DefaultDeny {
					t.Errorf("Policy = %+v; want DefaultDeny", st.Policy)
				}
				if st.InvocationID != "inv-1" {
					t.Errorf("InvocationID = %q; want %q", st.InvocationID, "inv-1")
				}
			},
		},
		{
			name: "failed core create leaves no state behind",
			run: func(t *testing.T, ec *egressCore) {
				ec.Runtime.(*fakeCore).createErr = errStartBoom
				if _, err := ec.Create(ctx, spec); err == nil {
					t.Fatal("Create: want error, got nil")
				}
				if _, ok := ec.LookupEgressState(id); ok {
					t.Error("state registered despite failed create")
				}
			},
		},
		{
			name: "duplicate create failure preserves the live sandbox's state",
			run: func(t *testing.T, ec *egressCore) {
				if _, err := ec.Create(ctx, spec); err != nil {
					t.Fatalf("Create: %v", err)
				}
				if err := ec.SetInvocationID(id, "live"); err != nil {
					t.Fatalf("SetInvocationID: %v", err)
				}
				// An ErrAlreadyExists loser (duplicate create racing the live
				// sandbox) must not wipe the winner's applied config.
				ec.Runtime.(*fakeCore).createErr = sandbox.ErrAlreadyExists
				if _, err := ec.Create(ctx, spec); err == nil {
					t.Fatal("duplicate Create: want error, got nil")
				}
				st, ok := ec.LookupEgressState(id)
				if !ok || st.InvocationID != "live" {
					t.Errorf("live state after duplicate create = %+v (ok=%v); want preserved", st, ok)
				}
			},
		},
		{
			name: "purge drops state",
			run: func(t *testing.T, ec *egressCore) {
				if _, err := ec.Create(ctx, spec); err != nil {
					t.Fatalf("Create: %v", err)
				}
				ec.Purge(ctx, id)
				if _, ok := ec.LookupEgressState(id); ok {
					t.Error("state survived Purge")
				}
			},
		},
		{
			name: "delete drops state",
			run: func(t *testing.T, ec *egressCore) {
				if _, err := ec.Create(ctx, spec); err != nil {
					t.Fatalf("Create: %v", err)
				}
				if err := ec.Delete(ctx, id); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				if _, ok := ec.LookupEgressState(id); ok {
					t.Error("state survived Delete")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newEgressCore(&fakeCore{}))
		})
	}
}

func TestResidentHost_ApplyEgress(t *testing.T) {
	backends := []sandbox.BackendListener{{Name: "eg", Addr: "127.0.0.1:8093", Shape: "tcp"}}

	cases := []struct {
		name string
		run  func(t *testing.T, h *ResidentHost, ec *egressCore)
	}{
		{
			name: "apply lands in the recorded state and echoes the generation",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				gen, err := h.ApplyEgress(EgressApply{Backends: backends, InvocationID: "inv-1", Generation: 3})
				if err != nil {
					t.Fatalf("ApplyEgress: %v", err)
				}
				if gen != 3 {
					t.Errorf("applied generation = %d; want 3", gen)
				}
				st, ok := ec.LookupEgressState(h.id)
				if !ok {
					t.Fatal("no egress state recorded")
				}
				if len(st.Backends) != 1 || st.Backends[0].Name != "eg" || st.InvocationID != "inv-1" {
					t.Errorf("recorded state = %+v; want the applied config", st)
				}
			},
		},
		{
			name: "stale generation is ignored, retained generation echoed",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				if _, err := h.ApplyEgress(EgressApply{InvocationID: "new", Generation: 5}); err != nil {
					t.Fatalf("ApplyEgress(gen 5): %v", err)
				}
				gen, err := h.ApplyEgress(EgressApply{InvocationID: "old", Generation: 4})
				if err != nil {
					t.Fatalf("ApplyEgress(gen 4): %v", err)
				}
				if gen != 5 {
					t.Errorf("applied generation = %d; want retained 5", gen)
				}
				if st, _ := ec.LookupEgressState(h.id); st.InvocationID != "new" {
					t.Errorf("InvocationID = %q; stale apply must not overwrite", st.InvocationID)
				}
			},
		},
		{
			name: "equal generation re-applies (idempotent re-push after recreate)",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				if _, err := h.ApplyEgress(EgressApply{InvocationID: "a", Generation: 7}); err != nil {
					t.Fatalf("ApplyEgress: %v", err)
				}
				if _, err := h.ApplyEgress(EgressApply{InvocationID: "b", Generation: 7}); err != nil {
					t.Fatalf("ApplyEgress(equal gen): %v", err)
				}
				if st, _ := ec.LookupEgressState(h.id); st.InvocationID != "b" {
					t.Errorf("InvocationID = %q; equal generation must re-apply", st.InvocationID)
				}
			},
		},
		{
			name: "nil policy records allow-all",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				if _, err := h.ApplyEgress(EgressApply{Policy: &sandbox.Policy{DefaultDeny: true}, Generation: 1}); err != nil {
					t.Fatalf("ApplyEgress: %v", err)
				}
				if _, err := h.ApplyEgress(EgressApply{Policy: nil, Generation: 2}); err != nil {
					t.Fatalf("ApplyEgress(nil policy): %v", err)
				}
				if st, _ := ec.LookupEgressState(h.id); st.Policy != nil {
					t.Errorf("Policy = %+v; want nil (allow-all)", st.Policy)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, ec := newRunningResident(t, &fakeCore{})
			tc.run(t, h, ec)
		})
	}

	t.Run("resident not running returns ErrNotFound", func(t *testing.T) {
		cfg := testResidentConfig()
		cfg.RootDir = t.TempDir()
		h := newResidentHostWithCore(newEgressCore(&fakeCore{}), cfg)
		if _, err := h.ApplyEgress(EgressApply{Generation: 1}); !errors.Is(err, sandbox.ErrNotFound) {
			t.Errorf("ApplyEgress = %v; want ErrNotFound", err)
		}
	})

	t.Run("core without egress support errors", func(t *testing.T) {
		h := newTestResidentHost(t, &fakeCore{})
		if _, err := h.EnsureResident(context.Background()); err != nil {
			t.Fatalf("EnsureResident: %v", err)
		}
		if _, err := h.ApplyEgress(EgressApply{Generation: 1}); err == nil {
			t.Error("ApplyEgress on a bare core: want error, got nil")
		}
	})

	t.Run("self-healed recreate resets the generation with the state", func(t *testing.T) {
		core := &fakeCore{}
		h, ec := newRunningResident(t, core)
		if _, err := h.ApplyEgress(EgressApply{InvocationID: "pre-crash", Generation: 5}); err != nil {
			t.Fatalf("ApplyEgress: %v", err)
		}

		// The workerd dies; the next EnsureResident purges (dropping the
		// recorded state) and recreates the sandbox with a fresh
		// zero-generation state — so a LOWER-generation push (e.g. a
		// restarted reconciler) must apply instead of being swallowed by a
		// generation the dead sandbox took with it.
		core.crash(h.id)
		if _, err := h.EnsureResident(context.Background()); err != nil {
			t.Fatalf("EnsureResident (self-heal): %v", err)
		}
		gen, err := h.ApplyEgress(EgressApply{InvocationID: "post-crash", Generation: 3})
		if err != nil {
			t.Fatalf("ApplyEgress after recreate: %v", err)
		}
		if gen != 3 {
			t.Errorf("applied generation after recreate = %d; want 3", gen)
		}
		if st, ok := ec.LookupEgressState(h.id); !ok || st.InvocationID != "post-crash" {
			t.Errorf("state after recreate = %+v (ok=%v); want the post-crash config", st, ok)
		}
	})

	t.Run("apply after stop returns ErrNotFound (state gone with the sandbox)", func(t *testing.T) {
		h, _ := newRunningResident(t, &fakeCore{})
		if _, err := h.ApplyEgress(EgressApply{Generation: 1}); err != nil {
			t.Fatalf("ApplyEgress: %v", err)
		}
		if err := h.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if _, err := h.ApplyEgress(EgressApply{Generation: 2}); !errors.Is(err, sandbox.ErrNotFound) {
			t.Errorf("ApplyEgress after Stop = %v; want ErrNotFound", err)
		}
	})
}
