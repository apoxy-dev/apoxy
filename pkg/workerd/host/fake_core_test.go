// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// fakeCore is an in-memory sandbox.Runtime that records lifecycle calls.
//
// It models the real manager's timing: Create returns a Ready instance with no
// inbound socket, then Start mutates that same instance to Running and exposes
// the socket.
type fakeCore struct {
	mu             sync.Mutex
	events         []string
	created        []sandbox.Spec
	createErr      error
	startErr       error
	instances      map[sandbox.SandboxID]*sandbox.Instance
	pendingInbound map[sandbox.SandboxID]string
}

func (f *fakeCore) Create(_ context.Context, spec sandbox.Spec) (*sandbox.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.events = append(f.events, "create:"+string(spec.ID))
	f.created = append(f.created, spec)
	if f.instances == nil {
		f.instances = make(map[sandbox.SandboxID]*sandbox.Instance)
		f.pendingInbound = make(map[sandbox.SandboxID]string)
	}
	inst := &sandbox.Instance{
		ID:        spec.ID,
		Phase:     sandbox.SandboxReady,
		SandboxIP: netip.AddrFrom4([4]byte{10, 88, byte(len(f.created)), 2}),
	}
	f.instances[spec.ID] = inst
	if spec.InboundListenAddr != "" {
		f.pendingInbound[spec.ID] = "/fake/" + strings.ReplaceAll(string(spec.ID), "/", "_") + ".in.sock"
	}
	return inst, nil
}

func (f *fakeCore) Start(_ context.Context, id sandbox.SandboxID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.events = append(f.events, "start:"+string(id))
	if inst, ok := f.instances[id]; ok {
		inst.Phase = sandbox.SandboxRunning
		inst.InboundSocket = f.pendingInbound[id]
	}
	return nil
}

func (f *fakeCore) Stop(_ context.Context, id sandbox.SandboxID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "stop:"+string(id))
	if inst, ok := f.instances[id]; ok {
		inst.Phase = sandbox.SandboxStopped
	}
	return nil
}

func (f *fakeCore) Kill(context.Context, sandbox.SandboxID) error {
	return nil
}

func (f *fakeCore) Wait(context.Context, sandbox.SandboxID) (int, error) {
	return 0, nil
}

func (f *fakeCore) Delete(context.Context, sandbox.SandboxID) error {
	return nil
}

func (f *fakeCore) Purge(_ context.Context, id sandbox.SandboxID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "purge:"+string(id))
	delete(f.instances, id)
	delete(f.pendingInbound, id)
}

func (f *fakeCore) Status(_ context.Context, id sandbox.SandboxID) (*sandbox.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[id]
	if !ok {
		return nil, sandbox.ErrNotFound
	}
	return inst, nil
}

func (f *fakeCore) crash(id sandbox.SandboxID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if inst, ok := f.instances[id]; ok {
		inst.Phase = sandbox.SandboxStopped
	}
}

func (f *fakeCore) List() []*sandbox.Instance {
	return nil
}

func (f *fakeCore) Cleanup(context.Context) error {
	return nil
}

func (f *fakeCore) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
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
	for _, option := range opts {
		if option == want {
			return true
		}
	}
	return false
}
