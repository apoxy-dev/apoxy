// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	workerdv1 "github.com/apoxy-dev/apoxy/api/workerd/v1"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// fakeApplier records ApplyEgress calls and returns a scripted result.
type fakeApplier struct {
	mu      sync.Mutex
	applies []host.EgressApply
	err     error
}

func (f *fakeApplier) ApplyEgress(apply host.EgressApply) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.applies = append(f.applies, apply)
	return apply.Generation, nil
}

func (f *fakeApplier) applied() []host.EgressApply {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]host.EgressApply(nil), f.applies...)
}

// shortSockDir returns a short-lived temp dir with a SHORT path: t.TempDir()
// embeds the full test name and overflows sun_path (104 bytes on darwin) for
// a unix socket bind.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "eg")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startEgressServer runs an EgressControlServer for tenant over a temp-dir
// unix socket and returns a connected client.
func startEgressServer(t *testing.T, tenant string, applier host.EgressApplier) workerdv1.EgressConfigClient {
	t.Helper()
	srv := NewEgressControlServer(tenant, applier)
	path := EgressSocketPath(shortSockDir(t), tenant)
	if err := srv.Listen(path); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("egress server did not shut down")
		}
	})

	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dialing egress socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return workerdv1.NewEgressConfigClient(conn)
}

func TestEgressControlServer_ApplyEgress(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	residentID := string(names.ResidentID(tenant))

	cases := []struct {
		name       string
		applierErr error
		req        *workerdv1.ApplyEgressRequest
		wantCode   codes.Code
		wantGen    uint64
		wantApply  *host.EgressApply
	}{
		{
			name: "apply fans out and echoes the generation",
			req: &workerdv1.ApplyEgressRequest{
				SandboxId: residentID,
				Backends: []*workerdv1.BackendListener{
					{Name: "eg", Addr: "127.0.0.1:8093", Shape: "tcp", MatchPort: 443, Priority: 2},
				},
				Policy:       &workerdv1.EgressPolicy{DefaultDeny: true},
				InvocationId: "inv-1",
				Generation:   7,
			},
			wantGen: 7,
			wantApply: &host.EgressApply{
				Backends:     []sandbox.BackendListener{{Name: "eg", Addr: "127.0.0.1:8093", Shape: "tcp", MatchPort: 443, Priority: 2}},
				Policy:       &sandbox.Policy{DefaultDeny: true},
				InvocationID: "inv-1",
				Generation:   7,
			},
		},
		{
			name: "absent policy maps to nil (allow-all)",
			req: &workerdv1.ApplyEgressRequest{
				SandboxId:  residentID,
				Generation: 1,
			},
			wantGen:   1,
			wantApply: &host.EgressApply{Generation: 1},
		},
		{
			name: "foreign sandbox id is rejected",
			req: &workerdv1.ApplyEgressRequest{
				SandboxId:  string(names.ResidentID("99999999-8888-7777-6666-555555555555")),
				Generation: 1,
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name:       "resident not running maps to Unavailable",
			applierErr: fmt.Errorf("workerd-host: resident is not running: %w", sandbox.ErrNotFound),
			req:        &workerdv1.ApplyEgressRequest{SandboxId: residentID, Generation: 1},
			wantCode:   codes.Unavailable,
		},
		{
			name:       "setter failure maps to Internal",
			applierErr: errors.New("boom"),
			req:        &workerdv1.ApplyEgressRequest{SandboxId: residentID, Generation: 1},
			wantCode:   codes.Internal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applier := &fakeApplier{err: tc.applierErr}
			client := startEgressServer(t, tenant, applier)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := client.ApplyEgress(ctx, tc.req)

			if tc.wantCode != codes.OK {
				if status.Code(err) != tc.wantCode {
					t.Fatalf("ApplyEgress code = %v (err %v); want %v", status.Code(err), err, tc.wantCode)
				}
				if len(applier.applied()) != 0 && tc.wantCode == codes.PermissionDenied {
					t.Error("rejected request must not reach the applier")
				}
				return
			}
			if err != nil {
				t.Fatalf("ApplyEgress: %v", err)
			}
			if resp.AppliedGeneration != tc.wantGen {
				t.Errorf("AppliedGeneration = %d; want %d", resp.AppliedGeneration, tc.wantGen)
			}
			applies := applier.applied()
			if len(applies) != 1 {
				t.Fatalf("applier saw %d applies; want 1", len(applies))
			}
			got := applies[0]
			if got.InvocationID != tc.wantApply.InvocationID || got.Generation != tc.wantApply.Generation {
				t.Errorf("apply = %+v; want %+v", got, *tc.wantApply)
			}
			if (got.Policy == nil) != (tc.wantApply.Policy == nil) ||
				(got.Policy != nil && got.Policy.DefaultDeny != tc.wantApply.Policy.DefaultDeny) {
				t.Errorf("apply policy = %+v; want %+v", got.Policy, tc.wantApply.Policy)
			}
			if len(got.Backends) != len(tc.wantApply.Backends) {
				t.Fatalf("apply backends = %+v; want %+v", got.Backends, tc.wantApply.Backends)
			}
			for i, b := range got.Backends {
				if b != tc.wantApply.Backends[i] {
					t.Errorf("backend[%d] = %+v; want %+v", i, b, tc.wantApply.Backends[i])
				}
			}
		})
	}
}

func TestEgressControlServer_ListenReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortSockDir(t), "egress.sock")

	// A leftover socket file from a dead incarnation must not block the bind.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("binding stale socket: %v", err)
	}
	stale.Close() // Close removes Go-created socket files; recreate the file.
	if ln, err := net.Listen("unix", path); err != nil {
		t.Fatalf("re-binding stale socket: %v", err)
	} else {
		// Leak the file (not the listener) the way a SIGKILLed process would:
		// close the fd without the *net.UnixListener unlink.
		f, _ := ln.(*net.UnixListener).File()
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		ln.Close()
		if f != nil {
			f.Close()
		}
	}

	srv := NewEgressControlServer("", &fakeApplier{})
	if err := srv.Listen(path); err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// A re-run teardown may Close the same server twice; the second call must be
// a strict no-op — in particular it must never touch the deterministic socket
// path again, which by then may belong to a rebuilt successor server.
func TestEgressControlServer_CloseIsIdempotent(t *testing.T) {
	dir := shortSockDir(t)
	path := filepath.Join(dir, "egress.sock")

	old := NewEgressControlServer("", &fakeApplier{})
	if err := old.Listen(path); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// A successor binds the same path (the rebuilt tenant).
	successor := NewEgressControlServer("", &fakeApplier{})
	if err := successor.Listen(path); err != nil {
		t.Fatalf("successor Listen: %v", err)
	}
	defer successor.Close()

	// The stale duplicate teardown re-runs Close on the old server.
	if err := old.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("successor's live socket was disturbed by the stale Close: %v", err)
	}
}
