// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
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

// fakeDNSApplier records ApplyDNS calls and returns a scripted result.
type fakeDNSApplier struct {
	mu      sync.Mutex
	applies []host.DNSApply
	err     error
}

func (f *fakeDNSApplier) ApplyDNS(apply host.DNSApply) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.applies = append(f.applies, apply)
	return apply.Generation, nil
}

func (f *fakeDNSApplier) applied() []host.DNSApply {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]host.DNSApply(nil), f.applies...)
}

// startDNSServer runs an EgressControlServer (which carries the DNSConfig
// service) for tenant over a temp-dir unix socket and returns a connected
// DNSConfig client.
func startDNSServer(t *testing.T, tenant string, dnsApplier host.DNSApplier) workerdv1.DNSConfigClient {
	t.Helper()
	srv := NewEgressControlServer(tenant, &fakeApplier{}, dnsApplier)
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
	return workerdv1.NewDNSConfigClient(conn)
}

func TestEgressControlServer_ApplyDNS(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	residentID := string(names.ResidentID(tenant))

	validReq := func() *workerdv1.ApplyDNSRequest {
		return &workerdv1.ApplyDNSRequest{
			SandboxId:          residentID,
			Generation:         7,
			AuthoritativeZones: []string{"tun.apoxy.net"},
			Bindings: []*workerdv1.Binding{{
				Fqdn:               "my-tunnel.tun.apoxy.net",
				Addrs:              []string{"fd61:706f:7879:100:0:1::"},
				DelegateSubdomains: true,
				Ttl:                30,
				// Unmasked on purpose: the server must normalize (Masked).
				ReachableCidrs: []string{"fd61:706f:7879:100:0:1::5/96"},
			}},
		}
	}

	cases := []struct {
		name       string
		applier    *fakeDNSApplier
		mutate     func(*workerdv1.ApplyDNSRequest)
		wantCode   codes.Code
		wantApply  bool
		checkApply func(t *testing.T, apply host.DNSApply)
	}{
		{
			name:      "valid push maps to the host apply shape",
			applier:   &fakeDNSApplier{},
			wantCode:  codes.OK,
			wantApply: true,
			checkApply: func(t *testing.T, apply host.DNSApply) {
				if apply.Generation != 7 || len(apply.Zones) != 1 || apply.Zones[0] != "tun.apoxy.net" {
					t.Errorf("apply = %+v; want generation 7, zone tun.apoxy.net", apply)
				}
				if len(apply.Bindings) != 1 {
					t.Fatalf("bindings = %d; want 1", len(apply.Bindings))
				}
				b := apply.Bindings[0]
				if b.FQDN != "my-tunnel.tun.apoxy.net" || !b.Delegate || b.TTL != 30 ||
					len(b.Addrs) != 1 || b.Addrs[0].String() != "fd61:706f:7879:100:0:1::" {
					t.Errorf("binding = %+v; want the pushed binding", b)
				}
				if len(b.Reachable) != 1 || b.Reachable[0].String() != "fd61:706f:7879:100:0:1::/96" {
					t.Errorf("reachable = %v; want the MASKED /96", b.Reachable)
				}
			},
		},
		{
			name:    "foreign sandbox id is rejected",
			applier: &fakeDNSApplier{},
			mutate: func(r *workerdv1.ApplyDNSRequest) {
				r.SandboxId = string(names.ResidentID("99999999-8888-7777-6666-555555555555"))
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name:    "malformed addr rejects the whole request",
			applier: &fakeDNSApplier{},
			mutate: func(r *workerdv1.ApplyDNSRequest) {
				r.Bindings[0].Addrs = []string{"not-an-ip"}
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name:    "malformed reachable cidr rejects the whole request",
			applier: &fakeDNSApplier{},
			mutate: func(r *workerdv1.ApplyDNSRequest) {
				r.Bindings[0].ReachableCidrs = []string{"fd61::/999"}
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "resident not running maps to Unavailable",
			applier:  &fakeDNSApplier{err: fmt.Errorf("gone: %w", sandbox.ErrNotFound)},
			wantCode: codes.Unavailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := startDNSServer(t, tenant, tc.applier)
			req := validReq()
			if tc.mutate != nil {
				tc.mutate(req)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := client.ApplyDNS(ctx, req)
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("ApplyDNS code = %v (err %v); want %v", got, err, tc.wantCode)
			}
			applies := tc.applier.applied()
			if tc.wantApply != (len(applies) == 1) {
				t.Fatalf("applies = %d; want applied=%v", len(applies), tc.wantApply)
			}
			if tc.wantApply {
				if resp.AppliedGeneration != req.Generation {
					t.Errorf("applied generation = %d; want %d", resp.AppliedGeneration, req.Generation)
				}
				if tc.checkApply != nil {
					tc.checkApply(t, applies[0])
				}
			}
		})
	}

	t.Run("nil DNS applier is Unimplemented", func(t *testing.T) {
		client := startDNSServer(t, tenant, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := client.ApplyDNS(ctx, validReq())
		if got := status.Code(err); got != codes.Unimplemented {
			t.Errorf("ApplyDNS code = %v; want Unimplemented", got)
		}
	})
}
