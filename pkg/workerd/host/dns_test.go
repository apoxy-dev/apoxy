// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/apoxy-dev/apoxy/pkg/net/dns/vpcdns"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

func testBindings(t *testing.T) []vpcdns.Binding {
	t.Helper()
	addr, err := netip.ParseAddr("fd61:706f:7879:100:0:1::")
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := netip.ParsePrefix("fd61:706f:7879:100:0:1::/96")
	if err != nil {
		t.Fatal(err)
	}
	return []vpcdns.Binding{{
		FQDN:      "my-tunnel.tun.apoxy.net",
		Addrs:     []netip.Addr{addr},
		Delegate:  true,
		Reachable: []netip.Prefix{prefix.Masked()},
	}}
}

func TestResidentHost_ApplyDNS(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, h *ResidentHost, ec *egressCore)
	}{
		{
			name: "apply lands in the recorded state and echoes the generation",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				gen, err := h.ApplyDNS(DNSApply{
					Zones:      []string{"tun.apoxy.net"},
					Bindings:   testBindings(t),
					Generation: 3,
				})
				if err != nil {
					t.Fatalf("ApplyDNS: %v", err)
				}
				if gen != 3 {
					t.Errorf("applied generation = %d; want 3", gen)
				}
				st, ok := ec.LookupEgressState(h.id)
				if !ok {
					t.Fatal("no state recorded")
				}
				if len(st.DNSBindings) != 1 || st.DNSBindings[0].FQDN != "my-tunnel.tun.apoxy.net" ||
					len(st.DNSZones) != 1 || st.DNSZones[0] != "tun.apoxy.net" {
					t.Errorf("recorded name plane = zones %v bindings %+v; want the applied config",
						st.DNSZones, st.DNSBindings)
				}
			},
		},
		{
			name: "stale generation is ignored, retained generation echoed",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				if _, err := h.ApplyDNS(DNSApply{Zones: []string{"new"}, Generation: 5}); err != nil {
					t.Fatalf("ApplyDNS(gen 5): %v", err)
				}
				gen, err := h.ApplyDNS(DNSApply{Zones: []string{"old"}, Generation: 4})
				if err != nil {
					t.Fatalf("ApplyDNS(gen 4): %v", err)
				}
				if gen != 5 {
					t.Errorf("applied generation = %d; want retained 5", gen)
				}
				if st, _ := ec.LookupEgressState(h.id); len(st.DNSZones) != 1 || st.DNSZones[0] != "new" {
					t.Errorf("zones = %v; stale apply must not overwrite", st.DNSZones)
				}
			},
		},
		{
			name: "DNS and egress generations are independent",
			run: func(t *testing.T, h *ResidentHost, ec *egressCore) {
				if _, err := h.ApplyEgress(EgressApply{InvocationID: "inv", Generation: 9}); err != nil {
					t.Fatalf("ApplyEgress: %v", err)
				}
				gen, err := h.ApplyDNS(DNSApply{Zones: []string{"z"}, Generation: 1})
				if err != nil {
					t.Fatalf("ApplyDNS: %v", err)
				}
				if gen != 1 {
					t.Errorf("DNS generation = %d; want 1 (not gated by egress generation 9)", gen)
				}
				st, _ := ec.LookupEgressState(h.id)
				if st.Generation != 9 || st.DNSGeneration != 1 {
					t.Errorf("generations = egress %d dns %d; want 9 and 1", st.Generation, st.DNSGeneration)
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
		if _, err := h.ApplyDNS(DNSApply{Generation: 1}); !errors.Is(err, sandbox.ErrNotFound) {
			t.Errorf("ApplyDNS = %v; want ErrNotFound", err)
		}
	})

	t.Run("self-healed recreate carries bindings at generation zero", func(t *testing.T) {
		core := &fakeCore{}
		h, ec := newRunningResident(t, core)
		if _, err := h.ApplyDNS(DNSApply{
			Zones:      []string{"tun.apoxy.net"},
			Bindings:   testBindings(t),
			Generation: 5,
		}); err != nil {
			t.Fatalf("ApplyDNS: %v", err)
		}

		core.crash(h.id)
		if _, err := h.EnsureResident(context.Background()); err != nil {
			t.Fatalf("EnsureResident after crash: %v", err)
		}

		st, ok := ec.LookupEgressState(h.id)
		if !ok {
			t.Fatal("no state after recreation")
		}
		if len(st.DNSBindings) != 1 || st.DNSBindings[0].FQDN != "my-tunnel.tun.apoxy.net" {
			t.Errorf("bindings after recreation = %+v; want carried", st.DNSBindings)
		}
		if st.DNSGeneration != 0 {
			t.Errorf("DNS generation after recreation = %d; want reset to 0", st.DNSGeneration)
		}
		// A lower-generation push from a restarted pusher must land.
		if _, err := h.ApplyDNS(DNSApply{Zones: []string{"z2"}, Generation: 2}); err != nil {
			t.Fatalf("ApplyDNS after recreation: %v", err)
		}
		if st, _ := ec.LookupEgressState(h.id); len(st.DNSZones) != 1 || st.DNSZones[0] != "z2" {
			t.Errorf("zones = %v; lower-generation push after recreation must apply", st.DNSZones)
		}
	})
}

// queryResidentDNS sends one DNS query to the resident's unixgram listener,
// binding an explicit client socket so replies route back (the production
// Sentry dial binds a unique abstract name for the same reason — Linux does
// not autobind unix dgram sockets on connect).
func queryResidentDNS(t *testing.T, target string, req *dns.Msg) *dns.Msg {
	t.Helper()
	sock := strings.TrimPrefix(target, "unix://")
	// A short path, not t.TempDir(): the subtest-derived dir plus socket name
	// exceeds the 104-byte darwin sun_path limit.
	dir, err := os.MkdirTemp("", "dns")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	clientPath := filepath.Join(dir, "c.sock")
	conn, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: clientPath, Net: "unixgram"},
		&net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatalf("dialing resident DNS socket: %v", err)
	}
	defer conn.Close()

	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("packing query: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("sending query: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpacking response: %v", err)
	}
	return resp
}

func TestResidentDNSListener_ServesPushedBindings(t *testing.T) {
	h, _ := newRunningResident(t, &fakeCore{})
	if h.dns == nil {
		t.Fatal("resident came up without a DNS listener")
	}
	if !strings.HasPrefix(h.dns.target, "unix://") {
		t.Fatalf("DNS target = %q; want a unix:// socket", h.dns.target)
	}

	if _, err := h.ApplyDNS(DNSApply{
		Zones:      []string{"tun.apoxy.net"},
		Bindings:   testBindings(t),
		Generation: 1,
	}); err != nil {
		t.Fatalf("ApplyDNS: %v", err)
	}

	t.Run("authoritative answer for a pushed binding", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("my-tunnel.tun.apoxy.net.", dns.TypeAAAA)
		resp := queryResidentDNS(t, h.dns.target, req)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("response = %+v; want one answer", resp)
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("answer = %T; want AAAA", resp.Answer[0])
		}
		if want := "fd61:706f:7879:100:0:1::"; aaaa.AAAA.String() != want {
			t.Errorf("AAAA = %s; want %s", aaaa.AAAA, want)
		}
	})

	t.Run("in-zone miss is NXDOMAIN", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("missing.tun.apoxy.net.", dns.TypeAAAA)
		resp := queryResidentDNS(t, h.dns.target, req)
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("rcode = %d; want NXDOMAIN", resp.Rcode)
		}
	})

	t.Run("anonymous sender is dropped, not a crash", func(t *testing.T) {
		// An UNBOUND unixgram client is anonymous: it can never receive a
		// reply, and an unguarded server panics on its nil remote address
		// deep in miekg/dns. The listener must drop the datagram and keep
		// serving bound clients.
		sock := strings.TrimPrefix(h.dns.target, "unix://")
		anon, err := net.DialUnix("unixgram", nil,
			&net.UnixAddr{Name: sock, Net: "unixgram"})
		if err != nil {
			t.Fatalf("dialing resident DNS socket unbound: %v", err)
		}
		defer anon.Close()
		req := new(dns.Msg)
		req.SetQuestion("my-tunnel.tun.apoxy.net.", dns.TypeAAAA)
		payload, err := req.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := anon.Write(payload); err != nil {
			t.Fatalf("sending anonymous query: %v", err)
		}

		// The listener survives and still answers a properly bound client.
		resp := queryResidentDNS(t, h.dns.target, req)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("post-anonymous response = %+v; want one answer", resp)
		}
	})

	t.Run("listener dies with the resident", func(t *testing.T) {
		target := h.dns.target
		if err := h.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if h.dns != nil {
			t.Error("DNS listener survived Stop")
		}
		sock := strings.TrimPrefix(target, "unix://")
		clientPath := filepath.Join(t.TempDir(), "client.sock")
		conn, err := net.DialUnix("unixgram",
			&net.UnixAddr{Name: clientPath, Net: "unixgram"},
			&net.UnixAddr{Name: sock, Net: "unixgram"})
		if err == nil {
			conn.Close()
			t.Error("stopped resident's DNS socket still dialable")
		}
	})
}

func TestResidentBridge_OverlayCarveOutFollowsPushedBindings(t *testing.T) {
	h, _ := newRunningResident(t, &fakeCore{})
	if h.bridge == nil {
		t.Fatal("resident came up without an egress bridge")
	}
	own := netip.AddrPortFrom(netip.MustParseAddr("fd61:706f:7879:100:0:1::5"), 443)
	sibling := netip.AddrPortFrom(netip.MustParseAddr("fd61:706f:7879:100:0:2::5"), 443)

	// Before any push: everything private/ULA denied.
	if got := h.bridge.filter.deny(own); got == "" {
		t.Error("own /96 admitted before any binding was pushed")
	}

	if _, err := h.ApplyDNS(DNSApply{
		Zones:      []string{"tun.apoxy.net"},
		Bindings:   testBindings(t),
		Generation: 1,
	}); err != nil {
		t.Fatalf("ApplyDNS: %v", err)
	}

	if got := h.bridge.filter.deny(own); got != "" {
		t.Errorf("own /96 denied (%q) after its binding was pushed", got)
	}
	if got := h.bridge.filter.deny(sibling); got == "" {
		t.Error("sibling /96 in the same /72 admitted; cross-tenant hole")
	}

	// Level-triggered retraction: an empty push withdraws the carve-out.
	if _, err := h.ApplyDNS(DNSApply{Zones: []string{"tun.apoxy.net"}, Generation: 2}); err != nil {
		t.Fatalf("ApplyDNS(empty): %v", err)
	}
	if got := h.bridge.filter.deny(own); got == "" {
		t.Error("carve-out survived binding deletion")
	}
}
