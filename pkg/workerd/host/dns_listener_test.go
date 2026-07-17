// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"fmt"
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

func TestAnonymousAddr(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{"nil addr", nil, true},
		{"empty unix name", &net.UnixAddr{Name: "", Net: "unixgram"}, true},
		{"bare abstract marker", &net.UnixAddr{Name: "@", Net: "unixgram"}, true},
		{"bound abstract name", &net.UnixAddr{Name: "@apoxy-dnsc-1-2", Net: "unixgram"}, false},
		{"bound filesystem path", &net.UnixAddr{Name: "/tmp/x.sock", Net: "unixgram"}, false},
		{"non-unix addr", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := anonymousAddr(tc.addr); got != tc.want {
				t.Errorf("anonymousAddr(%v) = %v; want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestStartResidentDNS_ServesBoundQuery boots a resident DNS listener over a
// filesystem unixgram socket (the non-Linux path) and drives one AAAA query
// from a properly-bound client, asserting the authoritative VPC answer comes
// back. This exercises the synchronous server construction (a construction
// error would surface here, not in a detached goroutine) and confirms a named
// sender is served through namedSenderOnly.
func TestStartResidentDNS_ServesBoundQuery(t *testing.T) {
	tunnelAddr := netip.MustParseAddr("fd61:706f:7879:100:0:1::")
	source := func() vpcdns.Snapshot {
		return vpcdns.Snapshot{
			Zones: []string{"tun.apoxy.net"},
			Bindings: []vpcdns.Binding{{
				FQDN:  "my-tunnel.tun.apoxy.net",
				Addrs: []netip.Addr{tunnelAddr},
			}},
		}
	}

	d, err := startResidentDNS(sandbox.SandboxID("test-resident"), source)
	if err != nil {
		t.Fatalf("startResidentDNS: %v", err)
	}
	t.Cleanup(func() { _ = d.close() })

	raddr := &net.UnixAddr{Name: strings.TrimPrefix(d.target, "unix://"), Net: "unixgram"}
	// A bound local address so the reply has somewhere to go — the whole point
	// of the namedSenderOnly guard.
	laddr := &net.UnixAddr{Name: filepath.Join(os.TempDir(), fmt.Sprintf("apoxy-dnsc-%d.sock", os.Getpid())), Net: "unixgram"}
	_ = os.Remove(laddr.Name)
	client, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		t.Fatalf("dial resident DNS socket: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = os.Remove(laddr.Name) })

	req := new(dns.Msg)
	req.SetQuestion("my-tunnel.tun.apoxy.net.", dns.TypeAAAA)
	q, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	if _, err := client.Write(q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if !resp.Authoritative {
		t.Error("reply not authoritative")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d; want 1", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer type = %T; want AAAA", resp.Answer[0])
	}
	if got := netip.MustParseAddr(aaaa.AAAA.String()); got != tunnelAddr {
		t.Errorf("answer = %s; want %s", got, tunnelAddr)
	}
}
