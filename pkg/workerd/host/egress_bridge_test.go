// SPDX-License-Identifier: AGPL-3.0-only

// Portable (no build tag): the bridge and merge logic are pure net/io, so this
// runs on the developer's macOS host and in CI without a sandbox.
package host

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egresswire"
)

func TestMergeResidentEgress(t *testing.T) {
	bkA := sandbox.BackendListener{Name: "a", Addr: "10.0.0.1:9000"}
	bkB := sandbox.BackendListener{Name: "b", Addr: "10.0.0.2:9000", MatchPort: 443}
	denyWithRule := &sandbox.Policy{DefaultDeny: true, Rules: []sandbox.Rule{{DestinationCIDRs: []string{"1.2.3.0/24"}}}}
	denyOtherRule := &sandbox.Policy{DefaultDeny: true, Rules: []sandbox.Rule{{DestinationCIDRs: []string{"5.6.7.0/24"}}}}

	cases := []struct {
		name         string
		st           EgressState
		wantAllowAll bool // true => merged policy is nil (allow-all)
		wantRules    int  // when not allow-all, number of merged rules
		wantBackends int
	}{
		{name: "empty state -> deny-all", st: EgressState{}, wantAllowAll: false, wantRules: 0, wantBackends: 0},
		{
			// Allow-all suppresses backends: the resident is allow-direct, and a
			// backend would force the (unimplemented) gateway path for the whole
			// resident since the bridge can't attribute a flow to a Service.
			name:         "single nil policy -> allow-all, backends suppressed",
			st:           EgressState{Services: []sandbox.ServiceEgress{{Service: "s1", Policy: nil, Backends: []sandbox.BackendListener{bkA}}}},
			wantAllowAll: true, wantBackends: 0,
		},
		{
			// Regression guard: an allow-all Service must not have its direct
			// egress broken by a sibling gateway-routed Service's backend. The
			// merge is allow-all, so backends are suppressed and every flow goes
			// direct (the documented same-project relaxation), rather than the
			// sibling's backend forcing the fail-closing gateway path.
			name: "allow-all sibling suppresses a gateway service's backend",
			st: EgressState{Services: []sandbox.ServiceEgress{
				{Service: "direct", Policy: nil},
				{Service: "gw", Policy: denyWithRule, Backends: []sandbox.BackendListener{bkB}},
			}},
			wantAllowAll: true, wantBackends: 0,
		},
		{
			name:         "single deny-default with rule",
			st:           EgressState{Services: []sandbox.ServiceEgress{{Service: "s1", Policy: denyWithRule}}},
			wantAllowAll: false, wantRules: 1,
		},
		{
			name: "union of two deny-default services",
			st: EgressState{Services: []sandbox.ServiceEgress{
				{Service: "s1", Policy: denyWithRule, Backends: []sandbox.BackendListener{bkA}},
				{Service: "s2", Policy: denyOtherRule, Backends: []sandbox.BackendListener{bkB}},
			}},
			wantAllowAll: false, wantRules: 2, wantBackends: 2,
		},
		{
			name: "any nil policy makes the merge allow-all",
			st: EgressState{Services: []sandbox.ServiceEgress{
				{Service: "s1", Policy: denyWithRule},
				{Service: "s2", Policy: nil},
			}},
			wantAllowAll: true,
		},
		{
			name: "non-deny default also makes the merge allow-all",
			st: EgressState{Services: []sandbox.ServiceEgress{
				{Service: "s1", Policy: &sandbox.Policy{DefaultDeny: false}},
			}},
			wantAllowAll: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol, bk := mergeResidentEgress(tc.st)
			if tc.wantAllowAll {
				if pol != nil {
					t.Fatalf("merged policy = %+v, want nil (allow-all)", pol)
				}
			} else {
				if pol == nil {
					t.Fatal("merged policy = nil (allow-all), want deny-default")
				}
				if !pol.DefaultDeny {
					t.Errorf("merged policy DefaultDeny = false, want true")
				}
				if len(pol.Rules) != tc.wantRules {
					t.Errorf("merged rules = %d, want %d", len(pol.Rules), tc.wantRules)
				}
			}
			if len(bk) != tc.wantBackends {
				t.Errorf("merged backends = %d, want %d", len(bk), tc.wantBackends)
			}
		})
	}
}

// startEcho stands up a loopback TCP echo server the fake dialer connects to.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// newTestBridge builds a bridge with an injected upstream dialer and starts it.
// overlayAllow is the SSRF carve-out membership predicate (nil for none).
func newTestBridge(t *testing.T, lookup egressStateLookup, overlayAllow func(netip.Addr) bool, dial func(string, string) (net.Conn, error)) *egressBridge {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bridge listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &egressBridge{
		ln:     ln,
		id:     sandbox.SandboxID("test"),
		lookup: lookup,
		filter: newLocalDstFilter(overlayAllow),
		log:    slog.Default(),
		dial:   dial,
		ctx:    ctx,
		cancel: cancel,
	}
	go b.serve()
	t.Cleanup(func() { _ = b.close() })
	return b
}

func allowAllLookup(id sandbox.SandboxID) (EgressState, bool) {
	return EgressState{Services: []sandbox.ServiceEgress{{Service: "s", Policy: nil}}}, true
}

func TestEgressBridge(t *testing.T) {
	echoAddr := startEcho(t)
	// A non-local destination that passes the SSRF filter; the fake dialer
	// ignores it and connects to the echo server, so we can both assert the
	// dst the bridge tried to reach and exercise a real splice.
	const goodDst = "203.0.113.5:80"
	src := netip.MustParseAddrPort("10.200.0.6:40000")

	t.Run("allow direct splices through", func(t *testing.T) {
		dialCh := make(chan string, 1)
		b := newTestBridge(t, allowAllLookup, nil, func(network, addr string) (net.Conn, error) {
			dialCh <- addr
			return net.Dial("tcp", echoAddr)
		})

		c, err := net.Dial("tcp", b.addr())
		if err != nil {
			t.Fatalf("dial bridge: %v", err)
		}
		defer c.Close()
		if err := egresswire.WriteEgressPreamble(c, src, netip.MustParseAddrPort(goodDst), ""); err != nil {
			t.Fatalf("write preamble: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if allow, err := egresswire.ReadEgressVerdict(c); err != nil || !allow {
			t.Fatalf("verdict for an allowed flow = (%v, %v), want (true, nil)", allow, err)
		}
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatalf("write payload: %v", err)
		}

		select {
		case got := <-dialCh:
			if got != goodDst {
				t.Fatalf("bridge dialed %q, want %q", got, goodDst)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("bridge never dialed upstream for an allowed flow")
		}

		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("reading echoed payload: %v", err)
		}
		if string(buf) != "hello" {
			t.Fatalf("echoed payload = %q, want %q", buf, "hello")
		}
	})

	// denyCases assert the bridge closes the flow WITHOUT dialing upstream.
	denyCases := []struct {
		name   string
		lookup egressStateLookup
		dst    string
	}{
		{
			name:   "policy deny (deny-default, no matching rule)",
			lookup: func(id sandbox.SandboxID) (EgressState, bool) {
				return EgressState{Services: []sandbox.ServiceEgress{{Policy: &sandbox.Policy{DefaultDeny: true}}}}, true
			},
			dst: goodDst,
		},
		{
			name:   "no recorded state",
			lookup: func(id sandbox.SandboxID) (EgressState, bool) { return EgressState{}, false },
			dst:    goodDst,
		},
		// SSRF backstop: even under an allow-all policy, the bridge must refuse
		// worker-local, cluster-internal, and private destinations. Driven through
		// a real bridge connection so every IP family is exercised end-to-end.
		{name: "SSRF loopback v4", lookup: allowAllLookup, dst: "127.0.0.1:8080"},
		{name: "SSRF loopback v6", lookup: allowAllLookup, dst: "[::1]:8080"},
		{name: "SSRF unspecified v4", lookup: allowAllLookup, dst: "0.0.0.0:80"},
		{name: "SSRF RFC1918 10/8 (ClusterIP)", lookup: allowAllLookup, dst: "10.96.0.1:443"},
		{name: "SSRF RFC1918 172.16/12", lookup: allowAllLookup, dst: "172.16.5.4:80"},
		{name: "SSRF RFC1918 192.168/16", lookup: allowAllLookup, dst: "192.168.1.1:80"},
		{name: "SSRF CGNAT 100.64/10", lookup: allowAllLookup, dst: "100.64.0.1:80"},
		{name: "SSRF link-local v4 (IMDS)", lookup: allowAllLookup, dst: "169.254.169.254:80"},
		{name: "SSRF link-local v6", lookup: allowAllLookup, dst: "[fe80::1]:80"},
		{name: "SSRF IPv6 ULA fc00::/7", lookup: allowAllLookup, dst: "[fd00::1]:80"},
		{name: "SSRF multicast v4", lookup: allowAllLookup, dst: "224.0.0.1:80"},
		{name: "SSRF multicast v6", lookup: allowAllLookup, dst: "[ff02::1]:80"},
		{
			// A deny-default Service with a rule allowing the dst AND a gateway
			// backend: policy passes, PickBackend selects the backend, and the
			// bridge fail-closes because the gateway path isn't implemented. (Uses
			// deny-default, not nil, because allow-all now suppresses backends.)
			name: "gateway routing not implemented",
			lookup: func(id sandbox.SandboxID) (EgressState, bool) {
				return EgressState{Services: []sandbox.ServiceEgress{{
					Policy: &sandbox.Policy{DefaultDeny: true, Rules: []sandbox.Rule{
						{DestinationCIDRs: []string{"203.0.113.0/24"}},
					}},
					Backends: []sandbox.BackendListener{{Name: "eg", Addr: "10.9.9.9:443"}},
				}}}, true
			},
			dst: goodDst,
		},
	}
	for _, tc := range denyCases {
		t.Run("deny: "+tc.name, func(t *testing.T) {
			dialCh := make(chan string, 1)
			b := newTestBridge(t, tc.lookup, nil, func(network, addr string) (net.Conn, error) {
				dialCh <- addr
				return net.Dial("tcp", echoAddr)
			})

			c, err := net.Dial("tcp", b.addr())
			if err != nil {
				t.Fatalf("dial bridge: %v", err)
			}
			defer c.Close()
			if err := egresswire.WriteEgressPreamble(c, src, netip.MustParseAddrPort(tc.dst), ""); err != nil {
				t.Fatalf("write preamble: %v", err)
			}
			// A denied flow answers with a deny verdict and is closed without
			// proxying: the forwarder turns the verdict into an RST at SYN, the
			// fake dialer is never invoked, and nothing is ever echoed.
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			allow, err := egresswire.ReadEgressVerdict(c)
			if err != nil {
				t.Fatalf("reading deny verdict: %v", err)
			}
			if allow {
				t.Fatal("verdict for a denied flow = allow, want deny")
			}
			if _, err := io.ReadFull(c, make([]byte, 1)); err == nil {
				t.Fatal("read after deny verdict succeeded; the flow should have been closed, not proxied")
			}
			select {
			case got := <-dialCh:
				t.Fatalf("bridge dialed %q for a denied flow; want no dial", got)
			default:
			}
		})
	}
}

// TestLocalDstFilterDeny exhaustively covers the SSRF backstop classifier across
// all IP families: public destinations pass, everything worker-local /
// cluster-internal / private is denied with a categorical reason. This is the
// unit-level companion to the bridge-level SSRF deny cases in TestEgressBridge.
func TestLocalDstFilterDeny(t *testing.T) {
	// A filter whose own-interface set is empty, so the categorical rules (not
	// this host's specific IPs) are what's under test. The categorical checks
	// need no interface enumeration.
	f := &localDstFilter{localIPs: map[netip.Addr]struct{}{}}

	cases := []struct {
		name       string
		dst        string
		wantReason string // "" => allowed
	}{
		// Allowed: public, routable addresses.
		{name: "public v4", dst: "203.0.113.5:80", wantReason: ""},
		{name: "public v4 dns", dst: "1.1.1.1:80", wantReason: ""},
		{name: "public v6", dst: "[2606:4700::1111]:443", wantReason: ""},

		// Loopback / unspecified.
		{name: "loopback v4", dst: "127.0.0.1:80", wantReason: "loopback"},
		{name: "loopback v6", dst: "[::1]:80", wantReason: "loopback"},
		{name: "unspecified v4", dst: "0.0.0.0:80", wantReason: "unspecified"},
		{name: "unspecified v6", dst: "[::]:80", wantReason: "unspecified"},

		// Link-local (incl. the cloud IMDS 169.254.169.254 — a classic SSRF pivot).
		{name: "link-local v4 IMDS", dst: "169.254.169.254:80", wantReason: "link-local"},
		{name: "link-local v6", dst: "[fe80::1]:80", wantReason: "link-local"},

		// RFC1918 private + IPv6 ULA.
		{name: "rfc1918 10/8 ClusterIP", dst: "10.96.0.1:443", wantReason: "private"},
		{name: "rfc1918 172.16/12", dst: "172.16.0.1:80", wantReason: "private"},
		{name: "rfc1918 172.31 edge", dst: "172.31.255.255:80", wantReason: "private"},
		{name: "rfc1918 192.168/16", dst: "192.168.1.1:80", wantReason: "private"},
		{name: "ula fc00::/7 low", dst: "[fc00::1]:80", wantReason: "private"},
		{name: "ula fd00 sibling pod", dst: "[fd00::1]:80", wantReason: "private"},

		// RFC6598 carrier-grade NAT (some k8s pod/service CIDRs).
		{name: "cgnat 100.64/10 low", dst: "100.64.0.1:80", wantReason: "cgnat"},
		{name: "cgnat 100.127 high", dst: "100.127.255.255:80", wantReason: "cgnat"},

		// Multicast.
		{name: "multicast v4 link-local", dst: "224.0.0.1:80", wantReason: "link-local-multicast"},
		{name: "multicast v4 global", dst: "239.1.2.3:80", wantReason: "multicast"},
		{name: "multicast v6 iface-local", dst: "[ff01::1]:80", wantReason: "interface-local-multicast"},
		{name: "multicast v6 link-local", dst: "[ff02::1]:80", wantReason: "link-local-multicast"},
		{name: "multicast v6 global", dst: "[ff0e::1]:80", wantReason: "multicast"},

		// Just-outside-CGNAT sanity: 100.63/... and 100.128/... are public.
		{name: "just below cgnat is public", dst: "100.63.255.255:80", wantReason: ""},
		{name: "just above cgnat is public", dst: "100.128.0.0:80", wantReason: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := f.deny(netip.MustParseAddrPort(tc.dst))
			if got != tc.wantReason {
				t.Errorf("deny(%s) = %q, want %q", tc.dst, got, tc.wantReason)
			}
		})
	}
}

// TestLocalDstFilterDeniesOwnInterface asserts the own-interface set is enforced
// (a public-looking IP that is actually one of this host's own addresses is
// denied), independent of the categorical rules.
func TestLocalDstFilterDeniesOwnInterface(t *testing.T) {
	own := netip.MustParseAddr("198.51.100.7") // TEST-NET-2: not private/link-local
	f := &localDstFilter{localIPs: map[netip.Addr]struct{}{own: {}}}
	if got := f.deny(netip.AddrPortFrom(own, 443)); got != "worker-local-interface" {
		t.Errorf("deny(own iface %s) = %q, want %q", own, got, "worker-local-interface")
	}
	// A different public IP is still allowed.
	if got := f.deny(netip.MustParseAddrPort("198.51.100.8:443")); got != "" {
		t.Errorf("deny(other public) = %q, want allow", got)
	}
}

// overlayAllowPrefixes returns a membership predicate admitting dst addresses
// within any of the given /96 endpoint prefixes — the test stand-in for the
// manager's project-filtered endpoint index (backplane/infra's
// EndpointDNSReconciler.IsProjectOverlayAddr).
func overlayAllowPrefixes(t *testing.T, cidrs ...string) func(netip.Addr) bool {
	t.Helper()
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		prefixes[i] = netip.MustParsePrefix(c)
	}
	return func(a netip.Addr) bool {
		a = a.Unmap()
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
}

// TestLocalDstFilterOverlayCarveOut asserts the SSRF carve-out admits only the
// resident's OWN project overlay endpoint /96s while every other private range
// stays denied. The load-bearing case is a DIFFERENT endpoint /96 in the SAME
// shared "default" network /72: because the carve-out is per-/96 membership (not
// a /72 prefix), that sibling — potentially another tenant's endpoint — is
// denied. That is what keeps a worker off other tenants' overlays.
func TestLocalDstFilterOverlayCarveOut(t *testing.T) {
	// This project owns exactly one endpoint /96 within the shared /72.
	f := newLocalDstFilter(overlayAllowPrefixes(t, "fd61:706f:7879:100:0:1::/96"))

	cases := []struct {
		name       string
		dst        string
		wantReason string // "" => allowed
	}{
		{name: "own overlay endpoint", dst: "[fd61:706f:7879:100:0:1::5]:443", wantReason: ""},
		{name: "own overlay deep host bits", dst: "[fd61:706f:7879:100:0:1:abcd:1234]:80", wantReason: ""},
		{name: "sibling /96 in same /72 denied", dst: "[fd61:706f:7879:100:0:2::5]:443", wantReason: "private"},
		{name: "other project /72 denied", dst: "[fd61:706f:7879:200:0:1::5]:443", wantReason: "private"},
		{name: "generic ULA still denied", dst: "[fd00::1]:80", wantReason: "private"},
		{name: "rfc1918 still denied", dst: "10.96.0.1:443", wantReason: "private"},
		{name: "imds still denied", dst: "169.254.169.254:80", wantReason: "link-local"},
		{name: "cgnat still denied", dst: "100.64.0.1:80", wantReason: "cgnat"},
		{name: "public still allowed", dst: "1.1.1.1:80", wantReason: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.deny(netip.MustParseAddrPort(tc.dst)); got != tc.wantReason {
				t.Errorf("deny(%s) = %q, want %q", tc.dst, got, tc.wantReason)
			}
		})
	}

	// A nil predicate = no carve-out: the same endpoint address is denied.
	noCarve := newLocalDstFilter(nil)
	if got := noCarve.deny(netip.MustParseAddrPort("[fd61:706f:7879:100:0:1::5]:443")); got != "private" {
		t.Errorf("no-overlay deny(overlay addr) = %q, want %q", got, "private")
	}
}

// TestEgressBridge_HostnamePolicy drives the full bridge to assert a
// hostname-based allow rule matches only when the preamble carries the resolved
// hostname (dstName) — the attribution the DNS forwarder binds. A matching name
// is proxied; an empty or non-matching name fail-closes.
func TestEgressBridge_HostnamePolicy(t *testing.T) {
	echoAddr := startEcho(t)
	const dst = "203.0.113.5:443" // public, passes the SSRF filter
	src := netip.MustParseAddrPort("10.200.0.6:40000")
	// Deny-default policy allowing only the hostname api.example.com.
	lookup := func(id sandbox.SandboxID) (EgressState, bool) {
		return EgressState{Services: []sandbox.ServiceEgress{{
			Policy: &sandbox.Policy{DefaultDeny: true, Rules: []sandbox.Rule{
				{DestinationHostnames: []string{"api.example.com"}},
			}},
		}}}, true
	}

	cases := []struct {
		name      string
		dstName   string
		wantDial  bool
	}{
		{name: "matching hostname allowed", dstName: "api.example.com", wantDial: true},
		{name: "empty dstName fail-closes", dstName: "", wantDial: false},
		{name: "non-matching hostname denied", dstName: "evil.example.com", wantDial: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialCh := make(chan string, 1)
			b := newTestBridge(t, lookup, nil, func(network, addr string) (net.Conn, error) {
				dialCh <- addr
				return net.Dial("tcp", echoAddr)
			})
			c, err := net.Dial("tcp", b.addr())
			if err != nil {
				t.Fatalf("dial bridge: %v", err)
			}
			defer c.Close()
			if err := egresswire.WriteEgressPreamble(c, src, netip.MustParseAddrPort(dst), tc.dstName); err != nil {
				t.Fatalf("write preamble: %v", err)
			}
			_, _ = c.Write([]byte("hi"))

			if tc.wantDial {
				select {
				case <-dialCh:
				case <-time.After(3 * time.Second):
					t.Fatal("bridge never dialed upstream for a hostname-allowed flow")
				}
				return
			}
			select {
			case got := <-dialCh:
				t.Fatalf("bridge dialed %q; want fail-closed for dstName=%q", got, tc.dstName)
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
}

// TestEgressBridge_OverlayAllowsOwnProject drives the full bridge to assert the
// overlay carve-out actually admits a flow to one of the resident's own project
// endpoint /96s (which the SSRF backstop would otherwise deny as ULA), while a
// sibling /96 in the SAME shared /72 stays denied.
func TestEgressBridge_OverlayAllowsOwnProject(t *testing.T) {
	echoAddr := startEcho(t)
	overlayAllow := overlayAllowPrefixes(t, "fd61:706f:7879:100:0:1::/96")
	src := netip.MustParseAddrPort("10.200.0.6:40000")

	cases := []struct {
		name     string
		dst      string
		wantDial bool
	}{
		{name: "own endpoint is reachable", dst: "[fd61:706f:7879:100:0:1::5]:8080", wantDial: true},
		{name: "sibling /96 in same /72 is denied", dst: "[fd61:706f:7879:100:0:2::5]:8080", wantDial: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialCh := make(chan string, 1)
			b := newTestBridge(t, allowAllLookup, overlayAllow, func(network, addr string) (net.Conn, error) {
				dialCh <- addr
				return net.Dial("tcp", echoAddr)
			})
			c, err := net.Dial("tcp", b.addr())
			if err != nil {
				t.Fatalf("dial bridge: %v", err)
			}
			defer c.Close()
			if err := egresswire.WriteEgressPreamble(c, src, netip.MustParseAddrPort(tc.dst), ""); err != nil {
				t.Fatalf("write preamble: %v", err)
			}
			_, _ = c.Write([]byte("hi"))

			if tc.wantDial {
				select {
				case <-dialCh:
				case <-time.After(3 * time.Second):
					t.Fatal("bridge never dialed upstream for an overlay-allowed flow")
				}
				return
			}
			select {
			case got := <-dialCh:
				t.Fatalf("bridge dialed %q for a sibling overlay; want denied", got)
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
}
