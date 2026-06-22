// Like inbound_demux_test.go, this test is intentionally NOT //go:build linux
// constrained: it uses only gVisor's portable pkg/tcpip netstack (no sentry, no
// runsc, no privileges), so it compiles and runs on the developer's macOS host
// as well as in CI.
//
// It is the APO-815 egress *plumbing* proof — the mirror of the APO-694 inbound
// proof. Egress mediation rests on one load-bearing assumption:
//
//	A worker's outbound fetch()/connect() to a NON-LOCAL destination is an
//	ordinary in-Sentry INET socket. The SYN routes out eth0 (default route),
//	the loopether link loops it straight back in (DeliverNetworkPacket),
//	promiscuous+spoofing accept it even though the dst isn't ours, it matches
//	no bound listening endpoint, and the catch-all egress tcp.NewForwarder
//	(installed via SetTransportProtocolHandler) STEALS it and bridges it to the
//	real upstream. The flow is serviced by the netstack — it never escapes
//	directly to the host. With NO forwarder installed the same SYN is RST in
//	the stack (fail-closed), never bridged.
//
// The topology here is the real one doInit/wireEth0 boot: lo + an eth0 NIC
// backed by the production loopether link + a 0.0.0.0/0 default route via eth0 +
// promiscuous/spoofing. That is what makes a non-local dst reach the forwarder
// at all — a lo-only stack drops a non-local dst at routing ("network
// unreachable") and never exercises egress.
//
// This proves that netstack plumbing end to end with a hit counter and a
// controlled upstream. It deliberately does NOT exercise workerd: that workerd
// issues ordinary socket()/connect()/sendmsg() syscalls — stock prebuilt
// Cloudflare binary, KJ epoll I/O, no io_uring/vsock/raw — which the systrap
// platform traps onto this same in-Sentry netstack, is established by code
// inspection and the APO-815 adversarial review, not by this test. The
// real-runsc end-to-end of a live workerd fetch() being forwarded additionally
// needs the clrk ForwarderInstaller egress data path (APO-723/APO-726), which is
// out of tree.
package sentrystack

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dpeckett/contextio"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// egressDstAddr is a non-local destination (TEST-NET-3, RFC 5737) — the stand-in
// for an external host a worker fetch()es. It is deliberately NOT one of the
// stack's own addresses, so reaching it requires the eth0 default route, not
// loopback delivery.
var egressDstAddr = tcpip.AddrFrom4([4]byte{203, 0, 113, 5})

// eth0EgressNIC is the eth0 NIC id (matches production's eth0NICID; redeclared
// here because that const lives in the linux-only stack.go).
const eth0EgressNIC tcpip.NICID = 2

// newEgressStack builds the real sentrystack EGRESS topology: lo (from
// newLoopbackStack) plus an eth0 NIC backed by the production loopether link, a
// 0.0.0.0/0 default route via eth0, and promiscuous+spoofing — exactly what
// doInit/wireEth0 install. A dial to a non-local dst routes out eth0, loops
// straight back via loopether, is accepted (promiscuous+spoofing), matches no
// listener, and falls to whatever catch-all the caller installs.
func newEgressStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := newLoopbackStack(t) // lo + 127.0.0.1/8 + loopback route

	mac := tcpip.LinkAddress([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	if err := s.CreateNICWithOptions(eth0EgressNIC, newLoopether(mac), stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("create eth0 NIC: %v", err)
	}
	if err := s.SetPromiscuousMode(eth0EgressNIC, true); err != nil {
		t.Fatalf("set eth0 promiscuous: %v", err)
	}
	if err := s.SetSpoofing(eth0EgressNIC, true); err != nil {
		t.Fatalf("set eth0 spoofing: %v", err)
	}
	if err := s.AddProtocolAddress(eth0EgressNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 200, 0, 6}),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("add eth0 v4 addr: %v", err)
	}
	// Replace the route table with lo's loopback route plus the eth0 default
	// route (SetRouteTable is wholesale). Gateway is cosmetic: the forwarder
	// catches the looped-back SYN before any neighbor resolution, and loopether
	// advertises no CapabilityResolutionRequired anyway.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4LoopbackSubnet, NIC: 1},
		{Destination: header.IPv4EmptySubnet, NIC: eth0EgressNIC},
	})
	return s
}

// dialEgressDst returns an http DialContext that ignores the requested address
// and dials the non-local egressDstAddr inside the stack via route lookup
// (NIC 0), exercising the eth0 default route.
func dialEgressDst(s *stack.Stack, port uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{
			Addr: egressDstAddr,
			Port: port,
		}, ipv4.ProtocolNumber)
	}
}

// installProxyEgressForwarder registers a catch-all TCP forwarder that stands in
// for the egress data path an installer wires (cf. pkg/netstack tcpHandler and
// sentrystack control_linux.go handleControl): for each forwarded SYN it records
// the hit, accepts the in-stack endpoint, dials the controlled upstream on the
// host, and splices the two via contextio.SpliceContext. A waiter.EventHUp entry
// cancels the splice when the in-stack side hangs up, and a test-scoped context
// bounds every goroutine to the test's lifetime, so nothing leaks past cleanup
// and the clean-shutdown req.Complete(false) is actually reached. Returns the
// hit counter; the hit is recorded synchronously so a caller can read it the
// instant the round-trip completes.
func installProxyEgressForwarder(t *testing.T, s *stack.Stack, upstream string) *atomic.Int64 {
	t.Helper()
	baseCtx, cancelAll := context.WithCancel(context.Background())
	t.Cleanup(cancelAll)

	var hits atomic.Int64
	fwd := tcp.NewForwarder(s, 0, 65535, func(req *tcp.ForwarderRequest) {
		hits.Add(1)
		go func() {
			ctx, cancel := context.WithCancel(baseCtx)
			defer cancel()

			var wq waiter.Queue
			ep, terr := req.CreateEndpoint(&wq)
			if terr != nil {
				req.Complete(true) // RST
				return
			}

			// Cancel the splice when the in-stack endpoint hangs up so neither
			// io copy blocks past connection close.
			waitEntry, hupCh := waiter.NewChannelEntry(waiter.EventHUp)
			wq.EventRegister(&waitEntry)
			defer wq.EventUnregister(&waitEntry)
			go func() {
				select {
				case <-ctx.Done():
				case <-hupCh:
					cancel()
				}
			}()

			guest := gonet.NewTCPConn(&wq, ep)
			defer guest.Close()

			up, derr := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
			if derr != nil {
				req.Complete(true) // RST
				return
			}
			defer up.Close()

			if _, err := contextio.SpliceContext(ctx, guest, up, nil); err != nil && !errors.Is(err, context.Canceled) {
				req.Complete(true) // RST
				return
			}
			req.Complete(false) // FIN
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return &hits
}

// TestEgressLandsOnForwarder asserts both halves of the egress claim:
//
//   - outbound_dial_is_serviced_by_forwarder: an outbound dial to a NON-LOCAL
//     dst routes out eth0, loops back, is stolen by the catch-all egress
//     forwarder (fires exactly once), and is serviced end to end — the
//     controlled host upstream receives the request and its response reaches the
//     caller. Positive proof that an outbound connection to an external dst is
//     captured and bridged by the netstack rather than escaping.
//   - no_forwarder_fails_closed: with the same egress topology but NO forwarder
//     installed (the apoxy-cli runtime today — ForwarderInstaller is nil,
//     egress.go ApplyEgress is an APO-723 no-op), the same non-local dial is RST
//     in the stack. Egress fails closed; it is never bridged.
func TestEgressLandsOnForwarder(t *testing.T) {
	t.Run("outbound_dial_is_serviced_by_forwarder", func(t *testing.T) {
		var gotPath atomic.Value
		gotPath.Store("")
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath.Store(r.URL.Path)
			_, _ = w.Write([]byte("egress-ok"))
		}))
		t.Cleanup(upstream.Close)

		s := newEgressStack(t)
		hits := installProxyEgressForwarder(t, s, upstream.Listener.Addr().String())

		// DisableKeepAlives so the client closes the in-stack conn right after
		// the response, letting the splice terminate cleanly (req.Complete(false)
		// runs) instead of parking on a kept-alive connection until teardown.
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext:       dialEgressDst(s, 80),
			},
		}
		// The URL host is cosmetic: DialContext is overridden to the non-local
		// egressDstAddr, the external destination under test.
		resp, err := client.Get("http://egress.example/egress-probe")
		if err != nil {
			t.Fatalf("outbound egress dial failed: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		// THE assertions: the forwarder fired exactly once for the non-local dst,
		// and the connection was serviced end to end through it to the upstream.
		if n := hits.Load(); n != 1 {
			t.Fatalf("egress forwarder fired %d time(s); want exactly 1 — the non-local outbound dial did not land on the forwarder", n)
		}
		if string(body) != "egress-ok" {
			t.Fatalf("upstream response did not reach the caller: body = %q, want %q", string(body), "egress-ok")
		}
		if got := gotPath.Load().(string); got != "/egress-probe" {
			t.Fatalf("controlled upstream did not receive the forwarded request: path = %q, want %q", got, "/egress-probe")
		}
	})

	t.Run("no_forwarder_fails_closed", func(t *testing.T) {
		// Full egress topology (eth0 + default route) but NO forwarder installed.
		// The non-local SYN loops back via eth0, matches no listener, and absent
		// a catch-all egress handler is RST in the stack — refused, never bridged.
		s := newEgressStack(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{
			Addr: egressDstAddr,
			Port: 80,
		}, ipv4.ProtocolNumber)
		if err == nil {
			_ = conn.Close()
			t.Fatal("outbound egress dial succeeded with no forwarder — egress is not fail-closed")
		}
		// It must be actively refused in-stack, not silently dropped (which would
		// surface as a deadline and hide a regression where the SYN escaped or hung).
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("egress dial hung to deadline instead of being RST in-stack: %v", err)
		}
	})
}
