// This test is intentionally NOT //go:build linux constrained: it uses only
// gVisor's portable pkg/tcpip netstack (no sentry, no runsc, no privileges),
// so it compiles and runs on the developer's macOS host as well as in CI.
//
// It exists to positively prove the one load-bearing assumption behind the
// APO-694 ingress design (host -> resident server inside the sandbox):
//
//	A bound/listening endpoint inside the in-Sentry tcpip.Stack SHADOWS the
//	catch-all tcp.NewForwarder that an egress installer registers via
//	SetTransportProtocolHandler. An in-stack dial toward that listener is
//	demuxed to the listener's accept queue and is NOT stolen by the egress
//	forwarder.
//
// The whole inbound mechanism (installInboundForwarder -> gonet.DialContextTCP
// into the resident workerd listener -> splice) rests on this. If gVisor ever
// changed transport demux precedence so the global handler ran first, the
// inbound path would silently route every connection to the egress bridge
// instead of the resident server. This test is the regression guard for that.
//
// The topology here mirrors newStack() + the lo wiring in doInit() exactly:
// ipv4/ipv6/arp + tcp/udp/icmp, HandleLocal, a loopback NIC with promiscuous +
// spoofing, 127.0.0.1/8, and the loopback route. The forwarder is installed the
// same way an egress installer does.
package sentrystack

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// TestInitStrInboundRoundtrip guards the wire format of the inbound fields the
// host ships to the Sentry. It is cross-platform (pure JSON, no gvisor), so it
// runs on the dev host. The omitempty behavior matters for compatibility: an
// egress-only sandbox must encode no inbound keys so the payload stays
// identical to the pre-ingress shape.
func TestInitStrInboundRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		in   InitStr
	}{
		{name: "inbound_loopback", in: InitStr{InboundListenAddr: "127.0.0.1:8080", InboundFDIndex: 3}},
		{name: "inbound_eth0", in: InitStr{Eth0V4: "10.200.0.6", Eth0V4PrefixLen: 32, InboundListenAddr: "10.200.0.6:9090", InboundFDIndex: 3}},
		{name: "inbound_unset", in: InitStr{SandboxID: "abc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := tc.in.Encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			out, err := DecodeInitStr(enc)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if out.InboundListenAddr != tc.in.InboundListenAddr {
				t.Errorf("InboundListenAddr = %q, want %q", out.InboundListenAddr, tc.in.InboundListenAddr)
			}
			if out.InboundFDIndex != tc.in.InboundFDIndex {
				t.Errorf("InboundFDIndex = %d, want %d", out.InboundFDIndex, tc.in.InboundFDIndex)
			}
			// Egress-only payloads must not carry inbound keys at all.
			if tc.in.InboundListenAddr == "" && tc.in.InboundFDIndex == 0 {
				if strings.Contains(enc, "inbound_") {
					t.Errorf("egress-only payload unexpectedly encodes inbound keys: %s", enc)
				}
			}
		})
	}
}

// loopbackAddr is 127.0.0.1 as a tcpip.Address.
var loopbackAddr = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})

// newLoopbackStack builds a tcpip.Stack topologically identical to the one a
// clrk Sentry boots (lo only, no eth0 — a 127.0.0.1 target is the most robust
// since lo exists even in Phase 1 lo-only mode). It installs NO transport
// handler, so each caller layers on whatever forwarder its scenario needs (the
// inbound proof a RST catch-all; the egress proof a real upstream-splicing one).
func newLoopbackStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
		HandleLocal: true,
	})
	t.Cleanup(s.Close)

	if err := s.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("create lo NIC: %v", err)
	}
	if err := s.SetPromiscuousMode(1, true); err != nil {
		t.Fatalf("set lo promiscuous: %v", err)
	}
	if err := s.SetSpoofing(1, true); err != nil {
		t.Fatalf("set lo spoofing: %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   loopbackAddr,
			PrefixLen: 8,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("add lo v4 addr: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4LoopbackSubnet, NIC: 1}})
	return s
}

// newProofStack builds a loopback stack and installs the catch-all egress
// forwarder exactly as an egress installer does. The returned counter records
// how many TCP SYNs reached the forwarder (i.e. matched no listening endpoint).
func newProofStack(t *testing.T) (*stack.Stack, *atomic.Int64) {
	t.Helper()
	s := newLoopbackStack(t)

	// Catch-all forwarder, installed exactly as an egress installer does. The
	// handler records the hit and RSTs — standing in for the egress dial path
	// so we can observe whether a SYN that should reach the resident listener
	// instead fell through to the forwarder.
	var fwdHits atomic.Int64
	fwd := tcp.NewForwarder(s, 0, 65535, func(req *tcp.ForwarderRequest) {
		fwdHits.Add(1)
		req.Complete(true) // RST
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return s, &fwdHits
}

func dialerFor(s *stack.Stack, port uint16) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{
			NIC:  1,
			Addr: loopbackAddr,
			Port: port,
		}, ipv4.ProtocolNumber)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

// TestInboundDemux is the APO-694 go/no-go proof. It asserts both directions of
// the load-bearing claim:
//
//   - listener_shadows_forwarder: with a resident listener bound on 127.0.0.1:p,
//     an in-stack dial to :p is served by the listener and the catch-all
//     forwarder NEVER fires. This is the mechanism the inbound forwarder relies
//     on.
//   - no_listener_falls_to_forwarder: with NO listener on :p, the same in-stack
//     dial DOES fall to the forwarder (and gets RST). This is the negative
//     control proving the forwarder really is the global catch-all, so the
//     positive result above is the listener shadowing it — not the forwarder
//     being absent.
func TestInboundDemux(t *testing.T) {
	t.Run("listener_shadows_forwarder", func(t *testing.T) {
		s, fwdHits := newProofStack(t)

		const port = 8080
		ln, err := gonet.ListenTCP(s, tcpip.FullAddress{
			NIC:  1,
			Addr: loopbackAddr,
			Port: port,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("listen on resident port: %v", err)
		}

		// Resident "workerd": a tiny HTTP server serving a fixed body. ln is a
		// net.Listener, so this is a stock net/http server over the in-stack
		// listening endpoint.
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "pong")
		})}
		go srv.Serve(ln)
		t.Cleanup(func() { _ = srv.Close() })

		// Inbound dial: stands in for the in-Sentry inbound forwarder's
		// gonet.DialContextTCP into the resident listener.
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{DialContext: dialerFor(s, port)},
		}
		resp, err := client.Get("http://127.0.0.1:8080/")
		if err != nil {
			t.Fatalf("inbound dial to resident listener failed: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if got := string(body); got != "pong" {
			t.Fatalf("resident server returned %q, want %q", got, "pong")
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		// THE assertion: the bound listener shadowed the catch-all forwarder.
		if hits := fwdHits.Load(); hits != 0 {
			t.Fatalf("egress forwarder fired %d time(s) for a connection that should have reached the resident listener — the inbound design is INVALID as written", hits)
		}
	})

	t.Run("no_listener_falls_to_forwarder", func(t *testing.T) {
		s, fwdHits := newProofStack(t)

		// No listener on this port. The in-stack dial must fall to the
		// catch-all forwarder (which RSTs), proving the forwarder is the
		// global handler and the positive case above is genuine shadowing.
		const port = 9999
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{
			NIC:  1,
			Addr: loopbackAddr,
			Port: port,
		}, ipv4.ProtocolNumber)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("dial to unlistened port unexpectedly succeeded")
		}
		if hits := fwdHits.Load(); hits == 0 {
			t.Fatalf("forwarder did not fire for an unlistened-port dial — the catch-all is not installed as expected, so the shadow test is inconclusive")
		}
	})
}
