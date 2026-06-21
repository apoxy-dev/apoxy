// This test is intentionally NOT //go:build linux constrained: like
// inbound_demux_test.go it uses only gVisor's portable pkg/tcpip netstack (no
// sentry, no runsc, no privileges), so it compiles and runs on the developer's
// macOS host as well as in CI.
//
// It proves the load-bearing assumption behind the resident → host-manager
// control path (APO-796), the guest→host mirror of inbound:
//
//	An in-stack TCP listener bound to an otherwise-unassigned loopback address
//	(127.0.0.2, deliberately distinct from the resident's own 127.0.0.1 data
//	socket) accepts a guest-originated dial and can be spliced to a HOST
//	AF_UNIX socket — round-tripping a real HTTP request/response.
//
// installControlForwarder rests on this. If gVisor ever stopped delivering to a
// listener on an assigned secondary loopback address, the dispatcher's MANAGER
// binding would never reach the host control server and WorkerLoader could never
// pull a worker definition — the whole resident would serve nothing. This test
// is the regression guard for that, and the macOS-runnable proof that the
// secondary-loopback bind works at all.
package sentrystack

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// controlAddr is 127.0.0.2 — the default in-sandbox control target, deliberately
// distinct from the resident's 127.0.0.1 data listener so the two never collide.
var controlAddr = tcpip.AddrFrom4([4]byte{127, 0, 0, 2})

// TestControlForwarderSplice is the APO-796 control-path go/no-go proof. It
// reproduces installControlForwarder's mechanism inline (the real impl is a
// //go:build linux method on *Stack, so it can't be called here) on the same
// stack topology a clrk Sentry boots, and asserts a guest dial to the control
// address round-trips through a host AF_UNIX socket — and that the bound control
// listener shadows the catch-all egress forwarder exactly as inbound does.
func TestControlForwarderSplice(t *testing.T) {
	s, fwdHits := newProofStack(t)

	// Assign the control addr to lo so the in-stack listener binds it. This is
	// exactly what installControlForwarder does before listening; the test
	// asserts that assignment is sufficient for delivery.
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: controlAddr, PrefixLen: 32},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("assign control addr to lo: %s", err)
	}

	// Host manager control server: a stock net/http server over a host AF_UNIX
	// socket that returns a worker definition keyed by the requested id. Stands
	// in for manager.ControlServer.
	sockPath := filepath.Join(t.TempDir(), "control.sock")
	hostLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen host unix: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "worker-def:"+r.URL.Query().Get("id"))
	})}
	go srv.Serve(hostLn)
	t.Cleanup(func() { _ = srv.Close() })

	// In-stack control listener on 127.0.0.2:80 that splices each accepted guest
	// connection to a fresh host dial of the manager socket — the inline
	// equivalent of installControlForwarder + handleControl.
	const port = 80
	ctrlLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: controlAddr, Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("in-stack listen on control addr 127.0.0.2:%d: %v", port, err)
	}
	t.Cleanup(func() { _ = ctrlLn.Close() })
	go func() {
		for {
			guestConn, err := ctrlLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer guestConn.Close()
				hostConn, err := net.Dial("unix", sockPath)
				if err != nil {
					return
				}
				defer hostConn.Close()
				splice(guestConn, hostConn)
			}()
		}
	}()

	// Guest side: dial 127.0.0.2:80 inside the stack (stands in for the
	// dispatcher's MANAGER binding) and fetch a worker definition.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: controlAddr, Port: port}, ipv4.ProtocolNumber)
		}},
	}
	resp, err := client.Get("http://127.0.0.2/worker?id=proj:api:api-r1")
	if err != nil {
		t.Fatalf("guest dial through control forwarder failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got, want := string(body), "worker-def:proj:api:api-r1"; got != want {
		t.Fatalf("control server returned %q, want %q", got, want)
	}

	// The bound control listener shadowed the catch-all forwarder, same as
	// inbound: the guest's control dial reached our listener, not the egress
	// bridge. A non-zero count would mean the control connection was stolen.
	if hits := fwdHits.Load(); hits != 0 {
		t.Fatalf("egress forwarder fired %d time(s) for a control connection that should have reached the in-stack listener", hits)
	}
}

// TestInitStrControlRoundtrip guards the wire format of the control fields the
// host ships to the Sentry. Cross-platform (pure JSON). The omitempty behavior
// matters: a sandbox with no control plane must encode no control keys so the
// payload stays identical to the pre-control shape.
func TestInitStrControlRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		in   InitStr
	}{
		{name: "control_set", in: InitStr{ControlForwardAddr: "127.0.0.2:80", ControlHostAddr: "127.0.0.1:2024"}},
		{name: "control_with_inbound", in: InitStr{
			InboundListenAddr:  "127.0.0.1:8080",
			InboundFDIndex:     3,
			ControlForwardAddr: "127.0.0.2:80",
			ControlHostAddr:    "127.0.0.1:2024",
		}},
		{name: "control_unset", in: InitStr{SandboxID: "abc"}},
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
			if out.ControlForwardAddr != tc.in.ControlForwardAddr {
				t.Errorf("ControlForwardAddr = %q, want %q", out.ControlForwardAddr, tc.in.ControlForwardAddr)
			}
			if out.ControlHostAddr != tc.in.ControlHostAddr {
				t.Errorf("ControlHostAddr = %q, want %q", out.ControlHostAddr, tc.in.ControlHostAddr)
			}
			if tc.in.ControlForwardAddr == "" && tc.in.ControlHostAddr == "" {
				if strings.Contains(enc, "control_") {
					t.Errorf("control-less payload unexpectedly encodes control keys: %s", enc)
				}
			}
		})
	}
}

// splice copies bytes bidirectionally between a and b until either side closes,
// propagating a half-close so an HTTP peer sees EOF on the request body.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
