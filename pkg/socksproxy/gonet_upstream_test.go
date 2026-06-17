package socksproxy

// This test covers the production upstream connection type. In the tunnel data
// path the dialed (upstream) target conn is a gVisor netstack *gonet.TCPConn,
// NOT an OS *net.TCPConn — the host-fallback/loopback tests use real sockets and
// would not catch a regression in deadline handling on the netstack type. The
// whole leak fix hinges on SetDeadline interrupting a Read blocked on a
// half-open netstack peer, so we exercise that directly here, wiring two gVisor
// stacks together in-memory (no OS networking — runs in the sandbox).

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/dpeckett/network/nettest"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestGonetUpstreamHalfOpenReaped(t *testing.T) {
	serverStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.1"), "")
	require.NoError(t, err)
	clientStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.2"), "")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = nettest.SplicePackets(ctx, serverStack, clientStack) }()

	// A half-open peer inside the server netstack: it accepts the connection but
	// never reads, writes, or closes it — the production failure mode (NAT
	// idle-drop / crashed peer) for an upstream target.
	lis, err := gonet.ListenTCP(serverStack.Stack, tcpip.FullAddress{
		NIC:  serverStack.NICID,
		Addr: tcpip.AddrFromSlice(netip.MustParseAddr("10.0.0.1").AsSlice()),
		Port: 9999,
	}, ipv4.ProtocolNumber)
	require.NoError(t, err)

	held := make(chan net.Conn, 1)
	go func() {
		c, aerr := lis.Accept()
		if aerr != nil {
			return
		}
		held <- c // keep it referenced, open, and silent
	}()

	// Dial the half-open peer. The returned conn is a *gonet.TCPConn — exactly
	// the type the SOCKS dialer hands back for an upstream target in the tunnel
	// data path.
	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)
	conn, err := clientNetwork.DialContext(ctx, "tcp", "10.0.0.1:9999")
	require.NoError(t, err)

	// Tear everything down in order and DRAIN the gVisor stacks. nettest.Close
	// only removes the NIC; without stack.Close()+Wait() the TCP processor and
	// timer goroutines outlive the test and starve the sub-second idle windows
	// in the other (timing-sensitive) tests when the package is run -count>1.
	t.Cleanup(func() {
		cancel()
		_ = conn.Close()
		_ = lis.Close()
		select {
		case c := <-held:
			_ = c.Close()
		default:
		}
		serverStack.Close()
		clientStack.Close()
		serverStack.Stack.Close()
		clientStack.Stack.Close()
		serverStack.Stack.Wait()
		clientStack.Stack.Wait()
	})

	if _, isOSConn := conn.(*net.TCPConn); isOSConn {
		t.Fatal("expected a gonet netstack conn, got *net.TCPConn — test would not cover the production type")
	}

	// Wrap exactly as dialer.DialContext does. The guard arms SetDeadline on the
	// gonet conn on the first Read; with the peer silent, the Read must return a
	// timeout near the idle window instead of blocking forever — proving the fix
	// works on the netstack conn type, not just OS sockets.
	const idle = 300 * time.Millisecond
	now := time.Now()
	wrapped := &upstreamConnWrapper{
		Conn:      conn,
		logger:    slog.Default(),
		destType:  "upstream",
		startTime: now,
		guard:     newDeadlineGuard(&config{idleTimeout: idle}, now),
	}

	start := time.Now()
	_, readErr := wrapped.Read(make([]byte, 1))
	elapsed := time.Since(start)

	require.Error(t, readErr, "half-open gonet read should not block forever")
	var nerr net.Error
	isTimeout := errors.Is(readErr, os.ErrDeadlineExceeded) || (errors.As(readErr, &nerr) && nerr.Timeout())
	require.True(t, isTimeout, "expected a deadline/timeout error from the gonet conn, got %v", readErr)
	require.Less(t, elapsed, 5*idle, "gonet read did not unblock near the idle deadline (%v)", elapsed)
	require.GreaterOrEqual(t, elapsed, idle/2, "gonet read returned too early to be the idle deadline (%v)", elapsed)
}
