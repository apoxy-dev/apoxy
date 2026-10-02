package netstack_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/dpeckett/network/nettest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

func TestTCPForwarder(t *testing.T) {
	var serverPcapPath, clientPcapPath string
	if testing.Verbose() {
		serverPcapPath = "server.pcap"
		clientPcapPath = "client.pcap"
	}

	serverStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.1"), serverPcapPath)
	require.NoError(t, err)
	t.Cleanup(serverStack.Close)

	clientStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.2"), clientPcapPath)
	require.NoError(t, err)
	t.Cleanup(clientStack.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Move packets between the two stacks.
	go func() {
		if err := nettest.SplicePackets(ctx, serverStack, clientStack); err != nil && !errors.Is(err, context.Canceled) {
			panic(fmt.Errorf("packet splicing failed: %w", err))
		}
	}()

	// The server stack forwards TCP connections to the host loopback.
	serverStack.SetTransportProtocolHandler(tcp.ProtocolNumber, netstack.TCPForwarder(ctx, serverStack.Stack, network.Loopback()))

	// Make 1 MiB of random data for the client.
	blob := make([]byte, 1<<20)
	_, err = rand.Reader.Read(blob)
	require.NoError(t, err)

	// Get the checksum of the data.
	h := sha256.New()
	_, _ = h.Write(blob)
	expectedChecksum := hex.EncodeToString(h.Sum(nil))

	// Start an HTTP server on the loopback interface.
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	}))
	defer httpServer.Close()

	httpServerPort := httpServer.Listener.Addr().(*net.TCPAddr).Port

	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)

	// Connect from the client through the forwarder to the server on loopback.
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: clientNetwork.DialContext,
		},
	}

	resp, err := httpClient.Get("http://10.0.0.1:" + strconv.Itoa(httpServerPort))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the response body and get its checksum.
	h = sha256.New()
	_, err = io.Copy(h, resp.Body)
	require.NoError(t, err)

	// Compare the checksums.
	assert.Equal(t, expectedChecksum, hex.EncodeToString(h.Sum(nil)))
}

func TestUnmap4in6(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{name: "IPv4", addr: "10.0.0.5", want: "10.0.0.5"},
		{name: "IPv4-mapped", addr: "::ffff:10.0.0.5", want: "10.0.0.5"},
		{name: "NAT64", addr: "64:ff9b::a00:5", want: "10.0.0.5"},
		{name: "v1 overlay with IPv4", addr: "fd61:706f:7879:12:3400:abcd:a00:5", want: "10.0.0.5"},
		{name: "v1 overlay with loopback", addr: "fd61:706f:7879:12:3400:abcd:7f00:1", want: "127.0.0.1"},
		{name: "v1 overlay /96 address", addr: "fd61:706f:7879:12:3400:abcd::", want: "0.0.0.0"},
		{name: "v2 attachment address", addr: "fd61:706f:7879:12:3456:7800::1", want: "fd61:706f:7879:12:3456:7800::1"},
		{name: "ULA outside the overlay", addr: "fd00:1::1", want: "fd00:1::1"},
		{name: "global IPv6", addr: "2001:db8::a00:5", want: "2001:db8::a00:5"},
		{name: "IPv6 loopback", addr: "::1", want: "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := netstack.Unmap4in6(netip.MustParseAddr(tc.addr))
			assert.Equal(t, netip.MustParseAddr(tc.want), got)
		})
	}
}

// TestStackIPv4 checks a stack with only an IPv6 address, as in a VPC. It
// forwards a connection from the VPC to IPv4 in the plain IPv4, overlay /96 and
// NAT64 forms. Its own IPv4 dials fail at once.
func TestStackIPv4(t *testing.T) {
	up := &recordNetwork{Network: network.Loopback(), echo: tcpEchoServer(t)}
	const overlay = "fd61:706f:7879:12:3456:7800::1/128"
	s := newStack(t, overlay)
	require.NoError(t, s.ForwardTo(t.Context(), up))
	// The VPC side has an IPv4 address and an overlay address.
	vpc := newStack(t, "192.0.2.10/32", "fd61:706f:7879:12:3456:aa00::1/128")
	spliceStacks(t, vpc, s)

	cases := []struct {
		name string
		addr string
		out  bool // Dial from the stack, not into it.
	}{
		{name: "into plain IPv4", addr: "10.1.0.5:80"},
		{name: "into the overlay /96", addr: "[fd61:706f:7879:12:3456:7800:a01:5]:80"},
		{name: "into NAT64", addr: "[64:ff9b::a01:5]:80"},
		{name: "out to IPv4", addr: "10.1.0.5:80", out: true},
		{name: "out to IPv4-mapped", addr: "[::ffff:10.1.0.5]:80", out: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if tc.out {
				// A new stack: while a forwarded IPv4 connection is open, a stack
				// can send from the IPv4 address of that connection.
				out := newStack(t, overlay)
				require.NoError(t, out.ForwardTo(t.Context(), up))
				_, err := out.Network(nil).DialContext(ctx, "tcp", tc.addr)
				require.ErrorContains(t, err, "network is unreachable")
				return
			}
			c, err := vpc.Network(nil).DialContext(ctx, "tcp", tc.addr)
			require.NoError(t, err)
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = c.Write([]byte("ping"))
			require.NoError(t, err)
			buf := make([]byte, 4)
			_, err = io.ReadFull(c, buf)
			require.NoError(t, err)
			require.Equal(t, "ping", string(buf))
			require.Equal(t, "10.1.0.5:80", up.last())
		})
	}
}

// newStack makes a stack with addrs, and closes it at the end of the test.
func newStack(t *testing.T, addrs ...string) *netstack.Stack {
	s, err := netstack.NewStack(netstack.TunnelMTU, "")
	require.NoError(t, err)
	t.Cleanup(s.Close)
	for _, a := range addrs {
		require.NoError(t, s.AddAddr(netip.MustParsePrefix(a)))
	}
	return s
}

// recordNetwork keeps the last dial address, and connects the dial to echo.
type recordNetwork struct {
	network.Network
	echo string

	mu   sync.Mutex
	addr string
}

func (n *recordNetwork) DialContext(ctx context.Context, nw, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.addr = addr
	n.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, nw, n.echo)
}

func (n *recordNetwork) last() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addr
}

// tcpEchoServer returns the address of a TCP echo server on loopback.
func tcpEchoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// spliceStacks moves packets between the NICs of a and b until the test ends.
func spliceStacks(t *testing.T, a, b *netstack.Stack) {
	ctx := t.Context()
	move := func(from, to *channel.Endpoint) {
		for {
			pkt := from.ReadContext(ctx)
			if pkt == nil {
				return
			}
			in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pkt.ToBuffer()})
			to.InjectInbound(pkt.NetworkProtocolNumber, in)
			in.DecRef()
			pkt.DecRef()
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() { move(a.Endpoint, b.Endpoint) })
	wg.Go(func() { move(b.Endpoint, a.Endpoint) })
	t.Cleanup(wg.Wait)
}
