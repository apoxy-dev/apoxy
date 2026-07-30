package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// TestDataPlaneRoundTrip sends real payload bytes through the tunnel and
// asserts they come back. Topology (all in-process, all loopback UDP):
//
//	echo client --SOCKS--> agent netstack --Geneve/PSP--> relay netstack
//	                                                          |
//	                              (non-egress ForwardTo loopback)
//	                                                          v
//	                                          echo server on 127.0.0.1
//
// The agent gets an IPv6 overlay address; the relay's ConnectResponse then
// includes the /72 network-prefix route (relay.go handleConnect), which is
// what authorizes the agent's icx handler to encapsulate traffic for other
// in-overlay destinations. (IPv4 only gets the agent's own /32 back — an
// earlier version of this test used v4 and the SYN was dropped at the agent's
// encapsulation step, never reaching the relay.)
func TestDataPlaneRoundTrip(t *testing.T) {
	const (
		vni            = uint(2601)
		agentOverlay   = "fd00:cafe::2/96"
		agentOverlayV4 = "10.77.0.2/32"
		serviceAddr    = "fd00:cafe::99" // same /72 as the agent's overlay
		tunnelToken    = "letmein"
	)

	orig := connectionHealthCounter.Load()
	t.Cleanup(func() { connectionHealthCounter.Store(orig) })
	connectionHealthCounter.Store(0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	// --- Echo server the relay will forward tunnel traffic to. ---
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = echoLn.Close() })
	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	// --- Relay: real ICXNetstackRouter (non-egress → forward to loopback). ---
	relayPP, err := newPacketPlaneAt("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(relayPP.Close)

	relayRtr, err := router.NewICXNetstackRouter(
		router.WithPacketConn(relayPP.Geneve),
		// The relay-side SOCKS listener is unused; keep it off the default port
		// so parallel tests don't collide.
		router.WithSocksListenAddr("127.0.0.1:0"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = relayRtr.Close() })

	// Assign the full dual-stack set like production OnConnect: primary v6,
	// VNI, then SetAddresses which programs the v4 /32 onto the relay router
	// and into the VNI's allowed routes. Relay.Start starts the router itself.
	onConnect := func(ctx context.Context, _, _ string, conn controllers.Connection) error {
		if err := conn.SetVNI(ctx, vni); err != nil {
			return err
		}
		if err := conn.SetOverlayAddress(agentOverlay); err != nil {
			return err
		}
		return conn.SetAddresses([]string{agentOverlay, agentOverlayV4})
	}
	r, stopRelay := startRelayHarness(t, tunnelToken, relayPP.QuicMux, relayRtr, relayRtr.Handler, onConnect,
		func(context.Context, string, string) error { return nil })
	t.Cleanup(stopRelay)

	relayAddr := r.Address().String()

	// --- Agent: bootstrap + full connection-slot path (installs keys, addrs). ---
	agentPP, err := newPacketPlaneAt("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(agentPP.Close)

	cfg := loopbackConfig()
	tlsConf := &tls.Config{InsecureSkipVerify: true}

	agentCtx, agentCancel := context.WithCancel(ctx)
	t.Cleanup(agentCancel)
	g, gctx := errgroup.WithContext(agentCtx)

	boot, err := bootstrapSession(gctx, cfg, relayAddr, agentPP.QuicMux, tlsConf)
	require.NoError(t, err)

	// A free loopback port for the agent's SOCKS listener.
	socksProbe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	socksAddr := socksProbe.Addr().String()
	require.NoError(t, socksProbe.Close())

	ar, handler, routes := newAgentRouterWithSocks(t, gctx, g, boot, agentPP, socksAddr)
	pool := randalloc.NewRandAllocator(sets.New[string](relayAddr))
	go func() { _ = manageConnectionSlot(gctx, cfg, agentPP.QuicMux, handler, ar, routes, pool, tlsConf) }()

	require.Eventually(t, func() bool {
		return connectionHealthCounter.Load() == 1
	}, 10*time.Second, 20*time.Millisecond, "agent should establish a live session")

	// --- Send traffic: SOCKS dial to an in-overlay address, expect the echo. ---
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	require.NoError(t, err)

	target := fmt.Sprintf("[%s]:%d", serviceAddr, echoPort)
	payload := []byte("ping through the tunnel")

	var conn net.Conn
	require.Eventually(t, func() bool {
		c, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
		if err != nil {
			t.Logf("dial %s not ready yet: %v", target, err)
			return false
		}
		conn = c
		return true
	}, 15*time.Second, 250*time.Millisecond, "SOCKS dial through the tunnel should succeed")
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got, "payload must round-trip through agent -> relay -> loopback echo server")
}
