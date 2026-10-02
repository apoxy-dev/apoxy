package netstack_test

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

var (
	localAddr = netip.MustParseAddr("fd00::1")
	peerAddr  = netip.MustParseAddr("fd00::2")
)

// TestStackClose checks that a closed stack stops all its goroutines. It counts
// goroutines, so no test in this package can run in parallel with it.
func TestStackClose(t *testing.T) {
	cases := []struct {
		name string
		// open makes the stack and starts its work. It returns the close.
		open func(t *testing.T) func()
	}{
		{name: "stack idle", open: openStack(false)},
		{name: "stack with a listener and a pending dial", open: openStack(true)},
		{name: "tun device idle", open: openTun(false)},
		{name: "tun device with a full read queue", open: openTun(true)},
		{name: "icx network running", open: openICX},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := runtime.NumGoroutine()
			closeStack := tc.open(t)

			done := make(chan struct{})
			go func() {
				closeStack()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not return in 5 s")
			}

			if !waitFor(func() bool { return runtime.NumGoroutine() <= base }) {
				buf := make([]byte, 1<<20)
				t.Logf("Goroutines:\n%s", buf[:runtime.Stack(buf, true)])
				t.Fatalf("%d goroutines after Close, %d before the open", runtime.NumGoroutine(), base)
			}
		})
	}
}

func openStack(dial bool) func(t *testing.T) func() {
	return func(t *testing.T) func() {
		ns, err := netstack.NewStack(netstack.TunnelMTU, "")
		require.NoError(t, err)
		if !dial {
			return ns.Close
		}
		require.NoError(t, ns.AddAddr(netip.PrefixFrom(localAddr, 128)))
		_, err = gonet.ListenTCP(ns.Stack, fullAddr(ns.NICID, localAddr, 80), ipv6.ProtocolNumber)
		require.NoError(t, err)
		// Nothing reads the endpoint, so the dial stays in SYN-SENT.
		dialed := make(chan error, 1)
		go func() {
			_, err := gonet.DialContextTCP(context.Background(), ns.Stack, fullAddr(ns.NICID, peerAddr, 80), ipv6.ProtocolNumber)
			dialed <- err
		}()
		require.True(t, waitFor(func() bool { return ns.Endpoint.NumQueued() > 0 }), "no SYN")
		return func() {
			ns.Close()
			assert.Error(t, <-dialed, "the dial continues after Close")
		}
	}
}

func openTun(full bool) func(t *testing.T) func() {
	return func(t *testing.T) func() {
		dev, err := netstack.NewTunDevice("")
		require.NoError(t, err)
		if !full {
			return func() { assert.NoError(t, dev.Close()) }
		}
		require.NoError(t, dev.AddAddr(netip.PrefixFrom(localAddr, 128)))
		pc, err := dev.ListenPacket(netip.AddrPortFrom(localAddr, 5000))
		require.NoError(t, err)
		// Nothing reads the device. The send after the read queue is full blocks.
		var sent atomic.Int64
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 9))
			for {
				if _, err := pc.WriteTo([]byte("x"), dst); err != nil {
					return
				}
				sent.Add(1)
			}
		}()
		require.True(t, waitFor(func() bool { return sent.Load() >= 1024 }), "the read queue is not full")
		return func() {
			assert.NoError(t, dev.Close())
			<-stopped
		}
	}
}

func openICX(t *testing.T) func() {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	phy, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.AddrPortFrom(local.Addr().Unmap(), local.Port()))),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)
	n, err := netstack.NewICXNetwork(h, phy, netstack.TunnelMTU, nil, "")
	require.NoError(t, err)
	started := make(chan struct{})
	go func() {
		defer close(started)
		_ = n.Start(context.Background())
	}()
	// The routers close the network first and then the underlay.
	return func() {
		assert.NoError(t, n.Close())
		assert.NoError(t, phy.Close())
		<-started
	}
}

func fullAddr(nic tcpip.NICID, addr netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: port}
}

// waitFor polls cond for up to 5 s. It starts no goroutines, so it does not
// change the goroutine count.
func waitFor(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}
