// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
)

// roamChild is set in the process that runs the body of TestRoamNetns.
const roamChild = "APOXY_TEST_ROAM_CHILD"

// TestRoamNetns moves agent a from link a0 to link a1, as a laptop moves from
// Wi-Fi to LTE, and measures the time until data works again.
func TestRoamNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	if os.Getenv(roamChild) == "" {
		// The agent finds its local address in the namespace of its process, so
		// the test runs again in a new process with a new namespace.
		cmd := exec.Command(os.Args[0], "-test.run=^TestRoamNetns$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), roamChild+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		require.NoError(t, err)
		return
	}
	const (
		oneWay   = 10 * time.Millisecond // Delay on each link end. The RTT to the relay is 2*oneWay.
		interval = 2 * time.Millisecond  // Time between the packets of agent a.
	)
	relayNS := newNetns(t)
	agentNS, err := vnetns.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = agentNS.Close() })
	veth(t, relayNS, agentNS, 0)
	veth(t, relayNS, agentNS, 1)
	rh, ah := handle(t, relayNS), handle(t, agentNS)
	for _, l := range []struct {
		nl   *netlink.Handle
		name string
	}{{rh, "r0"}, {rh, "r1"}, {ah, "a0"}, {ah, "a1"}} {
		delay(t, l.nl, l.name, oneWay)
	}

	udp := listenIn(t, agentNS, nil)
	newAddr := netip.AddrPortFrom(netip.MustParseAddr("10.98.0.2"), uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	tap := &tapConn{PacketConn: listenIn(t, relayNS, relayIP), to: newAddr}
	w := newWorld(t)
	r := w.relayOn(t, "relay-1", tap)
	runRouter(t, r)
	b := w.agent(t, "b", r, agentOptions{udp: listenIn(t, relayNS, relayIP), mode: TransportPSP})
	a := w.agent(t, "a", r, agentOptions{udp: udp, mode: TransportPSP})
	ea, eb := a.attached(t), b.attached(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.a.Connect(ctx, eb.addr))
	echo(t, b.stack, eb.addr, 7)
	ping(t, a.stack, ea.addr, eb.addr, 7, "before the move")
	// With no QUIC packet in flight, the first QUIC packet on the new path is Moved.
	time.Sleep(1500 * time.Millisecond)

	a0, err := ah.LinkByName("a0")
	require.NoError(t, err)
	a1, err := ah.LinkByName("a1")
	require.NoError(t, err)
	t0 := time.Now()
	require.NoError(t, ah.LinkSetDown(a0))
	require.NoError(t, ah.RouteAdd(&netlink.Route{
		LinkIndex: a1.Attrs().Index,
		Dst:       &net.IPNet{IP: relayIP, Mask: net.CIDRMask(32, 32)},
		Gw:        net.IPv4(10, 98, 0, 1),
	}))
	at := firstEcho(t, a.stack, ea.addr, eb.addr, 7, interval, 3*time.Second)
	require.False(t, at.IsZero(), "no data in 3 s after the move")
	require.NotZero(t, tap.quic.Load(), "relay sent no QUIC packet to the new address")
	require.NotZero(t, tap.psp.Load(), "relay sent no data to the new address")
	// The relay sends a PATH_CHALLENGE to the new path first. It moves the
	// connection when the response comes back, one RTT later.
	rtt := 2 * oneWay
	challenge := time.Unix(0, tap.quic.Load()).Sub(t0)
	migrated, rows, data := challenge+rtt, time.Unix(0, tap.psp.Load()).Sub(t0), at.Sub(t0)
	t.Logf("Roam: challenge %v, connection moved %v, relay data to the new address %v, data works %v after the move",
		challenge, migrated, rows, data)
	assert.Less(t, data, 1500*time.Millisecond)
	assert.LessOrEqual(t, data-migrated, rtt+2*interval+10*time.Millisecond)
}

// delay adds netem with delay d to the link name.
func delay(t *testing.T, nl *netlink.Handle, name string, d time.Duration) {
	t.Helper()
	link, err := nl.LinkByName(name)
	require.NoError(t, err)
	q := netlink.NewNetem(
		netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT},
		netlink.NetemQdiscAttrs{Latency: uint32(d.Microseconds())},
	)
	require.NoError(t, nl.QdiscAdd(q))
}
