// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// roamChild is set in the process that runs a row of TestRoamNetns.
const roamChild = "APOXY_TEST_ROAM_CHILD"

// TestRoamNetns moves agent a from link a0 to link a1, as a laptop moves from
// Wi-Fi to LTE, and measures the time until data works again.
func TestRoamNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	cases := []struct {
		name    string
		noRoute time.Duration // Time with no route. An RPC starts in this time.
	}{
		{"roam", 0},
		{"no route for a time", 500 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getenv(roamChild) == "" {
				// The agent finds its local address in the namespace of its process,
				// so each row runs in a new process with a new namespace.
				cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
				cmd.Env = append(os.Environ(), roamChild+"=1")
				cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
				out, err := cmd.CombinedOutput()
				if errors.Is(err, syscall.EPERM) {
					t.Skipf("cannot start a process in a new network namespace: %v", err)
				}
				t.Logf("%s", out)
				require.NoError(t, err)
				return
			}
			roam(t, tc.noRoute)
		})
	}
}

// roam runs one row of TestRoamNetns in the namespace of the process.
func roam(t *testing.T, noRoute time.Duration) {
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

	a.a.mu.Lock()
	rc := a.a.rc
	var peers []quic.Connection
	for _, p := range a.a.peers {
		peers = append(peers, p.qc)
	}
	a.a.mu.Unlock()
	a0, err := ah.LinkByName("a0")
	require.NoError(t, err)
	a1, err := ah.LinkByName("a1")
	require.NoError(t, err)
	t0 := time.Now()
	require.NoError(t, ah.LinkSetDown(a0))
	resolved := make(chan error, 1)
	if noRoute > 0 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := rc.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: rc.ref, Address: eb.addr.String()})
			resolved <- err
		}()
		time.Sleep(noRoute)
	}
	tr := time.Now()
	require.NoError(t, ah.RouteAdd(&netlink.Route{
		LinkIndex: a1.Attrs().Index,
		Dst:       &net.IPNet{IP: relayIP, Mask: net.CIDRMask(32, 32)},
		Gw:        net.IPv4(10, 98, 0, 1),
	}))
	at := firstEcho(t, a.stack, ea.addr, eb.addr, 7, interval, 3*time.Second)
	require.False(t, at.IsZero(), "no data in 3 s after the move")

	if noRoute > 0 {
		// QUIC sends the RPC again when the route comes back, on the same session.
		require.NoError(t, <-resolved, "RPC that started with no route")
		a.a.mu.Lock()
		same := a.a.rc == rc
		a.a.mu.Unlock()
		assert.True(t, same, "agent opened a new relay session")
		assert.NoError(t, context.Cause(rc.qc.Context()), "relay session closed")
		require.NotEmpty(t, peers)
		for _, qc := range peers {
			assert.NoError(t, context.Cause(qc.Context()), "peer session closed")
		}
		t.Logf("No route for %v: data works %v after the route came back", noRoute, at.Sub(tr))
		assert.Less(t, at.Sub(tr), 2*time.Second)
		return
	}
	require.NotZero(t, tap.quic.Load(), "relay sent no QUIC packet to the new address")
	require.NotZero(t, tap.psp.Load(), "relay sent no data to the new address")
	// The relay sends a PATH_CHALLENGE to the new path first. It moves the
	// connection when the response comes back, one RTT later.
	rtt := 2 * oneWay
	challenge := time.Unix(0, tap.quic.Load()).Sub(t0)
	migrated, rows, data := challenge+rtt, time.Unix(0, tap.psp.Load()).Sub(t0), at.Sub(t0)
	t.Logf("Roam: challenge %v, connection moved %v, relay data to the new address %v, data works %v after the move (%v after the connection moved)",
		challenge, migrated, rows, data, data-migrated)
	assert.Less(t, data, 1500*time.Millisecond)
	// Moved starts a watch. The sweep alone takes up to 1 s.
	assert.LessOrEqual(t, data-migrated, 200*time.Millisecond, "data works late after the move")
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
