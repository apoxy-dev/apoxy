// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

// ecnProxy forwards UDP between agents and a relay, with one socket to the
// relay for each agent. It reads the ECN bits of each packet that it gets.
type ecnProxy struct {
	t     *testing.T
	front *net.UDPConn
	relay netip.AddrPort

	mu    sync.Mutex
	backs map[netip.AddrPort]*net.UDPConn
	seen  map[string]*ecnCount // By sender and kind, for example "agent psp".
}

type ecnCount struct {
	packets int
	ect     int // Packets with ECT(0), ECT(1) or CE.
	noTOS   int // Packets with no IP_TOS control message.
}

func newECNProxy(t *testing.T, relayAddr string) *ecnProxy {
	px := &ecnProxy{
		t:     t,
		front: recvTOS(t, loopback(t)),
		relay: netip.MustParseAddrPort(relayAddr),
		backs: map[netip.AddrPort]*net.UDPConn{},
		seen:  map[string]*ecnCount{},
	}
	t.Cleanup(func() {
		_ = px.front.Close()
		px.mu.Lock()
		defer px.mu.Unlock()
		for _, c := range px.backs {
			_ = c.Close()
		}
	})
	go px.serve(px.front, "agent", func(b []byte, from netip.AddrPort) {
		if back := px.back(from); back != nil {
			_, _ = back.WriteToUDPAddrPort(b, px.relay)
		}
	})
	return px
}

func (px *ecnProxy) addr() string { return px.front.LocalAddr().String() }

// back returns the socket to the relay for the agent at from.
func (px *ecnProxy) back(from netip.AddrPort) *net.UDPConn {
	px.mu.Lock()
	defer px.mu.Unlock()
	if c := px.backs[from]; c != nil {
		return c
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		px.t.Errorf("proxy socket: %v", err)
		return nil
	}
	px.backs[from] = recvTOS(px.t, c)
	go px.serve(c, "relay", func(b []byte, _ netip.AddrPort) { _, _ = px.front.WriteToUDPAddrPort(b, from) })
	return c
}

func (px *ecnProxy) serve(c *net.UDPConn, side string, forward func([]byte, netip.AddrPort)) {
	buf, oob := make([]byte, 2048), make([]byte, 128)
	for {
		n, oobn, _, from, err := c.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			return
		}
		px.record(side, buf[:n], oob[:oobn])
		forward(buf[:n], from)
	}
}

func (px *ecnProxy) record(side string, pkt, oob []byte) {
	kind := "other"
	switch {
	case len(pkt) == 0:
	case pkt[0]&0x40 != 0:
		kind = "quic"
	case pkt[0] == pspwire.NextHdrV4 || pkt[0] == pspwire.NextHdrV6:
		kind = "psp"
	}
	px.mu.Lock()
	defer px.mu.Unlock()
	c := px.seen[side+" "+kind]
	if c == nil {
		c = &ecnCount{}
		px.seen[side+" "+kind] = c
	}
	c.packets++
	tos, ok := tosOf(oob)
	switch {
	case !ok:
		c.noTOS++
	case tos&0x3 != 0:
		c.ect++
	}
}

func (px *ecnProxy) counts() map[string]ecnCount {
	px.mu.Lock()
	defer px.mu.Unlock()
	out := map[string]ecnCount{}
	for k, c := range px.seen {
		out[k] = *c
	}
	return out
}

// recvTOS turns on IP_RECVTOS on c.
func recvTOS(t *testing.T, c *net.UDPConn) *net.UDPConn {
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var serr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
	}))
	require.NoError(t, serr)
	return c
}

func tosOf(oob []byte) (byte, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS && len(m.Data) > 0 {
			return m.Data[0], true
		}
	}
	return 0, false
}

// TestNotECT sends traffic through a proxy in front of the relay: PSP between
// two PSP agents, and a PSP agent to a QUIC agent through the bridge. The
// agents and the relay must send all packets as Not-ECT.
func TestNotECT(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	px := newECNProxy(t, r.addr)
	relays := []identity.Relay{{ID: r.id, Addresses: []string{px.addr()}}}
	a := w.agent(t, "a", r, agentOptions{mode: TransportPSP, relays: relays})
	b := w.agent(t, "b", r, agentOptions{mode: TransportQUIC, relays: relays})
	c := w.agent(t, "c", r, agentOptions{mode: TransportPSP, relays: relays})
	ea, eb, ec := a.attached(t), b.attached(t), c.attached(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.a.Connect(ctx, eb.addr))
	require.NoError(t, a.a.Connect(ctx, ec.addr))
	echo(t, b.stack, eb.addr, 9000)
	echo(t, c.stack, ec.addr, 9000)
	for range 20 {
		ping(t, a.stack, ea.addr, eb.addr, 9000, "to b")
		ping(t, a.stack, ea.addr, ec.addr, 9000, "to c")
	}
	got := px.counts()
	t.Logf("packets by sender and kind: %+v", got)
	for _, k := range []string{"agent psp", "agent quic", "relay psp", "relay quic"} {
		assert.Positive(t, got[k].packets, "%s: no packets", k)
	}
	for k, n := range got {
		assert.Zero(t, n.noTOS, "%s: packets with no TOS", k)
		assert.Zero(t, n.ect, "%s: packets with ECT or CE", k)
	}
}
