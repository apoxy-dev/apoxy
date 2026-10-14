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

// ecnProxy forwards UDP between agents and the QUIC and PSP sockets of a relay, with one
// relay socket for each agent, and reads the ECN bits of each packet that it gets.
type ecnProxy struct {
	t        *testing.T
	front    *net.UDPConn // For the QUIC socket of the relay.
	pspFront *net.UDPConn // For the PSP socket of the relay, at its port number.
	quic     netip.AddrPort
	psp      netip.AddrPort

	mu    sync.Mutex
	backs map[netip.AddrPort]*net.UDPConn
	seen  map[string]*ecnCount // By sender and kind, for example "agent psp".
}

type ecnCount struct {
	packets int
	ect     int // Packets with ECT(0), ECT(1) or CE.
	noTOS   int // Packets with no IP_TOS control message.
}

func newECNProxy(t *testing.T, quicAddr, pspAddr net.Addr, pspFront *net.UDPConn) *ecnProxy {
	px := &ecnProxy{
		t:        t,
		front:    recvTOS(t, loopback(t)),
		pspFront: recvTOS(t, pspFront),
		quic:     netip.MustParseAddrPort(quicAddr.String()),
		psp:      netip.MustParseAddrPort(pspAddr.String()),
		backs:    map[netip.AddrPort]*net.UDPConn{},
		seen:     map[string]*ecnCount{},
	}
	t.Cleanup(func() {
		_ = px.front.Close()
		_ = px.pspFront.Close()
		px.mu.Lock()
		defer px.mu.Unlock()
		for _, c := range px.backs {
			_ = c.Close()
		}
	})
	go px.serve(px.front, "agent", px.toRelay(px.quic))
	go px.serve(px.pspFront, "agent", px.toRelay(px.psp))
	return px
}

// toRelay returns a forward of the packets of an agent to the relay socket to.
func (px *ecnProxy) toRelay(to netip.AddrPort) func([]byte, netip.AddrPort) {
	return func(b []byte, from netip.AddrPort) {
		if back := px.back(from); back != nil {
			_, _ = back.WriteToUDPAddrPort(b, to)
		}
	}
}

// relaySockets returns a QUIC socket and a PSP socket for a relay at 127.0.0.2,
// and a socket at 127.0.0.1 with the port of the PSP socket. An agent that dials
// the proxy at 127.0.0.1 sends its PSP packets to that socket.
func relaySockets(t *testing.T) (quicSock, pspSock, pspFront *net.UDPConn) {
	t.Helper()
	at := func(ip byte, port int) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, ip), Port: port})
	}
	quicSock, err := at(2, 0)
	require.NoError(t, err)
	// Another socket can have the port at 127.0.0.1, so try some ports.
	for range 50 {
		pspSock, err = at(2, 0)
		require.NoError(t, err)
		if pspFront, err = at(1, pspSock.LocalAddr().(*net.UDPAddr).Port); err == nil {
			return quicSock, pspSock, pspFront
		}
		_ = pspSock.Close()
	}
	require.NoError(t, err, "no free port at the two addresses")
	return nil, nil, nil
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
	go px.serve(c, "relay", func(b []byte, relay netip.AddrPort) {
		out := px.front
		if relay == px.psp {
			out = px.pspFront
		}
		_, _ = out.WriteToUDPAddrPort(b, from)
	})
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

// TestNotECT checks that the agents and the relay send all packets as Not-ECT:
// PSP between PSP agents, and PSP to a QUIC agent through the bridge.
func TestNotECT(t *testing.T) {
	w := newWorld(t)
	quicSock, pspSock, pspFront := relaySockets(t)
	px := newECNProxy(t, quicSock.LocalAddr(), pspSock.LocalAddr(), pspFront)
	r := w.relayOn(t, "relay-1", quicSock, pspSock)
	relays := []identity.Relay{{ID: r.id, Addresses: []string{px.addr()}}}
	a := w.agent(t, "a", r, agentOptions{mode: TransportAuto, relays: relays})
	b := w.agent(t, "b", r, agentOptions{mode: TransportQUIC, relays: relays})
	c := w.agent(t, "c", r, agentOptions{mode: TransportAuto, relays: relays})
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
