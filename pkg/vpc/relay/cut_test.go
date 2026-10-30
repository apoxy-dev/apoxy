// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// cut drops the packets that a relay sends to the sockets of another relay while it is on. With a
// cut on each relay, the path between them is cut both ways.
type cut struct {
	on atomic.Bool
	mu sync.Mutex
	to []netip.AddrPort
}

func (c *cut) wrap(pc net.PacketConn) net.PacketConn { return cutConn{PacketConn: pc, c: c} }

// peer makes c drop the packets to the QUIC and data sockets of e.
func (c *cut) peer(e *env) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.to = append(c.to, e.quic.AddrPort(), e.data.AddrPort())
}

func (c *cut) drops(addr net.Addr) bool {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || !c.on.Load() {
		return false
	}
	ap := netip.AddrPortFrom(ua.AddrPort().Addr().Unmap(), ua.AddrPort().Port())
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.to, ap)
}

type cutConn struct {
	net.PacketConn
	c *cut
}

func (cc cutConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if cc.c.drops(addr) {
		return len(b), nil
	}
	return cc.PacketConn.WriteTo(b, addr)
}

// cutMesh starts relay-1 and relay-2 of one mesh with a path between them that the test can cut.
// It returns the function that cuts the path (true) or heals it (false).
func cutMesh(t *testing.T) (e1, e2 *env, setCut func(bool)) {
	t.Helper()
	c1, c2 := &cut{}, &cut{}
	e1, e2 = newMesh(t,
		envOpts{quicSend: c1.wrap, dataSend: c1.wrap},
		envOpts{quicSend: c2.wrap, dataSend: c2.wrap})
	c1.peer(e2)
	c2.peer(e1)
	return e1, e2, func(on bool) {
		c1.on.Store(on)
		c2.on.Store(on)
	}
}

// oldReport sends field 5 of SessionRequest as a revision 23 agent did: attachment id has the
// address of attachment far on relayID.
func (a *agent) oldReport(id, relayID, far, address string) {
	a.t.Helper()
	var at, rep []byte
	at = protowire.AppendString(protowire.AppendTag(at, 1, protowire.BytesType), relayID)
	at = protowire.AppendString(protowire.AppendTag(at, 2, protowire.BytesType), far)
	at = protowire.AppendString(protowire.AppendTag(at, 3, protowire.BytesType), address)
	rep = protowire.AppendString(protowire.AppendTag(rep, 1, protowire.BytesType), id)
	rep = protowire.AppendBytes(protowire.AppendTag(rep, 2, protowire.BytesType), at)
	m := &dpv1.SessionRequest{}
	m.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 5, protowire.BytesType), rep))
	require.NoError(a.t, a.st.Send(m))
}

// TestOtherRelayAddress runs agent x on relay-1 (pa, rank 0) and relay-2 (pa2, rank 1), and y on
// relay-2 (py). Relay-2 sends traffic for pa only on the trunk, also after a report of pa by x.
func TestOtherRelayAddress(t *testing.T) {
	e1, e2, setCut := cutMesh(t)
	x1 := e1.dial(t, "agent-x")
	x1.open(dpv1.Mode_MODE_QUIC)
	resX1 := x1.attachRank(0)
	pa := addr(t, resX1)
	x2 := e2.dial(t, "agent-x")
	x2.open(dpv1.Mode_MODE_QUIC)
	resX2 := x2.attachRank(1)
	pa2 := addr(t, resX2)
	y := e2.dial(t, "agent-y")
	y.open(dpv1.Mode_MODE_QUIC)
	py := addr(t, y.attach())
	agents := []*agent{x1, x2, y}
	// A build before revision 24 made a fallback for pa on relay-2 from this report.
	x2.oldReport(resX2.GetAttachmentId(), "relay-1", resX1.GetAttachmentId(), resX1.GetAddresses()[0])

	type row struct {
		name     string
		from     *agent
		src, dst netip.Addr
		to       *agent // to is the connection that gets the packet, or nil.
	}
	steps := []struct {
		name   string
		change func(t *testing.T) // change runs before the rows.
		rows   []row
	}{
		{
			name: "mesh up",
			rows: []row{
				{name: "address of relay-1 goes on the trunk", from: y, src: py, dst: pa, to: x1},
				{name: "address of relay-2 goes to its connection", from: y, src: py, dst: pa2, to: x2},
				{name: "source of relay-1 on relay-2 drops", from: x2, src: pa, dst: py},
				{name: "source of relay-2 on relay-2 passes", from: x2, src: pa2, dst: py, to: y},
			},
		},
		{
			name: "cut",
			change: func(t *testing.T) {
				setCut(true)
				assert.Equal(t, relay.MeshChange{Name: "relay-1", Down: relay.MeshLost}, e2.change(t))
				assert.Equal(t, relay.MeshChange{Name: "relay-2", Down: relay.MeshLost}, e1.change(t))
				y.waitRoute(slot, false)
			},
			rows: []row{
				{name: "address of relay-1 goes to no connection", from: y, src: py, dst: pa},
				{name: "address of relay-2 goes to its connection", from: y, src: py, dst: pa2, to: x2},
			},
		},
		{
			name: "heal",
			change: func(t *testing.T) {
				setCut(false)
				e1.waitUp(t, e2)
				e2.waitUp(t, e1)
				y.waitRoute(slot, true)
			},
			rows: []row{
				{name: "address of relay-1 goes on the trunk", from: y, src: py, dst: pa, to: x1},
			},
		},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.change != nil {
				st.change(t)
			}
			for _, r := range st.rows {
				t.Run(r.name, func(t *testing.T) {
					for _, a := range agents {
						a.drain()
					}
					srcDrops := e2.drops(t, "source")
					quiet := 300 * time.Millisecond
					if r.to != nil {
						r.from.waitDelivers(r.to, r.src, r.dst)
					} else {
						quiet = time.Second
						r.from.sendFrame(packet(r.src, r.dst, 100))
					}
					for _, a := range agents {
						if a != r.from && a != r.to {
							assert.False(t, a.gets(r.src, r.dst, quiet), "packet from %s to %s at %s", r.src, r.dst, a.name)
						}
					}
					if r.from == x2 && r.to == nil {
						assert.Equal(t, srcDrops+1, e2.drops(t, "source"), "source drops of relay-2")
					}
				})
			}
		})
	}
}
