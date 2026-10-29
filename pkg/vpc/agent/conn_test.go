// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// agentOn starts agent name with one session on each of the first sessions
// relays, and returns it with its attached sessions in rank order.
func (w *world) agentOn(t *testing.T, name string, opts agentOptions, sessions int, relays ...*testRelay) (*testAgent, []sessionRef) {
	t.Helper()
	for _, r := range relays {
		opts.relays = append(opts.relays, r.ref())
	}
	opts.sessions = sessions
	a := w.agent(t, name, relays[0], opts)
	for range min(sessions, len(relays)) {
		a.attached(t)
	}
	return a, a.sessions()
}

// ranks returns the ranks of the attached and the draining sessions of a.
func ranks(a *testAgent) (attached, draining []uint32) {
	for _, c := range a.a.Status().Connections {
		if c.Draining {
			draining = append(draining, c.Rank)
		} else {
			attached = append(attached, c.Rank)
		}
	}
	return attached, draining
}

// serveTCP answers the bytes of each TCP connection to addr:port.
func serveTCP(t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) {
	t.Helper()
	ln, err := gonet.ListenTCP(s, *fullAddr(addr, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

// roundTrip writes msg on c and reads the answer of serveTCP.
func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	roundTripIn(t, c, msg, 5*time.Second)
}

// roundTripIn is roundTrip with the wait for the answer.
func roundTripIn(t *testing.T, c net.Conn, msg string, wait time.Duration) {
	t.Helper()
	require.NoError(t, c.SetDeadline(time.Now().Add(wait)))
	_, err := c.Write([]byte(msg))
	require.NoError(t, err, msg)
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err, msg)
	assert.Equal(t, msg, string(buf))
}

// localOf returns the local address of the TCP connection c.
func localOf(c net.Conn) netip.Addr {
	return c.LocalAddr().(*net.TCPAddr).AddrPort().Addr()
}

// TestRoutesAfterAttach checks that routes from the relay before the end of the
// Attach call reach OnRoutes only after OnAttach of the session.
func TestRoutesAfterAttach(t *testing.T) {
	cases := []struct {
		name     string
		sessions int
	}{
		{name: "one session", sessions: 1},
		{name: "two sessions", sessions: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			var want []netip.Prefix
			for i, r := range []*testRelay{r1, r2, r1, r2} {
				o := w.agent(t, fmt.Sprintf("other-%d", i), r, agentOptions{})
				want = append(want, o.attached(t).prefixes...)
			}
			a, _ := w.agentOn(t, "a", agentOptions{}, tc.sessions, r1, r2)
			a.hasRoutes(t, want...)
		})
	}
}

// TestSessions checks that the agent attaches on Config.Sessions relays, with
// an address, a rank and each extra attachment on each session.
func TestSessions(t *testing.T) {
	cases := []struct {
		name             string
		sessions, relays int
		want             int
	}{
		{name: "one session of two relays", sessions: 1, relays: 2, want: 1},
		{name: "two sessions", sessions: 2, relays: 2, want: 2},
		{name: "more sessions than relays", sessions: 3, relays: 2, want: 2},
		{name: "three sessions", sessions: 3, relays: 3, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			var relays []*testRelay
			for _, id := range []string{"relay-1", "relay-2", "relay-3"}[:tc.relays] {
				relays = append(relays, w.relay(t, id))
			}
			a, rcs := w.agentOn(t, "a", agentOptions{}, tc.sessions, relays...)
			require.Len(t, rcs, tc.want)
			require.Never(t, func() bool { return len(a.attach) > 0 }, 300*time.Millisecond, 20*time.Millisecond, "one session for each relay")

			conns := a.a.Status().Connections
			require.Len(t, conns, tc.want)
			var addrs []netip.Addr
			var list []string
			for _, r := range relays {
				list = append(list, r.addr)
			}
			for i, c := range conns {
				assert.Contains(t, list, c.Relay, "a relay of the list")
				assert.False(t, slices.ContainsFunc(conns[:i], func(o ConnStatus) bool { return o.Relay == c.Relay }), "each session on its own relay")
				assert.Equal(t, uint32(i), c.Rank)
				assert.Equal(t, rcs[i].self, c.Address)
				assert.False(t, slices.Contains(addrs, c.Address), "each session has its own address")
				addrs = append(addrs, c.Address)
			}
			sameSession(t, rcs[0], a.current(), "the session with rank 0 has the default address")
			for i, c := range conns {
				deprecated := func() bool { return slices.Contains(a.events("a"), "deprecate a "+c.Address.String()) }
				if i == 0 {
					assert.False(t, deprecated(), "address of rank 0 is deprecated")
				} else {
					require.Eventually(t, deprecated, 5*time.Second, 10*time.Millisecond, "address of rank %d is deprecated", i)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			x, err := a.a.Attach(ctx, AttachmentSpec{Name: "x-1"})
			require.NoError(t, err)
			assert.Equal(t, conns[0].Relay, x.Relay, "Attach returns the attachment on the session with the lowest rank")
			lives := func() []string {
				return slices.DeleteFunc(a.events("x-1"), func(e string) bool { return !strings.HasPrefix(e, "attach ") && !strings.HasPrefix(e, "detach ") })
			}
			require.Eventually(t, func() bool { return len(lives()) == tc.want }, 5*time.Second, 10*time.Millisecond)
			var base, extra []string
			for _, at := range a.a.Attachments() {
				if at.Base {
					base = append(base, at.Relay)
				} else {
					extra = append(extra, at.Relay)
				}
				assert.True(t, at.Address.IsValid())
			}
			var want []string
			for _, c := range conns {
				want = append(want, c.Relay)
			}
			assert.Equal(t, want, base, "the attachment of Config is on each session")
			assert.Equal(t, want, extra, "the extra attachment is on each session")
			require.NoError(t, a.a.Detach(ctx, "x-1"))
			assert.Len(t, lives(), 2*tc.want, "OnDetach runs for each session")
		})
	}
}

// TestSendRule checks which relay session carries a packet: the session that has
// the source address, or else the session with the lowest rank that does not drain.
func TestSendRule(t *testing.T) {
	w := newWorld(t)
	w.mesh = true
	tap1, tap2 := &countConn{}, &countConn{}
	r1 := w.relayOn(t, "relay-1", loopback(t), tap1.wrap(loopback(t)))
	r2 := w.relayOn(t, "relay-2", loopback(t), tap2.wrap(loopback(t)))
	joinMesh(t, r1, r2)
	route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
	a, rcs := w.agentOn(t, "a", agentOptions{routes: []netip.Prefix{route}}, 2, r1, r2)
	b := w.agent(t, "b", r1, agentOptions{})
	eb := b.attached(t)
	echo(t, b.stack, eb.addr, 9000)
	a.netstack(t, a.binding(), far, false)
	a.hasRoutes(t, eb.prefixes[0])
	b.hasRoutes(t, route)
	// The PSP socket of each relay counts the PSP packets that it gets from a.
	from := unmap(a.tr.Conn.LocalAddr().(*net.UDPAddr).AddrPort())
	sent := map[string]func() int{r1.addr: func() int { return tap1.got(from) }, r2.addr: func() int { return tap2.got(from) }}
	require.Eventually(t, func() bool {
		cs := a.a.Status().Connections
		return len(cs) == 2 && cs[0].Mode == dp.Mode_MODE_PSP && cs[1].Mode == dp.Mode_MODE_PSP
	}, 10*time.Second, 10*time.Millisecond, "the sessions change to PSP mode")

	cases := []struct {
		name string
		src  netip.Addr
		want sessionRef // The session that carries the answer.
	}{
		{name: "source that no session has", src: far, want: rcs[0]},
		{name: "source of the second session", src: rcs[1].self, want: rcs[1]},
		{name: "source of the first session", src: rcs[0].self, want: rcs[0]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := sent[tc.want.addr]()
			ping(t, a.stack, tc.src, eb.addr, 9000, tc.name)
			assert.Greater(t, sent[tc.want.addr](), before, "the packet goes on the session")
		})
	}

	// When the relay of the first session drains, the second session carries
	// the packets with a source that no session has.
	drain(t, w.relayAt(rcs[0].addr))
	require.Eventually(t, func() bool { return a.current() == rcs[1] }, 5*time.Second, 10*time.Millisecond)
	before := sent[rcs[1].addr]()
	ping(t, a.stack, far, eb.addr, 9000, "after the drain")
	assert.Greater(t, sent[rcs[1].addr](), before, "the packet goes on the second session")
}

// TestDrainKeepsStream checks that a TCP stream carries data until its draining
// relay closes the session, and a new one uses the address of the other session.
func TestDrainKeepsStream(t *testing.T) {
	w, r1, r2 := meshRelays(t)
	a := w.agent(t, "a", r1, agentOptions{tcp: true, relays: []identity.Relay{r1.ref(), r2.ref()}})
	ea := a.attached(t)
	// The agent shuffles its relays, so the first session can be on either. b
	// stays on the relay that does not drain.
	prev := a.current()
	first, other := r1, r2
	if prev.addr == r2.addr {
		first, other = r2, r1
	}
	b := w.agent(t, "b", other, agentOptions{tcp: true})
	eb := b.attached(t)
	serveTCP(t, b.stack, eb.addr, 9000)
	a.hasRoutes(t, eb.prefixes[0])
	// The route of b names the other relay, so the agent attaches there too.
	moved := a.attached(t)
	sameSession(t, prev, a.current(), "the first session keeps the default address")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func() net.Conn {
		c, err := gonet.DialContextTCP(ctx, a.stack, *fullAddr(eb.addr, 9000), ipv6.ProtocolNumber)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	old := dial()
	require.Equal(t, ea.addr, localOf(old))
	roundTrip(t, old, "before the drain")

	end := drain(t, first)
	require.Eventually(t, func() bool { return a.current().addr == other.addr }, 5*time.Second, 10*time.Millisecond,
		"the session on the other relay gets the default address")
	roundTrip(t, old, "on the address of the draining relay")
	next := dial()
	assert.Equal(t, moved.addr, localOf(next), "a new connection uses the address of the relay that does not drain")
	roundTrip(t, next, "on the address of the other session")
	roundTrip(t, old, "on the address of the draining relay again")
	require.Never(t, func() bool { return len(a.attach) > 0 }, 500*time.Millisecond, 20*time.Millisecond,
		"the agent opens no session after the Drain")
	assert.Equal(t, 2, len(a.a.Status().Connections))
	roundTrip(t, old, "until the relay closes the session")

	end()
	closedByDrain(t, prev)
	roundTrip(t, next, "after the drain")
}

// TestNextRank checks that the session that the agent opens after a drain or
// a lost session gets the next rank, and that the other sessions stay.
func TestNextRank(t *testing.T) {
	cases := []struct {
		name  string
		drain bool
		// Ranks of the sessions after the new session attaches.
		attached, draining []uint32
	}{
		{name: "relay drains", drain: true, attached: []uint32{1, 2}, draining: []uint32{0}},
		{name: "session lost", attached: []uint32{1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1, r2, r3 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3")
			a, rcs := w.agentOn(t, "a", agentOptions{}, 2, r1, r2, r3)
			// Agent b stays on the relay of the first session, which gives it no
			// alternate. The relays have no mesh.
			r0 := w.relayAt(rcs[0].addr)
			b := w.agent(t, "b", r0, agentOptions{})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			ping(t, a.stack, rcs[0].self, eb.addr, 9000, "before")

			if tc.drain {
				drain(t, r0)
			} else {
				// The relay of the lost session takes no new session.
				r0.stopAccept()
				_ = rcs[0].qc.CloseWithError(0, "lost")
			}
			a.attached(t)
			attached, draining := ranks(a)
			assert.Equal(t, tc.attached, attached)
			assert.Equal(t, tc.draining, draining)
			sameSession(t, rcs[1], a.current(), "the session with the lowest rank that does not drain has the default address")
			assert.NoError(t, rcs[1].qc.Context().Err(), "the other session stays")
			require.Never(t, func() bool { return len(a.attach) > 0 }, 300*time.Millisecond, 20*time.Millisecond, "the agent opens one session")
			if tc.drain {
				ping(t, a.stack, rcs[0].self, eb.addr, 9000, "on the draining session")
			}
		})
	}
}

// TestAttachFails checks that a relay with no answer to Attach closes only its
// own session, and that the agent attaches again with backoff.
func TestAttachFails(t *testing.T) {
	w, r1, r2 := meshRelays(t)
	a := w.agent(t, "a", r1, agentOptions{})
	a.attached(t)
	prev := a.current()
	// The Attach calls of the agent get no address, so they end at their time limit.
	release := w.addrs.hold("a")
	drain(t, r1)
	require.Eventually(t, func() bool { now, _ := w.addrs.held(); return now == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { now, _ := w.addrs.held(); return now == 0 }, openTimeout+5*time.Second, 50*time.Millisecond,
		"the Attach call ends at its time limit")
	assert.NoError(t, prev.qc.Context().Err(), "the other session stays open")
	assert.Equal(t, prev, a.current())
	release()
	a.attached(t)
	assert.Equal(t, r2.addr, a.current().addr)
	assert.NoError(t, prev.qc.Context().Err(), "the other session stays open")
}

// TestAddressAgain checks that the OnDetach of an address comes before the
// next OnAttach of it, when the relay gives the next session the same address.
func TestAddressAgain(t *testing.T) {
	w := newWorld(t)
	w.addrs.sameAgain()
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	first := a.attached(t)
	_ = a.current().qc.CloseWithError(0, "test ends the session")
	second := a.attached(t)
	require.Equal(t, first.addr, second.addr, "the relay gave the same address")
	addr := first.addr.String()
	require.Equal(t, []string{"attach a " + addr, "detach a " + addr, "attach a " + addr}, a.events("a"))
}

// TestRemoteSets stops the reads of the Session stream at relay 1 while an extra
// attachment comes and goes many times. The small stream window of the relay
// makes the stream writer of session 1 wait in a send. After the reads start
// again, relay 1 gets far fewer sets than the cycles, no set of an attachment
// two times, and the newest set of each live attachment.
func TestRemoteSets(t *testing.T) {
	const cycles = 100
	cases := []struct {
		name     string
		reattach bool // The last cycle ends with an Attach.
	}{
		{name: "last cycle ends with a Detach"},
		{name: "last cycle ends with an Attach", reattach: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.streamWindow = 512
			r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
			a, ss := w.agentOn(t, "a", agentOptions{}, 2, r1, r2)
			require.Len(t, ss, 2)
			i := slices.IndexFunc(ss, func(s sessionRef) bool { return s.addr == r1.addr })
			require.GreaterOrEqual(t, i, 0, "no session on relay-1")
			tap := r1.tapOf(ss[i].qc)
			remotes := func() []*dp.RemoteAddresses {
				var out []*dp.RemoteAddresses
				for _, m := range tap.requests() {
					if rm := m.GetRemote(); rm != nil {
						out = append(out, rm)
					}
				}
				return out
			}
			// setOf returns the newest remote set of the attachment name on session 1.
			setOf := func(name string) *dp.RemoteAddresses {
				m := &dp.RemoteAddresses{}
				for _, c := range a.a.snap.Load().conns {
					for _, at := range append([]Attachment{c.base}, c.extras...) {
						switch {
						case at.Name != name:
						case c.relay == r1.addr:
							m.AttachmentId = at.ID
						default:
							m.Attachments = append(m.Attachments, &dp.RemoteAttachment{RelayId: w.relayAt(c.relay).id, AttachmentId: at.ID, Addresses: prefixStrings(at.Prefixes)})
						}
					}
				}
				return m
			}
			base := setOf("a")
			require.Len(t, base.Attachments, 1)
			require.Eventually(t, func() bool {
				return slices.ContainsFunc(remotes(), func(m *dp.RemoteAddresses) bool { return proto.Equal(base, m) })
			}, 5*time.Second, 10*time.Millisecond, "relay-1 has no set of the base attachment")
			before := len(remotes())
			resume := tap.pause()
			defer resume()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for i := range cycles {
				_, err := a.a.Attach(ctx, AttachmentSpec{Name: "x-1"})
				require.NoError(t, err, "cycle %d", i)
				require.NoError(t, a.a.Detach(ctx, "x-1"), "cycle %d", i)
			}
			live := []string{"m-1"} // An attachment after the cycles marks the end of the sends.
			if tc.reattach {
				live = append(live, "x-1")
			}
			var want []*dp.RemoteAddresses
			for _, name := range live {
				_, err := a.a.Attach(ctx, AttachmentSpec{Name: name})
				require.NoError(t, err)
				m := setOf(name)
				require.NotEmpty(t, m.AttachmentId)
				require.Len(t, m.Attachments, 1)
				want = append(want, m)
			}
			resume()
			// After the newest set of each live attachment, the writer has no change to send.
			require.Eventually(t, func() bool {
				got := remotes()
				for _, m := range want {
					if !slices.ContainsFunc(got, func(g *dp.RemoteAddresses) bool { return proto.Equal(m, g) }) {
						return false
					}
				}
				return true
			}, 10*time.Second, 10*time.Millisecond, "relay-1 has no newest set of each live attachment")
			got := remotes()[before:]
			// A writer that sends each change gives one set for each cycle.
			assert.Less(t, len(got), cycles/2, "sets after the pause")
			seen := map[string]bool{}
			for _, m := range got {
				assert.NotEqual(t, base.AttachmentId, m.AttachmentId, "a set of the base attachment again")
				assert.False(t, seen[m.AttachmentId], "a second set of %s", m.AttachmentId)
				seen[m.AttachmentId] = true
			}
		})
	}
}
