// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// lostWait is the most time from the start of a black hole to the end of the direct routes on both
// sides: 7 s, and 1 s for a loaded test host.
const lostWait = 8 * time.Second

// directPair waits until ta has one pair with a direct path, and returns it.
func directPair(t *testing.T, ta *testAgent, msg string) DirectStatus {
	t.Helper()
	var d []DirectStatus
	require.Eventually(t, func() bool {
		d = ta.a.Status().Direct
		return len(d) == 1 && d[0].State == DirectDirect
	}, pairWait, 20*time.Millisecond, "%s: one direct pair", msg)
	return d[0]
}

// notDirect reports whether ta has one pair, and it has no direct path.
func notDirect(ta *testAgent) bool {
	d := ta.a.Status().Direct
	return len(d) == 1 && d[0].State != DirectDirect
}

// socket returns the address of the agent socket of ta.
func (ta *testAgent) socket() netip.AddrPort {
	return unmap(ta.tr.Conn.LocalAddr().(*net.UDPAddr).AddrPort())
}

// relayRx returns the inner packets that the relays took from each live attachment, by name.
func relayRx(relays ...*testRelay) map[string]uint64 {
	out := map[string]uint64{}
	for _, r := range relays {
		for _, st := range r.r.AttachmentStats() {
			out[st.Name] += st.RXPackets
		}
	}
	return out
}

// flat pings dst from src on ta for d, and checks that the relays take no data packet: the data
// goes direct both ways.
func flat(t *testing.T, ta *testAgent, src, dst netip.Addr, relays []*testRelay, d time.Duration) {
	t.Helper()
	before := relayRx(relays...)
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		ping(t, ta.stack, src, dst, 9000, "direct")
	}
	assert.Equal(t, before, relayRx(relays...), "the relays took data packets of %s to %s", src, dst)
}

// onRelay checks that a ping from src to dst on ta goes on the relay route.
func onRelay(t *testing.T, ta *testAgent, src, dst netip.Addr, relays []*testRelay, msg string) {
	t.Helper()
	sum := func() (n uint64) {
		for _, v := range relayRx(relays...) {
			n += v
		}
		return n
	}
	before := sum()
	ping(t, ta.stack, src, dst, 9000, msg)
	assert.Greater(t, sum(), before, "%s: the relays took the data", msg)
}

// TestDirectLost blocks the direct path of a and b: the routes go out within 7 s and the pair stays.
// The path comes back with a check that continues the BFD counters, and a second loss is the same.
func TestDirectLost(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	relays := []*testRelay{r}
	b := w.agent(t, "b", r, agentOptions{direct: true})
	// The block is between the agent sockets of a and b only.
	block := &blockConn{relay: b.socket().String()}
	a := w.agent(t, "a", r, agentOptions{direct: true, block: block})
	ea, eb := a.attached(t), b.attached(t)
	echo(t, b.stack, eb.addr, 9000)
	ping(t, a.stack, ea.addr, eb.addr, 9000, "a to b")
	first := directPair(t, a, "a")
	directPair(t, b, "b")
	// Keep the BFD packets of the first check from 8 s after the install: their state is Up, and a
	// check that starts its counters from zero again would take them.
	time.Sleep(8 * time.Second)
	block.keep.Store(true)
	time.Sleep(12 * time.Second)
	block.keep.Store(false)

	lose := func(msg string, replay bool) {
		block.out.Store(true)
		block.in.Store(true)
		if replay {
			stop := make(chan struct{})
			defer close(stop)
			go block.replay(stop, time.Second)
		}
		start := time.Now()
		require.Eventually(t, func() bool { return notDirect(a) && notDirect(b) }, lostWait, 20*time.Millisecond,
			"%s: the routes go out on both sides", msg)
		t.Logf("%s: the routes went out after %v", msg, time.Since(start).Round(time.Millisecond))
		d := a.a.Status().Direct
		require.Len(t, d, 1)
		assert.Equal(t, first.Instance, d[0].Instance, "%s: the pair stays", msg)
		assert.Equal(t, first.Key, d[0].Key, "%s: the pair stays", msg)
		assert.Empty(t, d[0].Address, "%s: no direct address", msg)
		onRelay(t, a, ea.addr, eb.addr, relays, msg)
	}
	back := func(msg string) {
		block.out.Store(false)
		block.in.Store(false)
		directPair(t, a, "a "+msg)
		directPair(t, b, "b "+msg)
	}
	lose("first loss", false)
	back("after the first return")
	time.Sleep(time.Second)
	flat(t, a, ea.addr, eb.addr, relays, time.Second)
	// b gets the packets of the first check again, and drops them: the new check continues the
	// counters, so the routes go out as with no packet.
	lose("second loss", true)
	back("after the second return")
	require.Never(t, func() bool { return notDirect(a) || notDirect(b) }, lostWait, 50*time.Millisecond,
		"the direct path stays after the return")
}

// TestPairEndRoutes ends a direct pair: the data goes on the relay route at once, and the next head
// starts a new pair that goes direct, except to a revoked peer.
func TestPairEndRoutes(t *testing.T) {
	cases := []struct {
		name    string
		end     func(w *world, b *testAgent)
		revoked bool
	}{
		{name: "peer revoked", end: func(w *world, _ *testAgent) { w.revoke("b") }, revoked: true},
		// The new cert must expire later than the cert in use.
		{name: "peer cert renews", end: func(_ *world, b *testAgent) { b.writeIdentity(25 * time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, r1, r2 := meshRelays(t)
			relays := []*testRelay{r1, r2}
			// relay-2 gets no revocation list, so the session of b stays.
			w.noList = map[string]bool{"relay-2": true}
			a := w.agent(t, "a", r1, agentOptions{direct: true})
			b := w.agent(t, "b", r2, agentOptions{direct: true, identityFile: true})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "a to b")
			first := directPair(t, a, "a")
			directPair(t, b, "b")

			tc.end(w, b)
			require.Eventually(t, func() bool {
				return !slices.ContainsFunc(a.a.Status().Direct, func(d DirectStatus) bool { return d.Key == first.Key })
			}, 5*time.Second, 20*time.Millisecond, "the pair of a ends")
			onRelay(t, a, ea.addr, eb.addr, relays, "a to b after the end")
			if tc.revoked {
				require.Len(t, b.a.Status().Connections, 1, "b keeps its session")
				// A new dial gets no channel: a refuses the cert of b in the handshake.
				for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
					require.False(t, slices.ContainsFunc(a.a.Status().Direct, func(d DirectStatus) bool { return d.Key != "" }),
						"a opened a pair with the revoked peer")
				}
				return
			}
			// Data keeps a head on the relay route at least each second, and the next one starts the new pair.
			var again DirectStatus
			require.Eventually(t, func() bool {
				ping(t, a.stack, ea.addr, eb.addr, 9000, "a to b")
				d := a.a.Status().Direct
				if len(d) == 1 && d[0].State == DirectDirect {
					again = d[0]
				}
				return again.State == DirectDirect
			}, pairWait, 200*time.Millisecond, "a goes direct with the new cert of b")
			assert.NotEqual(t, first.Key, again.Key, "the new pair has the new key of b")
			directPair(t, b, "b")
			time.Sleep(time.Second)
			flat(t, a, ea.addr, eb.addr, relays, time.Second)
		})
	}
}

// pipeNet is the binding of a pair in a process test: it gives each channel packet to the flow of
// the other pair. It drops the probes.
type pipeNet struct{ to *flowRef }

func (n *pipeNet) Send(pkts [][]byte) (int, error) {
	for _, pkt := range pkts {
		n.give(pkt)
	}
	return len(pkts), nil
}

func (n *pipeNet) SendVia(_ *psp.Peer, pkt []byte, _ netip.AddrPort) error {
	n.give(pkt)
	return nil
}

func (n *pipeNet) give(pkt []byte) {
	data := pkt[header.IPv6MinimumSize+udpHdr:]
	if len(data) > 0 && data[0] == p2p.TypeProbe {
		return
	}
	n.to.rx.Send(chanPkt{data: slices.Clone(data)})
}

func (*pipeNet) ClampMTU() int  { return 0 }
func (*pipeNet) DeviceMTU() int { return psp.DefaultMTU }

// procRoot is the root of one pair in a process test. It opens the channel, gives SAs for each
// offer and keeps each key change that the pair applies.
type procRoot struct {
	mb      *proc.Mailbox
	applied chan keys.Request
	ended   chan struct{}
}

func newProcRoot() *procRoot {
	return &procRoot{mb: proc.NewMailbox(0), applied: make(chan keys.Request, 16), ended: make(chan struct{})}
}

func (r *procRoot) run() {
	spi := uint32(0x100)
	for range r.mb.Wake() {
		for _, m := range r.mb.Take() {
			switch m := m.(type) {
			case pairOpen:
				m.p.mb.Send(openOK{})
			case offerMsg:
				spi++
				m.pr.mb.Send(rekeyMsg{attempt: m.attempt, req: testSAs(keys.OpOffer, spi)})
			case applyMsg:
				r.applied <- m.req
				m.pr.mb.Send(appliedMsg{attempt: m.attempt})
			case removePeerMsg:
				m.p.mb.Send(peerRemoved{})
			case pairEnded:
				close(r.ended)
				return
			}
		}
	}
}

// testSAs returns a key change with one SA.
func testSAs(op keys.Op, spi uint32) keys.Request {
	return keys.Request{Op: op, SAs: []keys.SA{{SPI: spi, Key: make([]byte, 16), VNI: testVNI, ExpiresIn: time.Hour}}}
}

// procAgent returns an agent with a cert of name for the pairs of a process test. It does not run.
func procAgent(t *testing.T, ca *testCA, name string) *Agent {
	t.Helper()
	cred := ca.credential(t, testProject, testVPC, name, 24*time.Hour)
	ids := identity.NewManager(filepath.Join(t.TempDir(), "cred.json"), func(context.Context) (*identity.Credential, error) {
		return cred, nil
	})
	require.NoError(t, ids.Start(context.Background()))
	tr := &quic.Transport{Conn: loopback(t)}
	t.Cleanup(func() { _ = tr.Close() })
	return New(Config{Identity: ids, Transport: tr})
}

// TestPairRekey runs two pair processes with a test root each. A rekeyMsg to one pair after the
// open makes a Keys call with the rekey, and the other pair applies it.
func TestPairRekey(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	pfxA, pfxB := netip.MustParsePrefix("fd00:1::/96"), netip.MustParsePrefix("fd00:2::/96")
	fa := flow{own: relay.OverlayAddr(pfxA), peer: relay.OverlayAddr(pfxB)}
	fb := flow{own: fa.peer, peer: fa.own}
	refA, refB := &flowRef{rx: proc.NewMailbox(pairRx)}, &flowRef{rx: proc.NewMailbox(pairRx)}
	rootA, rootB := newProcRoot(), newProcRoot()
	start := func(ag *Agent, root *procRoot, f flow, ref, other *flowRef, own netip.Prefix, dial bool) *pair {
		p := newPair(ag, root.mb, pairStart{
			flow: f, inst: rand.Uint64(), b: &pipeNet{to: other}, dial: dial, ref: ref,
			cands: &candsVal{own: []netip.Prefix{own}}, lists: &revLists{},
		})
		go root.run()
		go p.run()
		return p
	}
	pa := start(procAgent(t, ca, "a"), rootA, fa, refA, refB, pfxA, true)
	pb := start(procAgent(t, ca, "b"), rootB, fb, refB, refA, pfxB, false)

	// Each side applies the offer of the other.
	for _, r := range []*procRoot{rootA, rootB} {
		select {
		case req := <-r.applied:
			require.Equal(t, keys.OpOffer, req.Op)
		case <-time.After(pairWait):
			t.Fatal("no offer from the peer")
		}
	}
	pa.mb.Send(rekeyMsg{req: testSAs(keys.OpRekey, 0x7777)})
	select {
	case req := <-rootB.applied:
		assert.Equal(t, keys.OpRekey, req.Op)
		require.Len(t, req.SAs, 1)
		assert.Equal(t, uint32(0x7777), req.SAs[0].SPI)
	case <-time.After(pairWait):
		t.Fatal("no Keys call with the rekey")
	}

	// The end sequence ends discovery and the tasks of each pair.
	pa.mb.Send(endMsg{})
	pb.mb.Send(endMsg{})
	for _, r := range []*procRoot{rootA, rootB} {
		select {
		case <-r.ended:
		case <-time.After(pairWait):
			t.Fatal("the pair did not end")
		}
	}
}
