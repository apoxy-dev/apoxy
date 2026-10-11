// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The row tests have laptop on the relay of the test, and server on relay-a.
const (
	rowSrc   = "192.0.2.9:1000" // Socket of laptop.
	rowDst   = "fd00:a::1"      // Address of server, in prefixA.
	rowLocal = "fd00:3::1"      // Address of an agent of the relay of the test.
	rowHome  = "192.0.2.3:1"    // Socket of that agent.
	rowTag   = 1                // Tag of laptop: it is the first session with an attachment.
	rowTTL   = 10 * time.Minute
)

// The two ways that a mesh session ends.
var (
	meshLost    = &quic.IdleTimeoutError{}
	meshRestart = &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART)}
)

func denyAll(VPCKey, string, VPCKey, netip.Addr) bool { return false }

// rowCalls has the SPIRows calls of a relay to one member, as the member that
// the test plays gets them. It is also the stream of each call.
type rowCalls struct {
	mu      sync.Mutex
	n       int            // Number of calls.
	updates [][]*dp.SPIRow // Rows of each message since the last take.
	refuse  error          // The member has no call: it answers each open with this.
	end     error          // The member ends a call with this at its next message.
}

func (c *rowCalls) open() (rowStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	if c.refuse != nil {
		return nil, c.refuse
	}
	return c, nil
}

func (c *rowCalls) Send(u *dp.SPIRowUpdate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.end != nil {
		// The stream of a call that the member ended takes no message.
		return errors.New("stream closed")
	}
	c.updates = append(c.updates, u.GetRows())
	return nil
}

func (c *rowCalls) CloseAndRecv() (*emptypb.Empty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return nil, c.end
}

// fail sets the answers of the member to the next opens and messages.
func (c *rowCalls) fail(refuse, end error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refuse, c.end = refuse, end
}

func (c *rowCalls) count() int {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// take returns the rows of each message since the last call of it.
func (c *rowCalls) take() [][]*dp.SPIRow {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	updates := c.updates
	c.updates = nil
	return updates
}

// liveRow is the SPIRow of a row of laptop to server with the time left.
func liveRow(spi uint32, left time.Duration) *dp.SPIRow {
	return &dp.SPIRow{Vpc: ref(vpcA), SenderTag: rowTag, Spi: spi, Destination: rowDst, ExpiresIn: durationpb.New(left)}
}

// goneRow is the SPIRow of a row of laptop that ended.
func goneRow(spi uint32) *dp.SPIRow {
	return &dp.SPIRow{Vpc: ref(vpcA), SenderTag: rowTag, Spi: spi, Removed: true}
}

func diffRows(want, got [][]*dp.SPIRow) string { return cmp.Diff(want, got, protocmp.Transform()) }

// entryOf is the entry of the attachment id of subject that has prefixA, at
// generation gen. tag is the tag of the session of subject on its relay.
func entryOf(id, subject string, tag uint32, gen uint64) *dp.Presence {
	e := liveEntry(id, subject, "", tag, prefixA)
	e.Generation = gen
	return e
}

// pspOfSize returns a PSP packet with spi and an inner packet of n bytes. A
// relay does not open it, so the key is not kept.
func pspOfSize(t *testing.T, spi uint32, n int) []byte {
	t.Helper()
	aead, err := pspwire.NewAEAD(make([]byte, 16))
	require.NoError(t, err)
	inner := make([]byte, n)
	for i := range inner {
		inner[i] = byte(i)
	}
	inner[0] = 0x60
	out := make([]byte, n+pspwire.Overhead)
	m, err := pspwire.Seal(aead, pspwire.Header{SPI: spi, VNI: testVNI}, out, inner)
	require.NoError(t, err)
	return out[:m]
}

// rowRig is a trunkRig with the agent laptop, which has a tag. The test plays
// relay-a, which has server, and the SPIRows calls of the relay go to a.
type rowRig struct {
	*trunkRig
	sess   *MeshSession // Newest session of relay-a.
	pair   *trunkPair   // Pair of relay-a after that session opened.
	laptop *Session
	a      rowCalls
}

func newRowRig(t *testing.T, cfg MeshConfig) *rowRig {
	t.Helper()
	g := &rowRig{trunkRig: newTrunkRig(t, cfg)}
	g.rows = g.a.open
	g.laptop = g.agent(laptop, rowSrc, "fd00:1::/96")
	return g
}

// agent adds a session of subject at addr, with a Session call and an
// attachment that has prefix.
func (g *rowRig) agent(subject, addr, prefix string) *Session {
	g.t.Helper()
	ap := netip.MustParseAddrPort(addr)
	s := newSession(Identity{VPC: vpcA, ID: subject}, func() netip.AddrPort { return ap })
	g.r.addSession(s, time.Now())
	require.NoError(g.t, g.r.openSync(s, dp.Mode_MODE_PSP, ref(vpcA), nil))
	require.NoError(g.t, g.r.attach(s, attachment("att-"+addr, prefix)))
	return s
}

// join opens a new session of relay-a at revision rev, with its Presence
// call. relay-a gives no SA on it.
func (g *rowRig) join(rev uint32) *MeshSession {
	g.t.Helper()
	g.sess = g.open(rev)
	require.NoError(g.t, g.m.pres.accept(g.sess))
	g.deliver()
	g.requests()
	g.pair = g.tk.to("relay-a")
	return g.sess
}

// connect is join at the trunk revision. Then relay-a gives its SA and
// answers the probe, so the pair has keys in both directions and a full path.
func (g *rowRig) connect() *MeshSession {
	g.t.Helper()
	s := g.join(trunkRevision)
	g.pair = g.keyed(s)
	return s
}

// rejoin opens a new session of relay-a at revision rev from addr, and relay-a
// gives its SAs on it.
func (g *rowRig) rejoin(rev uint32, addr netip.AddrPort) {
	g.t.Helper()
	g.addr = addr
	_, err := g.offer(g.join(rev))
	require.NoError(g.t, err)
	g.pair = g.tk.to("relay-a")
	// The relay sent a probe.
	g.packets()
}

// start is connect, and then relay-a tells of the attachment x of server.
func (g *rowRig) start() *MeshSession {
	g.t.Helper()
	s := g.connect()
	g.announce(entryOf("x", server, 7, 10))
	return s
}

// announce gives the relay entries on the Presence call of relay-a.
func (g *rowRig) announce(entries ...*dp.Presence) {
	g.t.Helper()
	require.NoError(g.t, g.m.pres.apply(g.sess, &dp.PresenceUpdate{Entries: entries}))
}

// register registers SPIs of laptop to dst for ttl.
func (g *rowRig) register(dst string, ttl time.Duration, spis ...uint32) error {
	return g.r.registerSPI(g.laptop, register(vpcA, dst, ttl, spis...), time.Now())
}

func (g *rowRig) unregister(spis ...uint32) {
	g.t.Helper()
	require.NoError(g.t, g.r.unregisterSPI(g.laptop, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: spis}))
}

// rowView is what a test reads of a row.
type rowView struct {
	trunked  bool       // The row keeps the place of another relay.
	pair     *trunkPair // Pair that carries the packets of the row now, or nil.
	receiver *Session
	home     string // Relay that has the receiver. Empty is the relay of the test.
	tag      uint32 // Tag of the receiver on that relay.
}

// row returns the row of laptop with spi. ok is false with no row.
func (g *rowRig) row(spi uint32) (v rowView, ok bool) { return g.rowOf(g.laptop, spi) }

// rowOf returns the row of sender s with spi. ok is false with no row.
func (g *rowRig) rowOf(s *Session, spi uint32) (v rowView, ok bool) {
	g.r.mu.RLock()
	defer g.r.mu.RUnlock()
	w := s.rows[spi]
	if w == nil {
		return rowView{}, false
	}
	v = rowView{receiver: w.receiver, home: w.receiver.home, tag: w.receiver.tag}
	if w.trunk != nil {
		v.trunked, v.pair = true, w.trunk.pair.Load()
	}
	return v, true
}

// places returns the number of members that the trunk has a place for.
func (g *rowRig) places() int {
	g.tk.mu.Lock()
	defer g.tk.mu.Unlock()
	return len(g.tk.members)
}

// inbound returns the number of rows to the sessions of other relays.
func (g *rowRig) inbound() int {
	g.r.mu.RLock()
	defer g.r.mu.RUnlock()
	n := 0
	for _, s := range g.r.remotes {
		n += len(s.inbound)
	}
	return n
}

// verdict returns where the relay sends a packet of laptop with spi now.
func (g *rowRig) verdict(spi uint32) (netip.AddrPort, Verdict) {
	return g.r.Forward(netip.MustParseAddrPort(rowSrc), spi, 100, time.Now())
}

// packet gives the relay a PSP packet from the socket of laptop, with spi and
// an inner packet of n bytes. It returns the packet and what the relay sent.
func (g *rowRig) packet(spi uint32, n int) ([]byte, []keptPacket) {
	g.t.Helper()
	pkt := pspOfSize(g.t, spi, n)
	g.packets()
	g.handle(slices.Clone(pkt), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(rowSrc)))
	return pkt, g.packets()
}

// unchanged checks that pkts is one packet to the relay socket of relay-a with
// the bytes of sent: the relay sends the packet of an agent on with no seal.
func (g *rowRig) unchanged(sent []byte, pkts []keptPacket) {
	g.t.Helper()
	assert.Equal(g.t, []keptPacket{{sent, g.addr}}, pkts, "relay-a gets the packet of the agent with no change")
}

// revoke makes relay-a revoke the SA that it gave to the relay.
func (g *rowRig) revoke() {
	g.t.Helper()
	sa := g.pair.tx.SA(trunkLane)
	require.NotNil(g.t, sa)
	_, err := g.tk.apply(g.sess, keys.Request{Op: keys.OpRevoke, SPIs: []uint32{sa.SPI()}}, time.Now())
	require.NoError(g.t, err)
}

// away ends the session of relay-a and waits until the relay has it as down.
func (g *rowRig) away() { g.lose(g.sess, meshLost, meshDownAfter) }

// refused returns the rows that the relay refused or ended, by what had the SPI.
func (g *rowRig) refused() map[string]uint64 {
	out := map[string]uint64{}
	for i := range g.r.refusals {
		if n := g.r.refusals[i].Load(); n > 0 {
			out[rowRefusalLabels[i]] = n
		}
	}
	return out
}

// rowMember is relay-b, a second member that the test plays.
type rowMember struct {
	sess  *MeshSession
	addr  netip.AddrPort
	tx    *keys.TxPeer // SAs of the relay for packets to it.
	rx    *keys.Peer   // SAs of relay-b for packets from the relay, if it is keyed.
	calls rowCalls
}

// second adds the member relay-b with a session and its Presence call. With
// keyed, relay-b gives its SA, so the pair has keys in both directions.
func (g *rowRig) second(keyed bool) *rowMember {
	g.t.Helper()
	return g.secondAt(keyed, netip.MustParseAddrPort("192.0.2.2:6081"))
}

// secondAt is second with the relay socket of relay-b at addr.
func (g *rowRig) secondAt(keyed bool, addr netip.AddrPort) *rowMember {
	g.t.Helper()
	b := &rowMember{addr: addr}
	g.m.SetMembers([]MeshMember{{Name: "relay-a", Addr: trunkRigAddr}, {Name: "relay-b", Addr: b.addr}})
	sender, err := keys.NewSender(trunkMTU)
	require.NoError(g.t, err)
	tx := sender.NewPeer()
	b.tx = tx
	conn := newStubConn()
	b.sess = g.m.newSession(movedConn{conn, b.addr}, false)
	g.stubs[b.sess] = conn
	b.sess.client = trunkClient{
		keys: func(in *dp.KeysRequest) (*dp.KeysResponse, error) {
			req, err := keyproto.FromProto(in)
			if err != nil {
				return nil, err
			}
			refused, err := tx.Apply(req, time.Now())
			return &dp.KeysResponse{RefusedSpis: refused}, err
		},
		rows: b.calls.open,
	}
	require.True(g.t, g.m.track(b.sess))
	require.NoError(g.t, g.m.admit(b.sess, "relay-b", nil, &dp.Version{Revision: trunkRevision}, nil))
	require.NoError(g.t, g.m.pres.accept(b.sess))
	g.deliver()
	if keyed {
		table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
		require.NoError(g.t, err)
		recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
		require.NoError(g.t, err)
		b.rx, err = recv.NewPeer(keys.PeerConfig{Trunk: true, MTU: trunkMTU, Lanes: trunkLanes})
		require.NoError(g.t, err)
		req, err := b.rx.Offer(time.Now())
		require.NoError(g.t, err)
		_, err = g.tk.apply(b.sess, req, time.Now())
		require.NoError(g.t, err)
	}
	// The relay sent a probe to relay-b.
	g.packets()
	return b
}

// TestTrunkRowRegister checks RegisterSPI for an address of another relay:
// when the relay makes the rows, and which rows the other relay gets.
func TestTrunkRowRegister(t *testing.T) {
	const (
		noRow    = iota
		trunkRow // A row to relay-a whose packets go to it.
		heldRow  // A row to relay-a whose packets drop, because the relay has no trunk to relay-a.
		localRow
	)
	many := make([]uint32, 300)
	manyRows := make([]*dp.SPIRow, len(many))
	for i := range many {
		many[i] = uint32(1000 + i)
		manyRows[i] = liveRow(many[i], time.Minute)
	}
	cases := []struct {
		name string
		// link opens the session of relay-a. Nil gives the pair keys in both
		// directions.
		link  func(g *rowRig)
		setup func(t *testing.T, g *rowRig)
		from  func(g *rowRig) *Session // The caller. Nil is laptop.
		dst   string
		spis  []uint32
		code  rpc.Code
		msg   string
		rows  [][]*dp.SPIRow // Messages that relay-a gets for the call.
		opens int            // SPIRows calls that the call opens.
		row   int            // Row of the last SPI after the call.
	}{
		{
			name: "address on another relay",
			dst:  rowDst, spis: []uint32{6, 5},
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute), liveRow(6, time.Minute)}}, opens: 1,
			row: trunkRow,
		},
		{
			name: "the same row again",
			setup: func(t *testing.T, g *rowRig) {
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				time.Sleep(30 * time.Second)
			},
			dst: rowDst, spis: []uint32{5},
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}},
			row:  trunkRow,
		},
		{
			name: "more rows than one message has",
			dst:  rowDst, spis: many,
			rows: [][]*dp.SPIRow{manyRows[:256], manyRows[256:]}, opens: 1,
			row: trunkRow,
		},
		{
			name: "other relay came back at a new address",
			setup: func(t *testing.T, g *rowRig) {
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				g.end(g.sess, meshLost)
				g.rejoin(trunkRevision, netip.MustParseAddrPort("198.51.100.7:6081"))
			},
			dst: rowDst, spis: []uint32{5},
			// The row uses the pair of the new address, and the new session has its call.
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}},
			row:  trunkRow,
		},
		{
			name:  "Permit denies",
			setup: func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			dst:   rowDst, spis: []uint32{5},
			code: rpc.PermissionDenied, msg: "permit denies " + rowDst,
		},
		{
			name: "caller with no attachment",
			from: func(g *rowRig) *Session {
				return addSession(g.t, g.r, vpcA, agentID(vpcA, "spare"), "192.0.2.8:1000").Session
			},
			dst: rowDst, spis: []uint32{5},
			code: rpc.NotFound, msg: "no route to " + rowDst,
		},
		{
			name: "other relay gave no SA",
			link: func(g *rowRig) { g.join(trunkRevision) },
			dst:  rowDst, spis: []uint32{5},
			// The packet of an agent needs no trunk SA.
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}}, opens: 1,
			row: trunkRow,
		},
		{
			name:  "other relay revoked its SA",
			setup: func(_ *testing.T, g *rowRig) { g.revoke() },
			dst:   rowDst, spis: []uint32{5},
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}}, opens: 1,
			row: trunkRow,
		},
		{
			name: "other relay from before the mesh routes",
			link: func(g *rowRig) { g.join(presenceRevision) },
			dst:  rowDst, spis: []uint32{5},
			row: heldRow,
		},
		{
			name: "other relay one revision before the trunk",
			link: func(g *rowRig) { g.join(trunkRevision - 1) },
			dst:  rowDst, spis: []uint32{5},
			// It gets no row and no packet of a sender.
			row: heldRow,
		},
		{
			name:  "other relay is down",
			setup: func(_ *testing.T, g *rowRig) { g.away() },
			dst:   rowDst, spis: []uint32{5},
			// The call waits for no relay. The next session of the other relay gets the row.
			row: heldRow,
		},
		{
			name: "address with no route",
			dst:  "fd00:f::1", spis: []uint32{5},
			code: rpc.NotFound, msg: "no route to fd00:f::1",
		},
		{
			name:  "SPI of a row to another address",
			setup: func(t *testing.T, g *rowRig) { require.NoError(t, g.register(rowLocal, rowTTL, 5)) },
			dst:   rowDst, spis: []uint32{5, 6},
			code: rpc.AlreadyExists, msg: "held for another destination",
		},
		{
			name: "address on this relay",
			dst:  rowLocal, spis: []uint32{5},
			row: localRow,
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				home := g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
				if tc.link != nil {
					tc.link(g)
				} else {
					g.connect()
				}
				g.announce(entryOf("x", server, 7, 10))
				if tc.setup != nil {
					tc.setup(t, g)
				}
				g.a.take()
				calls := g.a.count()
				from := g.laptop
				if tc.from != nil {
					from = tc.from(g)
				}
				err := g.r.registerSPI(from, register(vpcA, tc.dst, time.Minute, tc.spis...), time.Now())
				require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
				if tc.msg != "" {
					assert.ErrorContains(t, err, tc.msg)
				}
				assert.Empty(t, diffRows(tc.rows, g.a.take()), "rows that relay-a gets")
				assert.Equal(t, calls+tc.opens, g.a.count(), "a session has one SPIRows call, from its first row")
				last := tc.spis[len(tc.spis)-1]
				v, ok := g.rowOf(from, last)
				to, verdict := g.verdict(last)
				switch tc.row {
				case noRow:
					assert.False(t, ok, "row of SPI %d", last)
					assert.Equal(t, DropUnknownSPI, verdict)
				case trunkRow, heldRow:
					require.True(t, ok)
					assert.True(t, v.trunked)
					assert.Equal(t, "relay-a", v.home)
					assert.EqualValues(t, 7, v.tag, "the receiver is the session of server on relay-a")
					assert.Equal(t, len(tc.spis), g.inbound())
					if tc.row == heldRow {
						assert.Equal(t, DropTrunkKeys, verdict)
						_, pkts := g.packet(last, 100)
						assert.Empty(t, pkts, "the relay sends no packet of the row")
						break
					}
					assert.Same(t, g.pair, v.pair)
					assert.Equal(t, Pass, verdict)
					assert.Equal(t, g.addr, to)
				case localRow:
					require.True(t, ok)
					assert.False(t, v.trunked)
					assert.Same(t, home, v.receiver)
					assert.Equal(t, Pass, verdict)
					assert.Equal(t, netip.MustParseAddrPort(rowHome), to)
				}
			})
		})
	}
}

// TestTrunkRowEnd checks each way that a row to another relay ends, and when
// the other relay learns of it. The row is SPI 5 of laptop to server.
func TestTrunkRowEnd(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T, g *rowRig)
		// first is the verdict for a packet of the row after end. With stays,
		// the row is there until the next sweep.
		first Verdict
		stays bool
		told  bool // relay-a gets the end of the row.
		// down tells that relay-a has no pair after the end. Its place stays until
		// the trunk SA that it gave ends, because it can still use the SPI of that SA.
		down bool
	}{
		{
			name:  "UnregisterSPI",
			end:   func(_ *testing.T, g *rowRig) { g.unregister(5) },
			first: DropUnknownSPI, told: true,
		},
		{
			name:  "expiry",
			end:   func(*testing.T, *rowRig) { time.Sleep(rowTTL + time.Nanosecond) },
			first: DropUnknownSPI, stays: true, told: true,
		},
		{
			name: "5 minutes with no packet",
			end: func(_ *testing.T, g *rowRig) {
				time.Sleep(rowIdle + time.Nanosecond)
				g.r.Sweep(time.Now())
			},
			first: DropUnknownSPI, told: true,
		},
		{
			name:  "Permit stops allowing it",
			end:   func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			first: DropUnknownSPI, told: true,
		},
		{
			name:  "the sender closes",
			end:   func(_ *testing.T, g *rowRig) { g.r.removeSession(g.laptop) },
			first: DropUnknownSource, told: true,
		},
		{
			name:  "the attachment of the receiver ends",
			end:   func(_ *testing.T, g *rowRig) { g.announce(goneAt("x", 11)) },
			first: DropUnknownSPI, told: true,
		},
		{
			name: "UnregisterSPI after the other relay is lost",
			end: func(_ *testing.T, g *rowRig) {
				g.away()
				g.unregister(5)
			},
			first: DropUnknownSPI, down: true,
		},
		{
			// The routes of a relay that stops go with its attachments.
			name: "the other relay stops",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshRestart)
				g.deliver()
			},
			first: DropUnknownSPI, down: true,
		},
		{
			name: "the other relay leaves the member set",
			end: func(_ *testing.T, g *rowRig) {
				g.m.SetMembers(nil)
				g.deliver()
			},
			first: DropUnknownSPI, down: true,
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.start()
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				require.Empty(t, diffRows([][]*dp.SPIRow{{liveRow(5, rowTTL)}}, g.a.take()))
				_, v := g.verdict(5)
				require.Equal(t, Pass, v)
				require.Equal(t, 1, g.places())

				tc.end(t, g)
				last := tc.first
				_, v = g.verdict(5)
				assert.Equal(t, tc.first, v, "verdict after the end")
				if tc.stays {
					_, ok := g.row(5)
					require.True(t, ok, "the row stays until the sweep")
					assert.Empty(t, g.a.take(), "rows before the sweep")
					g.r.Sweep(time.Now())
					last = DropUnknownSPI
				}
				_, ok := g.row(5)
				assert.False(t, ok, "row after the end")
				assert.Zero(t, g.inbound(), "rows to the sessions of other relays")
				_, v = g.verdict(5)
				assert.Equal(t, last, v, "verdict with no row")
				var want [][]*dp.SPIRow
				if tc.told {
					want = [][]*dp.SPIRow{{goneRow(5)}}
				}
				assert.Empty(t, diffRows(want, g.a.take()), "rows that relay-a gets")
				assert.Equal(t, 1, g.a.count(), "SPIRows calls")
				assert.Equal(t, tc.down, g.tk.to("relay-a") == nil, "relay-a has no pair")
				require.Equal(t, 1, g.places(), "the place stays while relay-a can have its trunk SA")
				time.Sleep(engine.DefaultLifetime + time.Nanosecond)
				g.r.tickBridge(time.Now())
				left := 1
				if tc.down {
					left = 0
				}
				assert.Equal(t, left, g.places(), "the trunk keeps a place only for a relay with a pair, a row or a trunk SA")
			})
		})
	}
}

// TestTrunkRowAway checks that a row to another relay stays while the relay has
// no trunk to it, and that its packets go again with no call of the agent.
func TestTrunkRowAway(t *testing.T) {
	const downAfter = 3 * time.Second
	moved := netip.MustParseAddrPort("198.51.100.7:6081")
	lost := func(_ *testing.T, g *rowRig) { g.away() }
	offer := func(t *testing.T, g *rowRig) {
		_, err := g.offer(g.sess)
		require.NoError(t, err)
		g.packets()
	}
	cases := []struct {
		name string
		away func(t *testing.T, g *rowRig) // Changes the trunk to relay-a.
		held bool                          // The packets of the row drop after away.
		back func(t *testing.T, g *rowRig) // Gives the relay a trunk to relay-a with keys.
		// rows has the messages that relay-a gets from away to the end of back,
		// and calls the SPIRows calls of the relay at that time.
		rows  [][]*dp.SPIRow
		calls int
	}{
		{
			name: "the other relay revokes its SA and gives a new SA",
			away: func(_ *testing.T, g *rowRig) { g.revoke() },
			back: offer, calls: 1,
		},
		{
			name: "the other relay is lost and comes back",
			away: lost, held: true,
			back: func(_ *testing.T, g *rowRig) { g.rejoin(trunkRevision, trunkRigAddr) },
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL-downAfter)}}, calls: 2,
		},
		{
			name: "the other relay is lost and comes back at a new address",
			away: lost, held: true,
			back: func(_ *testing.T, g *rowRig) { g.rejoin(trunkRevision, moved) },
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL-downAfter)}}, calls: 2,
		},
		{
			// The packets go to the new address before relay-a gives an SA there.
			name: "the other relay comes back at a new address before it is down",
			away: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.addr = moved
				g.join(trunkRevision)
			},
			back: offer,
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL)}}, calls: 2,
		},
		{
			name: "the other relay comes back from before the trunk revision, and then at this revision",
			away: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.join(trunkRevision - 1)
			},
			held: true,
			back: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.rejoin(trunkRevision, trunkRigAddr)
			},
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL)}}, calls: 2,
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.start()
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				require.Len(t, g.a.take(), 1)
				_, v := g.verdict(5)
				require.Equal(t, Pass, v)

				tc.away(t, g)
				for range 3 {
					g.r.Sweep(time.Now())
					sent, pkts := g.packet(5, 100)
					if tc.held {
						assert.Empty(t, pkts, "the relay sends no packet with no trunk to relay-a")
					} else {
						g.unchanged(sent, pkts)
					}
				}
				_, v = g.verdict(5)
				want, drops := Pass, 0
				if tc.held {
					want, drops = DropTrunkKeys, 4
				}
				assert.Equal(t, want, v)
				assert.EqualValues(t, drops, g.r.drops[dropTrunkKeys].Load())
				_, ok := g.row(5)
				require.True(t, ok, "the row stays")
				assert.Equal(t, 1, g.inbound())

				tc.back(t, g)
				g.pair = g.tk.to("relay-a")
				row, _ := g.row(5)
				assert.Same(t, g.pair, row.pair, "the row uses the pair of the member now")
				sent, pkts := g.packet(5, 100)
				g.unchanged(sent, pkts)
				assert.Empty(t, diffRows(tc.rows, g.a.take()), "rows that relay-a gets")
				assert.Equal(t, tc.calls, g.a.count(), "SPIRows calls")

				// The other relay learns of the end of the row on the session that it has now.
				g.unregister(5)
				assert.Empty(t, diffRows([][]*dp.SPIRow{{goneRow(5)}}, g.a.take()))
			})
		})
	}
}

// TestTrunkRowSession checks what a new session of the other relay gets: each
// live row with the time that it has left, and no row that ended before.
func TestTrunkRowSession(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		home := g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
		s := g.start()
		pair := g.pair
		require.NoError(t, g.register(rowDst, rowTTL, 5, 6))
		require.NoError(t, g.register(rowDst, 2*time.Minute, 7))
		require.NoError(t, g.register(rowDst, 500*time.Millisecond, 4))
		require.NoError(t, g.register(rowLocal, rowTTL, 9))
		// home is the second session with an attachment, so it has the next tag.
		require.NoError(t, g.r.registerSPI(home, register(vpcA, rowDst, rowTTL, 3), time.Now()))
		require.NotEmpty(t, g.a.take())
		// relay-b has a row of laptop too. No session of relay-a gets that row.
		b := g.second(true)
		require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{
			atGen(liveEntry("y", agentID(vpcA, "other"), "", 3, prefixB), 10),
		}}))
		require.NoError(t, g.register("fd00:b::1", rowTTL, 10))
		require.Len(t, b.calls.take(), 1)

		// The other relay is up for 3 s after its session ended: the rows work,
		// but no call carries a change.
		g.end(s, meshLost)
		time.Sleep(time.Second)
		g.unregister(6)
		require.NoError(t, g.register(rowDst, rowTTL, 8))
		assert.Empty(t, g.a.take(), "rows with no session")
		for _, spi := range []uint32{5, 7, 8} {
			to, v := g.verdict(spi)
			assert.Equal(t, Pass, v, "SPI %d", spi)
			assert.Equal(t, trunkRigAddr, to, "SPI %d", spi)
		}

		// The time of SPI 4 ended, and no sweep removed its row.
		_, ok := g.row(4)
		require.True(t, ok)

		g.join(trunkRevision)
		require.Same(t, pair, g.pair, "a new session from the same address keeps the pair")
		ofHome := liveRow(3, rowTTL-time.Second)
		ofHome.SenderTag = rowTag + 1
		want := [][]*dp.SPIRow{{
			ofHome, goneRow(4), liveRow(5, rowTTL-time.Second), liveRow(7, 2*time.Minute-time.Second), liveRow(8, rowTTL),
		}}
		assert.Empty(t, diffRows(want, g.a.take()), "rows on the new session, in the order of the SPIs")
		assert.Equal(t, 2, g.a.count(), "one SPIRows call for each session")

		// A change after the full set goes on the call of the new session.
		g.unregister(5)
		assert.Empty(t, diffRows([][]*dp.SPIRow{{goneRow(5)}}, g.a.take()))
		assert.Equal(t, 2, g.a.count())

		// A session with no row to the other relay gets no call.
		g.unregister(4, 7, 8)
		require.NoError(t, g.r.unregisterSPI(home, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{3}}))
		g.a.take()
		g.end(g.sess, meshLost)
		g.join(trunkRevision)
		assert.Empty(t, g.a.take())
		assert.Equal(t, 2, g.a.count(), "no SPIRows call with no row")
	})
}

// TestTrunkRowCallFails checks a relay whose SPIRows call fails: its rows
// work, it makes no new call on that session, and the next session gets all rows.
func TestTrunkRowCallFails(t *testing.T) {
	cases := []struct {
		name        string
		refuse, end error
	}{
		{name: "the other relay has no SPIRows call", refuse: rpc.Errorf(rpc.Unimplemented, "unknown method SPIRows")},
		{name: "the other relay ends the call", end: rpc.Errorf(rpc.Unavailable, "relay stops")},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				s := g.start()
				g.a.fail(tc.refuse, tc.end)
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				assert.Equal(t, 1, g.a.count())
				require.NoError(t, g.register(rowDst, rowTTL, 6))
				g.unregister(6)
				require.NoError(t, g.register(rowDst, rowTTL, 7))
				assert.Empty(t, g.a.take())
				assert.Equal(t, 1, g.a.count(), "no new call on the session of a call that failed")
				g.tk.mu.Lock()
				require.NotNil(t, g.pair.sess)
				kept := len(g.pair.sess.rows)
				g.tk.mu.Unlock()
				assert.Zero(t, kept, "the relay keeps no row for a call that failed")

				// The row does not wait for the answer of the other relay.
				sent, pkts := g.packet(5, 100)
				g.unchanged(sent, pkts)

				g.a.fail(nil, nil)
				g.end(s, meshLost)
				g.join(trunkRevision)
				want := [][]*dp.SPIRow{{liveRow(5, rowTTL), liveRow(7, rowTTL)}}
				assert.Empty(t, diffRows(want, g.a.take()), "rows on the next session")
				assert.Equal(t, 2, g.a.count())
			})
		})
	}
}

// TestTrunkRowMove checks a row to another relay when the address of its
// receiver gets a new owner. The row is SPI 5 of laptop to server on relay-a.
func TestTrunkRowMove(t *testing.T) {
	other := agentID(vpcA, "other")
	cases := []struct {
		name string
		// relayB adds relay-b, and keyed makes it give its trunk SA.
		relayB, keyed bool
		move          func(t *testing.T, g *rowRig, b *rowMember)
		to            string         // Relay of the receiver after the move: "local" is the relay of the test.
		tag           uint32         // Tag of the receiver on its relay.
		verdict       Verdict        // Verdict for a packet of the row after the move.
		a, b          [][]*dp.SPIRow // Messages that relay-a and relay-b get.
	}{
		{
			name: "to a new attachment of the same session",
			move: func(_ *testing.T, g *rowRig, _ *rowMember) { g.announce(entryOf("x2", server, 7, 20)) },
			to:   "relay-a", tag: 7,
		},
		{
			name: "to another session of the same relay",
			move: func(_ *testing.T, g *rowRig, _ *rowMember) { g.announce(entryOf("y", other, 8, 20)) },
			to:   "relay-a", tag: 8,
		},
		{
			name: "to an agent of this relay",
			move: func(_ *testing.T, g *rowRig, _ *rowMember) { g.agent(other, rowHome, prefixA) },
			to:   "local",
			a:    [][]*dp.SPIRow{{goneRow(5)}},
		},
		{
			name:   "to a relay that gave its trunk SA",
			relayB: true, keyed: true,
			move: func(t *testing.T, g *rowRig, b *rowMember) {
				time.Sleep(time.Minute)
				require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{entryOf("y", other, 3, 20)}}))
			},
			to: "relay-b", tag: 3,
			a: [][]*dp.SPIRow{{goneRow(5)}},
			b: [][]*dp.SPIRow{{liveRow(5, rowTTL-time.Minute)}},
		},
		{
			// The packet of an agent needs no trunk SA.
			name:   "to a relay that gave no trunk SA",
			relayB: true,
			move: func(t *testing.T, g *rowRig, b *rowMember) {
				require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{entryOf("y", other, 3, 20)}}))
			},
			to: "relay-b", tag: 3,
			a: [][]*dp.SPIRow{{goneRow(5)}},
			b: [][]*dp.SPIRow{{liveRow(5, rowTTL)}},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				g.start()
				var b *rowMember
				if tc.relayB {
					b = g.second(tc.keyed)
				}
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				require.Len(t, g.a.take(), 1)

				tc.move(t, g, b)
				assert.Empty(t, diffRows(tc.a, g.a.take()), "rows that relay-a gets")
				if b != nil {
					assert.Empty(t, diffRows(tc.b, b.calls.take()), "rows that relay-b gets")
				}
				v, ok := g.row(5)
				to, verdict := g.verdict(5)
				require.True(t, ok, "row after the move")
				assert.Equal(t, tc.verdict, verdict)
				switch tc.to {
				case "local":
					assert.False(t, v.trunked)
					assert.Empty(t, v.home)
					assert.Equal(t, netip.MustParseAddrPort(rowHome), to)
					assert.Zero(t, g.inbound())
					return
				case "relay-a":
					assert.Same(t, g.pair, v.pair)
					assert.Equal(t, trunkRigAddr, to)
				case "relay-b":
					assert.Same(t, g.tk.to("relay-b"), v.pair)
					assert.Equal(t, b.addr, to)
				}
				assert.Empty(t, g.refused())
				assert.True(t, v.trunked)
				assert.Equal(t, tc.to, v.home)
				assert.Equal(t, tc.tag, v.tag)
				assert.Equal(t, 1, g.inbound())
			})
		})
	}
}

// The SPI tests have a second sender, tablet, on the relay of the test, and other,
// an agent of relay-b with the tag 3.
const (
	spiTablet = "192.0.2.10:1000" // Socket of tablet.
	spiOnB    = "fd00:b::1"       // Address of other, in prefixB.
)

// spiRig is a rowRig with tablet, a receiver of the relay of the test, relay-a
// with server, and relay-b with other. Each of the two relays gave its trunk SA.
type spiRig struct {
	*rowRig
	tablet *Session
	b      *rowMember
}

func newSPIRig(t *testing.T, cfg MeshConfig) *spiRig {
	t.Helper()
	g := &spiRig{rowRig: newRowRig(t, cfg)}
	g.tablet = g.agent(agentID(vpcA, "tablet"), spiTablet, "fd00:2::/96")
	g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
	g.start()
	g.b = g.second(true)
	g.tellB(atGen(liveEntry("y", agentID(vpcA, "other"), "", 3, prefixB), 20))
	return g
}

// tellB gives the relay entries on the Presence call of relay-b.
func (g *spiRig) tellB(entries ...*dp.Presence) {
	g.t.Helper()
	require.NoError(g.t, g.m.pres.apply(g.b.sess, &dp.PresenceUpdate{Entries: entries}))
}

// saOfB returns the SPI of the trunk SA that relay-b gave.
func (g *spiRig) saOfB() uint32 { return g.tk.to("relay-b").tx.SA(trunkLane).SPI() }

// call is a RegisterSPI call of s for dst.
func (g *spiRig) call(s *Session, dst string, spis ...uint32) error {
	return g.r.registerSPI(s, register(vpcA, dst, rowTTL, spis...), time.Now())
}

// refusedMetric checks the text of the metric of the refused rows.
func (g *spiRig) refusedMetric(want map[string]uint64) {
	g.t.Helper()
	text := fmt.Sprintf(`
# HELP apoxy_vpc_relay_refused_rows_total Rows that the relay refused or ended because the relay of the receiver has their SPI in use, by what has the SPI.
# TYPE apoxy_vpc_relay_refused_rows_total counter
apoxy_vpc_relay_refused_rows_total{reason="row"} %d
apoxy_vpc_relay_refused_rows_total{reason="trunk_sa"} %d
`, want["row"], want["trunk_sa"])
	assert.NoError(g.t, testutil.CollectAndCompare(g.r, strings.NewReader(text), "apoxy_vpc_relay_refused_rows_total"))
}

// TestTrunkRowSPI checks which SPIs RegisterSPI refuses for an address of another
// relay. The call is from tablet for SPI 5 to server on relay-a.
func TestTrunkRowSPI(t *testing.T) {
	cases := []struct {
		name string
		// setup runs before the call. It can return other SPIs for the call.
		setup   func(t *testing.T, g *spiRig) []uint32
		dst     string            // Empty is the address of server.
		refused map[string]uint64 // Counts of the refused rows. Nil is a call that passes.
	}{
		{name: "SPI in no use"},
		{
			name: "row of another sender to the relay",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				return nil
			},
			refused: map[string]uint64{"row": 1},
		},
		{
			// A call makes all its rows or none.
			name: "row of another sender for the last SPI of the call",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				return []uint32{6, 7, 5}
			},
			refused: map[string]uint64{"row": 1},
		},
		{
			name: "row of the caller",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.tablet, rowDst, 5))
				return nil
			},
		},
		{
			// This relay finds a row by the socket of its sender and the SPI.
			name: "row of another sender to a receiver of this relay",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowLocal, 5))
				return nil
			},
		},
		{
			name: "call for a receiver of this relay, and a row of another sender to the relay",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				return nil
			},
			dst: rowLocal,
		},
		{
			name: "row of another sender to a third relay",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, spiOnB, 5))
				return nil
			},
		},
		{
			name: "row of another sender that ended",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				g.unregister(5)
				return nil
			},
		},
		{
			name: "row of a sender that closed",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				g.r.removeSession(g.laptop)
				return nil
			},
		},
		{
			name: "row that the sweep removed after its end time",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				time.Sleep(rowTTL + time.Nanosecond)
				g.r.Sweep(time.Now())
				return nil
			},
		},
		{
			name:    "trunk SA of the relay",
			setup:   func(_ *testing.T, g *spiRig) []uint32 { return []uint32{g.inner} },
			refused: map[string]uint64{"trunk_sa": 1},
		},
		{
			name:    "trunk SA of the relay for the last SPI of the call",
			setup:   func(_ *testing.T, g *spiRig) []uint32 { return []uint32{5, g.inner} },
			refused: map[string]uint64{"trunk_sa": 1},
		},
		{
			// The relay can open packets with an SA for a time after it revoked the SA.
			name: "trunk SA that the relay revoked",
			setup: func(_ *testing.T, g *spiRig) []uint32 {
				g.revoke()
				return []uint32{g.inner}
			},
			refused: map[string]uint64{"trunk_sa": 1},
		},
		{
			name: "trunk SA of a relay that is down",
			setup: func(_ *testing.T, g *spiRig) []uint32 {
				g.away()
				return []uint32{g.inner}
			},
			refused: map[string]uint64{"trunk_sa": 1},
		},
		{
			name: "trunk SA of the relay at its end time",
			setup: func(_ *testing.T, g *spiRig) []uint32 {
				time.Sleep(engine.DefaultLifetime)
				g.r.tickBridge(time.Now())
				return []uint32{g.inner}
			},
			refused: map[string]uint64{"trunk_sa": 1},
		},
		{
			name: "trunk SA of the relay after its end time",
			setup: func(_ *testing.T, g *spiRig) []uint32 {
				time.Sleep(engine.DefaultLifetime + time.Nanosecond)
				g.r.tickBridge(time.Now())
				return []uint32{g.inner}
			},
		},
		{
			name:  "trunk SA of a third relay",
			setup: func(_ *testing.T, g *spiRig) []uint32 { return []uint32{g.saOfB()} },
		},
		{
			// relay-b deletes an SA that this relay refused, so it has the SPI in no use.
			name: "call for a third relay, and a trunk SA of it that this relay refused",
			setup: func(t *testing.T, g *spiRig) []uint32 {
				req := keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: g.inner, Key: make([]byte, 16), ExpiresIn: time.Minute}}}
				refused, err := g.tk.apply(g.b.sess, req, time.Now())
				require.NoError(t, err)
				require.Equal(t, []uint32{g.inner}, refused, "the relay holds the SPI from relay-a")
				return []uint32{g.inner}
			},
			dst: spiOnB,
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newSPIRig(t, cfg)
				defer g.stop()
				spis := []uint32{5}
				if tc.setup != nil {
					if other := tc.setup(t, g); other != nil {
						spis = other
					}
				}
				dst := rowDst
				if tc.dst != "" {
					dst = tc.dst
				}
				g.a.take()
				kept, hadRow := g.rowOf(g.laptop, 5)

				err := g.call(g.tablet, dst, spis...)
				for _, spi := range spis {
					_, ok := g.rowOf(g.tablet, spi)
					assert.Equal(t, tc.refused == nil, ok, "row of SPI %#x", spi)
				}
				after, ok := g.rowOf(g.laptop, 5)
				assert.Equal(t, hadRow, ok, "the row of the other sender stays")
				assert.Equal(t, kept, after)
				g.refusedMetric(tc.refused)
				if tc.refused == nil {
					require.NoError(t, err)
					assert.Empty(t, g.refused())
					return
				}
				assert.Equal(t, rpc.AlreadyExists, rpc.CodeOf(err), "error: %v", err)
				assert.ErrorContains(t, err, `is in use at relay "relay-a"`)
				assert.Equal(t, tc.refused, g.refused())
				assert.Empty(t, g.a.take(), "relay-a gets no row of a refused call")
				// The agent gets new keys from the receiver, and calls again.
				require.NoError(t, g.call(g.tablet, dst, 0x900, 0x901))
				assert.Equal(t, tc.refused, g.refused())
			})
		})
	}
}

// TestTrunkRowSPIMove checks a row to relay-a when the address of its receiver
// goes to relay-b: the row ends if relay-b has its SPI in use.
func TestTrunkRowSPIMove(t *testing.T) {
	cases := []struct {
		name    string
		spi     func(g *spiRig) uint32 // SPI of the row of laptop. Nil is 5.
		held    bool                   // tablet has a row with the SPI to other on relay-b.
		refused string                 // What has the SPI at relay-b. Empty is nothing.
	}{
		{name: "relay with the SPI in no use"},
		{name: "relay with a row of another sender", held: true, refused: "row"},
		{name: "relay whose trunk SA has the SPI", spi: (*spiRig).saOfB, refused: "trunk_sa"},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newSPIRig(t, cfg)
				defer g.stop()
				spi := uint32(5)
				if tc.spi != nil {
					spi = tc.spi(g)
				}
				require.NoError(t, g.call(g.laptop, rowDst, spi))
				if tc.held {
					require.NoError(t, g.call(g.tablet, spiOnB, spi))
				}
				g.a.take()
				g.b.calls.take()

				// The address of server goes to an attachment of other on relay-b.
				g.tellB(atGen(liveEntry("z", agentID(vpcA, "other"), "", 3, prefixA), 30))
				gone := &dp.SPIRow{Vpc: ref(vpcA), SenderTag: rowTag, Spi: spi, Removed: true}
				assert.Empty(t, diffRows([][]*dp.SPIRow{{gone}}, g.a.take()), "rows that relay-a gets")
				v, ok := g.row(spi)
				_, verdict := g.verdict(spi)
				if tc.refused == "" {
					require.True(t, ok, "the row moves")
					assert.Equal(t, "relay-b", v.home)
					assert.Equal(t, Pass, verdict)
					assert.Len(t, g.b.calls.take(), 1, "relay-b gets the row")
					assert.Empty(t, g.refused())
					return
				}
				assert.False(t, ok, "the row ends")
				assert.Equal(t, DropUnknownSPI, verdict)
				assert.Empty(t, g.b.calls.take(), "relay-b gets no row with an SPI that it has in use")
				assert.Equal(t, map[string]uint64{tc.refused: 1}, g.refused())
				if tc.held {
					to, verdict := g.r.Forward(netip.MustParseAddrPort(spiTablet), spi, 100, time.Now())
					assert.Equal(t, Pass, verdict, "the row of the other sender stays")
					assert.Equal(t, g.b.addr, to)
				}
				// The refresh of the agent fails, and the agent gets new keys from the receiver.
				err := g.call(g.laptop, rowDst, spi)
				assert.Equal(t, rpc.AlreadyExists, rpc.CodeOf(err), "error: %v", err)
				assert.ErrorContains(t, err, `is in use at relay "relay-b"`)
				assert.Equal(t, map[string]uint64{tc.refused: 2}, g.refused())
				require.NoError(t, g.call(g.laptop, rowDst, 0x900))
				to, verdict := g.verdict(0x900)
				assert.Equal(t, Pass, verdict)
				assert.Equal(t, g.b.addr, to)
			})
		})
	}
}

// TestTrunkSASPI checks that the relay refuses a trunk SA of relay-a whose SPI a row
// to relay-a has: relay-a opens each packet with the SPI of a trunk SA.
func TestTrunkSASPI(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, g *spiRig) // Runs after laptop has the row of SPI 5 to server.
		op      keys.Op                       // Zero is an offer.
		fromB   bool                          // relay-b gives the SA.
		refused bool
	}{
		{name: "SPI of a row to the member", refused: true},
		{name: "rekey with the SPI of a row to the member", op: keys.OpRekey, refused: true},
		{name: "SPI of a row to another member", fromB: true},
		{name: "SPI of a row that ended", setup: func(_ *testing.T, g *spiRig) { g.unregister(5) }},
		{
			name: "SPI of a row to a receiver of this relay",
			setup: func(t *testing.T, g *spiRig) {
				g.unregister(5)
				require.NoError(t, g.call(g.laptop, rowLocal, 5))
			},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newSPIRig(t, cfg)
				defer g.stop()
				require.NoError(t, g.call(g.laptop, rowDst, 5))
				if tc.setup != nil {
					tc.setup(t, g)
				}
				sess, name := g.sess, "relay-a"
				if tc.fromB {
					sess, name = g.b.sess, "relay-b"
				}
				pair := g.tk.to(name)
				before := pair.tx.SA(trunkLane)
				op := keys.OpOffer
				if tc.op != 0 {
					op = tc.op
				}
				give := func(spi uint32) []uint32 {
					req := keys.Request{Op: op, SAs: []keys.SA{{SPI: spi, Key: make([]byte, 16), ExpiresIn: time.Minute}}}
					refused, err := g.tk.apply(sess, req, time.Now())
					require.NoError(t, err)
					return refused
				}

				refused := give(5)
				if !tc.refused {
					assert.Empty(t, refused)
					assert.EqualValues(t, 5, pair.tx.SA(trunkLane).SPI())
					return
				}
				assert.Equal(t, []uint32{5}, refused)
				assert.Same(t, before, pair.tx.SA(trunkLane), "the relay keeps the SA that it had")
				sent, pkts := g.packet(5, 100)
				g.unchanged(sent, pkts)
				// The SPI is in use by the row only: the member did not get to use the SA.
				err := g.call(g.tablet, rowDst, 5)
				assert.Equal(t, rpc.AlreadyExists, rpc.CodeOf(err), "error: %v", err)
				assert.Equal(t, map[string]uint64{"row": 1}, g.refused())

				// The member offers an SA with a new SPI, as an agent does.
				assert.Empty(t, give(6))
				assert.EqualValues(t, 6, pair.tx.SA(trunkLane).SPI())
				err = g.call(g.tablet, rowDst, 6)
				assert.Equal(t, rpc.AlreadyExists, rpc.CodeOf(err), "error: %v", err)
				assert.Equal(t, map[string]uint64{"row": 1, "trunk_sa": 1}, g.refused())
				// The relay forgets the SPI of the SA after the end time of the SA.
				time.Sleep(time.Minute + time.Nanosecond)
				g.r.tickBridge(time.Now())
				require.NoError(t, g.call(g.tablet, rowDst, 6))
			})
		})
	}
}

// TestTrunkRowForward checks that a PSP packet of a row to another relay goes
// to that relay with no change and no seal, or drops if too long for the path.
func TestTrunkRowForward(t *testing.T) {
	cases := []struct {
		name  string
		path  trunkPath // Result of the full-size probe of the pair.
		inner int       // Bytes of the inner packet of the agent.
		want  Verdict
	}{
		{name: "small packet", path: trunkPathFull, inner: 48, want: Pass},
		{name: "largest packet of a full path", path: trunkPathFull, inner: 1412, want: Pass},
		{name: "one byte more than a full path carries", path: trunkPathFull, inner: 1413, want: DropTrunkMTU},
		{name: "largest packet of a limited path", path: trunkPathLimited, inner: 1280, want: Pass},
		{name: "one byte more than a limited path carries", path: trunkPathLimited, inner: 1281, want: DropTrunkMTU},
		{name: "largest packet before the first probe result", path: trunkPathUnknown, inner: 1280, want: Pass},
		{name: "one byte more before the first probe result", path: trunkPathUnknown, inner: 1281, want: DropTrunkMTU},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				s := g.join(trunkRevision)
				_, err := g.offer(s)
				require.NoError(t, err)
				switch tc.path {
				case trunkPathFull:
					pkts := g.packets()
					require.Len(t, pkts, 1)
					g.answer(pkts[0])
				case trunkPathLimited:
					time.Sleep(trunkProbeWait)
					synctest.Wait()
				}
				require.Equal(t, tc.path, trunkPath(g.pair.path.Load()))
				g.announce(entryOf("x", server, 7, 10))
				require.NoError(t, g.register(rowDst, rowTTL, 5))

				sent, pkts := g.packet(5, tc.inner)
				st := g.r.SenderStats(g.laptop)
				require.Len(t, st.Lanes, 1)
				rx := g.r.AttachmentStats()[0]
				if tc.want != Pass {
					assert.Empty(t, pkts, "the relay sends no part of a packet that does not fit")
					assert.EqualValues(t, 1, st.DropTrunk)
					assert.EqualValues(t, 1, g.r.drops[dropTrunkMTU].Load())
					assert.Zero(t, st.Lanes[0].Packets)
					assert.EqualValues(t, 1, rx.RXDrops, "drops of the attachment of the sender")
					_, v := g.r.Forward(netip.MustParseAddrPort(rowSrc), 5, len(sent), time.Now())
					assert.Equal(t, tc.want, v)
					return
				}
				g.unchanged(sent, pkts)
				assert.Len(t, sent, tc.inner+pspwire.Overhead, "the one PSP overhead is from the agent")
				assert.LessOrEqual(t, len(sent), maxUDP)
				assert.Zero(t, st.DropTrunk)
				assert.EqualValues(t, 1, st.Lanes[0].Packets)
				assert.EqualValues(t, len(sent), st.Lanes[0].Bytes)
				assert.EqualValues(t, 1, rx.RXPackets)
				assert.Zero(t, rx.RXDrops)
				assert.Zero(t, g.r.MalformedDrops())
			})
		})
	}
}

// TestTrunkRowDrops checks the drops of a row to another relay. A packet that
// the trunk does not carry takes nothing from the meters.
func TestTrunkRowDrops(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		g.start()
		require.NoError(t, g.register(rowDst, rowTTL, 5))
		const fits = trunkMTU + pspwire.Overhead
		// Each meter has room for one packet.
		g.r.mu.Lock()
		g.laptop.meter = rate.NewLimiter(1, fits+1)
		g.laptop.rows[5].meter = rate.NewLimiter(1, fits+1)
		g.r.mu.Unlock()

		_, pkts := g.packet(5, trunkMTU+1)
		assert.Empty(t, pkts)
		_, pkts = g.packet(5, trunkMTU)
		assert.Len(t, pkts, 1, "the packet that did not fit took nothing from the meters")
		_, pkts = g.packet(5, trunkMTU)
		assert.Empty(t, pkts, "the meters are empty")
		st := g.r.SenderStats(g.laptop)
		assert.EqualValues(t, 1, st.DropTrunk)
		assert.EqualValues(t, 1, st.DropMeter)
		time.Sleep(time.Hour)
		require.NoError(t, g.register(rowDst, rowTTL, 5))

		// With no SA of the other relay the packets go, because the relay seals none of them.
		g.revoke()
		sent, pkts := g.packet(5, 100)
		g.unchanged(sent, pkts)
		// With no trunk to the other relay the packets drop, and the row stays.
		g.away()
		_, pkts = g.packet(5, 100)
		assert.Empty(t, pkts, "a packet with no trunk")
		assert.EqualValues(t, 2, g.r.SenderStats(g.laptop).DropTrunk)

		const want = `
# HELP apoxy_vpc_relay_dropped_packets_total Packets that the relay dropped before it forwarded them, by reason.
# TYPE apoxy_vpc_relay_dropped_packets_total counter
apoxy_vpc_relay_dropped_packets_total{reason="closed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="lane_meter"} 1
apoxy_vpc_relay_dropped_packets_total{reason="malformed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_malformed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_no_session"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_not_local"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_not_sent"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_old_member"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_old_session"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_permit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_too_large"} 0
apoxy_vpc_relay_dropped_packets_total{reason="mesh_unknown_tag"} 0
apoxy_vpc_relay_dropped_packets_total{reason="send_queue"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_expired"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_keys"} 1
apoxy_vpc_relay_dropped_packets_total{reason="trunk_mtu"} 1
apoxy_vpc_relay_dropped_packets_total{reason="trunk_no_row"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_local"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_sent"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_payload"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_permit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_replay"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_sender"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="tunnel_limit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_spi"} 0
`
		assert.NoError(t, testutil.CollectAndCompare(g.r, strings.NewReader(want), "apoxy_vpc_relay_dropped_packets_total"))
	})
}

// TestTrunkRowXDP checks when a row to another relay is an XDP row with the
// relay socket of that relay as next hop, and when it stays on the socket path.
func TestTrunkRowXDP(t *testing.T) {
	// The address that the host of the test sends from to relay-a.
	src := netip.MustParseAddr("192.0.2.200")
	const viaSocket = ""
	cases := []struct {
		name string
		own  []string // Addresses of the relay that the XDP program has.
		link func(g *rowRig)
		src  netip.Addr
		next string
	}{
		{name: "full path, and the program has the one address", own: []string{"192.0.2.200"}, src: src, next: trunkRigAddr.String()},
		{name: "an address of the other family too", own: []string{"fd00::200", "192.0.2.200"}, src: src, next: trunkRigAddr.String()},
		{name: "the same address in the mapped form", own: []string{"::ffff:192.0.2.200"}, src: src, next: trunkRigAddr.String()},
		// The program sends from the address that the agent sent to, which relay-a can not know.
		{name: "the program has a second address of the family", own: []string{"192.0.2.200", "192.0.2.201"}, src: src, next: viaSocket},
		{name: "the program has only another address", own: []string{"192.0.2.201"}, src: src, next: viaSocket},
		{name: "the program has only an address of the other family", own: []string{"fd00::200"}, src: src, next: viaSocket},
		{name: "the program has no address", src: src, next: viaSocket},
		{name: "the host has no route to the other relay", own: []string{"192.0.2.200"}, next: viaSocket},
		// The program has no length limit for one row.
		{
			name: "path with no probe result", own: []string{"192.0.2.200"}, src: src, next: viaSocket,
			link: func(g *rowRig) { g.join(trunkRevision) },
		},
		{
			name: "limited path", own: []string{"192.0.2.200"}, src: src, next: viaSocket,
			link: func(g *rowRig) {
				_, err := g.offer(g.join(trunkRevision))
				require.NoError(g.t, err)
				time.Sleep(trunkProbeWait)
				synctest.Wait()
				require.Equal(g.t, trunkPathLimited, trunkPath(g.pair.path.Load()))
			},
		},
	}
	cfg := trunkRigConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newRowRig(t, cfg)
				defer g.stop()
				f := newFakeXDP()
				for _, a := range tc.own {
					f.own = append(f.own, netip.MustParseAddr(a))
				}
				g.r.setXDP(f, time.Now())
				g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
				if tc.link != nil {
					tc.link(g)
				} else {
					g.connect()
				}
				g.announce(entryOf("x", server, 7, 10))
				g.r.mu.Lock()
				g.pair.src = tc.src
				g.r.mu.Unlock()
				require.NoError(t, g.register(rowDst, rowTTL, 5))
				require.NoError(t, g.register(rowLocal, rowTTL, 6))
				flushXDP(g.r, time.Now())
				want := map[string]string{rowSrc + "/6": rowHome}
				if tc.next != viaSocket {
					want[rowSrc+"/5"] = tc.next
				}
				assert.Equal(t, want, f.installed())
				to, v := g.verdict(5)
				assert.Equal(t, Pass, v, "the socket path has the row too")
				assert.Equal(t, trunkRigAddr, to)

				// The row goes to an agent of this relay that takes the address.
				g.agent(agentID(vpcA, "other"), "192.0.2.4:1", prefixA)
				flushXDP(g.r, time.Now())
				assert.Equal(t, map[string]string{rowSrc + "/5": "192.0.2.4:1", rowSrc + "/6": rowHome}, f.installed())
			})
		})
	}
}

// TestTrunkRowXDPPath checks that the sweep moves a row to another relay to the
// XDP program when the probe passes, and off it when the trunk goes.
func TestTrunkRowXDPPath(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		f := newFakeXDP()
		g.r.setXDP(f, time.Now())
		s := g.join(trunkRevision)
		g.r.mu.Lock()
		g.pair.src = netip.MustParseAddr("192.0.2.200")
		f.own = []netip.Addr{g.pair.src}
		g.r.mu.Unlock()
		g.announce(entryOf("x", server, 7, 10))
		require.NoError(t, g.register(rowDst, rowTTL, 5))
		flushXDP(g.r, time.Now())
		assert.Empty(t, f.installed(), "the row is on the socket path before the probe result")

		g.keyed(s)
		assert.Empty(t, f.installed(), "the row moves at the next sweep")
		g.r.Sweep(time.Now())
		assert.Equal(t, map[string]string{rowSrc + "/5": trunkRigAddr.String()}, f.installed())

		g.away()
		g.r.Sweep(time.Now())
		assert.Empty(t, f.installed(), "no XDP row with no trunk to the other relay")
		_, ok := g.row(5)
		assert.True(t, ok, "the row stays")
	})
}

// tapConn keeps the trunk packets that its socket reads from one address.
type tapConn struct {
	net.PacketConn
	from netip.AddrPort

	mu   sync.Mutex
	pkts [][]byte
}

func (c *tapConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(b)
	// The first byte of a trunk packet is its next header value, which does not
	// have the fixed bit of a QUIC packet.
	if err == nil && n > 0 && b[0]&0x40 == 0 && addrPort(from) == c.from {
		c.mu.Lock()
		c.pkts = append(c.pkts, slices.Clone(b[:n]))
		c.mu.Unlock()
	}
	return n, from, err
}

// with returns the packets of c that have the SPI spi.
func (c *tapConn) with(spi uint32) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	for _, p := range c.pkts {
		if len(p) >= pspwire.Overhead && binary.BigEndian.Uint32(p[4:8]) == spi {
			out = append(out, p)
		}
	}
	return out
}

// TestSourceTo checks the address that the host sends from to an address.
func TestSourceTo(t *testing.T) {
	cases := []struct{ name, dst, want string }{
		{name: "IPv4 loopback", dst: "127.0.0.1:6081", want: "127.0.0.1"},
		{name: "IPv6 loopback", dst: "[::1]:6081", want: "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceTo(net.UDPAddrFromAddrPort(netip.MustParseAddrPort(tc.dst)))
			if !got.IsValid() {
				t.Skip("the host has no such loopback address")
			}
			assert.Equal(t, netip.MustParseAddr(tc.want), got)
		})
	}
}

// TestTrunkRowBetweenRelays sends PSP packets between agents of two relays on loopback
// sockets, in the two directions: each relay sends the bytes of the sender with no change.
func TestTrunkRowBetweenRelays(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		max  int64 // Longest packet that the socket of relay-a sends. Zero is no limit.
		path trunkPath
		fits int // Inner bytes of the largest packet that the trunk carries.
	}{
		{name: "full path", path: trunkPathFull, fits: 1412},
		{name: "limited path", max: maxUDP - 1, path: trunkPathLimited, fits: 1280},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tap := &tapConn{}
			a, b := trunkNodes(t, func(a, b *trunkNode) {
				a.conn.max.Store(tc.max)
				tap.PacketConn, tap.from = b.conn.PacketConn, a.addr
				b.conn.PacketConn = tap
			})
			for _, d := range []struct{ n, peer *trunkNode }{{a, b}, {b, a}} {
				require.Eventually(t, func() bool { return d.n.path(d.peer.name) == tc.path },
					10*time.Second, 10*time.Millisecond, "%s: probe result for %s", d.n.name, d.peer.name)
			}

			// Each agent has a socket, and a session with an attachment on its relay.
			agent := func(n *trunkNode, subject, prefix string) (*Session, *net.UDPConn) {
				udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				t.Cleanup(func() { _ = udp.Close() })
				ap := netip.MustParseAddrPort(udp.LocalAddr().String())
				s := newSession(Identity{VPC: vpcA, ID: subject}, func() netip.AddrPort { return ap })
				n.r.addSession(s, time.Now())
				require.NoError(t, n.r.openSync(s, dp.Mode_MODE_PSP, ref(vpcA), nil))
				require.NoError(t, n.r.attach(s, attachment("att-"+prefix, prefix)))
				return s, udp
			}
			onA, sockA := agent(a, laptop, "fd00:1::/96")
			onB, sockB := agent(b, server, prefixA)
			require.Eventually(t, func() bool { return routeTable(a.r, vpcA)[prefixA] == "att-"+prefixA+"@relay-b" },
				10*time.Second, 5*time.Millisecond, "relay-a has the route of the attachment of relay-b")
			require.Eventually(t, func() bool { return routeTable(b.r, vpcA)["fd00:1::/96"] == "att-fd00:1::/96@relay-a" },
				10*time.Second, 5*time.Millisecond, "relay-b has the route of the attachment of relay-a")
			trunkSPI := a.txSPIs("relay-b")[trunkLane]
			sealed := len(tap.with(trunkSPI))
			long := tc.fits < trunkMTU

			dirs := []struct {
				name     string
				from, to *trunkNode
				snd      *Session
				src, dst *net.UDPConn
				addr     string // Address of the receiver.
				spi      uint32
			}{
				{name: "relay-a to relay-b", from: a, to: b, snd: onA, src: sockA, dst: sockB, addr: rowDst, spi: 0x501},
				// The same SPI number in the other direction is another row.
				{name: "relay-b to relay-a", from: b, to: a, snd: onB, src: sockB, dst: sockA, addr: "fd00:1::1", spi: 0x501},
			}
			for _, d := range dirs {
				require.NoError(t, d.from.r.registerSPI(d.snd, register(vpcA, d.addr, time.Minute, d.spi), time.Now()), d.name)
				d.from.r.mu.RLock()
				tag := d.snd.tag
				d.from.r.mu.RUnlock()
				require.NotZero(t, tag)
				// The call does not wait for the other relay, which drops the packets of
				// the row before it has the row.
				require.Eventually(t, func() bool {
					d.to.r.mu.RLock()
					defer d.to.r.mu.RUnlock()
					in := d.to.r.in[d.from.name]
					return in != nil && in.rows[d.spi] != nil && in.rows[d.spi].tag == tag
				}, 10*time.Second, 5*time.Millisecond, "%s: the other relay has the row with the tag of the sender", d.name)
				send := func(inner int) []byte {
					pkt := pspOfSize(t, d.spi, inner)
					_, err := d.src.WriteToUDPAddrPort(pkt, d.from.addr)
					require.NoError(t, err)
					return pkt
				}
				// has reports whether the other relay has the row of spi.
				has := func(spi uint32) bool {
					d.to.r.mu.RLock()
					defer d.to.r.mu.RUnlock()
					in := d.to.r.in[d.from.name]
					return in != nil && in.rows[spi] != nil
				}

				// A packet that is too long for a limited path goes nowhere. On a full
				// path, the path from the agent does not carry a longer packet.
				if long {
					send(tc.fits + 1)
					require.Eventually(t, func() bool { return d.from.r.SenderStats(d.snd).DropTrunk == 1 }, 5*time.Second, 5*time.Millisecond, d.name)
				}

				buf := make([]byte, maxUDP+1)
				sizes := []int{48, tc.fits}
				for i, inner := range sizes {
					sent := send(inner)
					require.NoError(t, d.dst.SetReadDeadline(time.Now().Add(5*time.Second)))
					n, src, err := d.dst.ReadFromUDPAddrPort(buf)
					require.NoError(t, err, "%s: the agent gets the packet", d.name)
					assert.Equal(t, sent, buf[:n], "%s: the packet of the agent does not change", d.name)
					assert.Equal(t, d.to.addr, src, "%s: the packet comes from the socket of the relay of the receiver", d.name)
					if d.from == a {
						got := tap.with(d.spi)
						require.Len(t, got, i+1, "one packet between the relays for one packet of the agent")
						assert.Equal(t, sent, got[i], "the packet between the relays is the packet of the agent")
					}
				}
				st := d.from.r.SenderStats(d.snd)
				require.Len(t, st.Lanes, 1)
				assert.EqualValues(t, 2, st.Lanes[0].Packets, d.name)
				assert.Equal(t, long, st.DropTrunk == 1, d.name)
				// The attachment of the receiver counts the inner packets.
				rx := d.to.r.AttachmentStats()
				require.Len(t, rx, 1)
				assert.EqualValues(t, 2, rx[0].TXPackets, d.name)
				assert.EqualValues(t, sizes[0]+sizes[1], rx[0].TXBytes, d.name)

				// A rekey of the receiver gives the sender a row with a new SPI. The
				// packets of the two SAs go, and then the row of the old SA ends.
				next := d.spi + 0x100
				require.NoError(t, d.from.r.registerSPI(d.snd, register(vpcA, d.addr, time.Minute, next), time.Now()), d.name)
				require.Eventually(t, func() bool { return has(next) }, 10*time.Second, 5*time.Millisecond, "%s: row of the new SPI", d.name)
				for _, spi := range []uint32{d.spi, next} {
					sent := pspOfSize(t, spi, 64)
					_, err := d.src.WriteToUDPAddrPort(sent, d.from.addr)
					require.NoError(t, err)
					require.NoError(t, d.dst.SetReadDeadline(time.Now().Add(5*time.Second)))
					n, _, err := d.dst.ReadFromUDPAddrPort(buf)
					require.NoError(t, err, "%s: the agent gets the packet of SPI %#x", d.name, spi)
					assert.Equal(t, sent, buf[:n], "%s: the packet of SPI %#x does not change", d.name, spi)
				}
				require.NoError(t, d.from.r.unregisterSPI(d.snd, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{d.spi}}), d.name)
				require.Eventually(t, func() bool { return !has(d.spi) }, 10*time.Second, 5*time.Millisecond, "%s: the row of the old SPI ends", d.name)
				assert.True(t, has(next), d.name)
			}
			assert.Len(t, tap.with(trunkSPI), sealed, "relay-a sealed no packet of an agent with its trunk SA")
			drops := map[string]uint64{}
			if long {
				drops["trunk_mtu"] = 1
			}
			for _, n := range []*trunkNode{a, b} {
				assert.Equal(t, drops, dropsOf(n.r), "%s drops only the packet that is too long", n.name)
			}
		})
	}
}
