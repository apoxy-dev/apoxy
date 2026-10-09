// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"encoding/binary"
	"errors"
	"math"
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
	g.pair = g.tk.pair("relay-a")
	return g.sess
}

// connect is join at the row revision. Then relay-a gives its SAs and
// answers the probe, so the pair has keys in both directions and a full path.
func (g *rowRig) connect() *MeshSession {
	g.t.Helper()
	s := g.join(trunkRowsRevision)
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
	g.pair = g.tk.pair("relay-a")
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

// payload checks that pkt is a trunk packet to relay-a on the lane for PSP
// packets, and opens it as relay-a does.
func (g *rowRig) payload(pkt keptPacket) (payload []byte, tag uint32) {
	g.t.Helper()
	assert.Equal(g.t, g.addr, pkt.to)
	assert.NotEqual(g.t, g.inner, binary.BigEndian.Uint32(pkt.b[4:8]), "the packet of an agent goes on the lane with no replay window")
	payload, tag, nextHdr, err := g.rxq.ReceiveTrunk(slices.Clone(pkt.b))
	require.NoError(g.t, err)
	assert.EqualValues(g.t, pspwire.NextHdrPSP, nextHdr)
	return payload, tag
}

// revoke makes relay-a revoke the SAs of lanes that it gave to the relay. No
// lane is each lane.
func (g *rowRig) revoke(lanes ...int) {
	g.t.Helper()
	if len(lanes) == 0 {
		lanes = []int{trunkLanePSP, trunkLaneInner}
	}
	var spis []uint32
	for _, lane := range lanes {
		if sa := g.pair.tx.SA(lane); sa != nil {
			spis = append(spis, sa.SPI())
		}
	}
	_, err := g.tk.apply(g.sess, keys.Request{Op: keys.OpRevoke, SPIs: spis}, time.Now())
	require.NoError(g.t, err)
}

// rowMember is relay-b, a second member that the test plays.
type rowMember struct {
	sess  *MeshSession
	addr  netip.AddrPort
	tx    *keys.TxPeer // SAs of the relay for packets to it.
	calls rowCalls
}

// second adds the member relay-b with a session and its Presence call. With
// keyed, relay-b gives its SAs, so the pair has keys in both directions.
func (g *rowRig) second(keyed bool) *rowMember {
	g.t.Helper()
	b := &rowMember{addr: netip.MustParseAddrPort("192.0.2.2:6081")}
	g.m.SetMembers([]MeshMember{{Name: "relay-a", Addr: trunkRigAddr}, {Name: "relay-b", Addr: b.addr}})
	sender, err := keys.NewSender(trunkPayload)
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
	require.NoError(g.t, g.m.admit(b.sess, "relay-b", nil, &dp.Version{Revision: trunkRowsRevision}, nil))
	require.NoError(g.t, g.m.pres.accept(b.sess))
	g.deliver()
	if keyed {
		table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
		require.NoError(g.t, err)
		recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
		require.NoError(g.t, err)
		rx, err := recv.NewPeer(keys.PeerConfig{Trunk: true, MTU: trunkPayload, Lanes: trunkLanes, NoReplayLanes: 1})
		require.NoError(g.t, err)
		req, err := rx.Offer(time.Now())
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
		trunkRow // A row to relay-a that the trunk carries.
		heldRow  // A row to relay-a whose packets drop, because the trunk has no SA for them.
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
				g.rejoin(trunkRowsRevision, netip.MustParseAddrPort("198.51.100.7:6081"))
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
			link: func(g *rowRig) { g.join(trunkRowsRevision) },
			dst:  rowDst, spis: []uint32{5},
			// The call does not wait for the keys, and the other relay gets the row.
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}}, opens: 1,
			row: heldRow,
		},
		{
			name: "other relay from before the trunk",
			link: func(g *rowRig) { g.join(presenceRevision) },
			dst:  rowDst, spis: []uint32{5},
			row: heldRow,
		},
		{
			name: "other relay from before the SPI rows",
			link: func(g *rowRig) { g.rejoin(trunkRowsRevision-1, trunkRigAddr) },
			dst:  rowDst, spis: []uint32{5},
			// It gave its SAs, but it gets no row and no packet of a sender.
			row: heldRow,
		},
		{
			name:  "other relay revoked its SAs",
			setup: func(_ *testing.T, g *rowRig) { g.revoke() },
			dst:   rowDst, spis: []uint32{5},
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}}, opens: 1,
			row: heldRow,
		},
		{
			name:  "other relay revoked only its SA for PSP packets",
			setup: func(_ *testing.T, g *rowRig) { g.revoke(trunkLanePSP) },
			dst:   rowDst, spis: []uint32{5},
			rows: [][]*dp.SPIRow{{liveRow(5, time.Minute)}}, opens: 1,
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
		first  Verdict
		stays  bool
		told   bool // relay-a gets the end of the row.
		places int  // Members that the trunk has a place for after the end.
	}{
		{
			name:  "UnregisterSPI",
			end:   func(_ *testing.T, g *rowRig) { g.unregister(5) },
			first: DropUnknownSPI, told: true, places: 1,
		},
		{
			name:  "expiry",
			end:   func(*testing.T, *rowRig) { time.Sleep(rowTTL + time.Nanosecond) },
			first: DropUnknownSPI, stays: true, told: true, places: 1,
		},
		{
			name: "5 minutes with no packet",
			end: func(_ *testing.T, g *rowRig) {
				time.Sleep(rowIdle + time.Nanosecond)
				g.r.Sweep(time.Now())
			},
			first: DropUnknownSPI, told: true, places: 1,
		},
		{
			name:  "Permit stops allowing it",
			end:   func(_ *testing.T, g *rowRig) { g.r.SetPermit(denyAll) },
			first: DropUnknownSPI, told: true, places: 1,
		},
		{
			name:  "the sender closes",
			end:   func(_ *testing.T, g *rowRig) { g.r.removeSession(g.laptop) },
			first: DropUnknownSource, told: true, places: 1,
		},
		{
			name:  "the attachment of the receiver ends",
			end:   func(_ *testing.T, g *rowRig) { g.announce(goneAt("x", 11)) },
			first: DropUnknownSPI, told: true, places: 1,
		},
		{
			name: "UnregisterSPI after the other relay is lost",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				time.Sleep(3 * time.Second)
				g.deliver()
				g.unregister(5)
			},
			first: DropUnknownSPI,
		},
		{
			// The routes of a relay that stops go with its attachments.
			name: "the other relay stops",
			end: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshRestart)
				g.deliver()
			},
			first: DropUnknownSPI,
		},
		{
			name: "the other relay leaves the member set",
			end: func(_ *testing.T, g *rowRig) {
				g.m.SetMembers(nil)
				g.deliver()
			},
			first: DropUnknownSPI,
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
				assert.Equal(t, tc.places, g.places(), "the trunk keeps a place only for a relay with keys or rows")
			})
		})
	}
}

// TestTrunkRowKeys checks that a row to another relay stays with no trunk SA,
// and that its packets go again with the next keys, with no call of the agent.
func TestTrunkRowKeys(t *testing.T) {
	const downAfter = 3 * time.Second
	moved := netip.MustParseAddrPort("198.51.100.7:6081")
	lost := func(_ *testing.T, g *rowRig) {
		g.end(g.sess, meshLost)
		time.Sleep(downAfter)
		g.deliver()
	}
	offer := func(t *testing.T, g *rowRig) {
		_, err := g.offer(g.sess)
		require.NoError(t, err)
	}
	cases := []struct {
		name string
		away func(t *testing.T, g *rowRig) // Takes the keys of relay-a from the relay.
		back func(t *testing.T, g *rowRig) // Gives the relay keys of relay-a again.
		// rows has the messages that relay-a gets from away to the end of back,
		// and calls the SPIRows calls of the relay at that time.
		rows  [][]*dp.SPIRow
		calls int
	}{
		{
			name: "the other relay revokes its SAs and gives new SAs",
			away: func(_ *testing.T, g *rowRig) { g.revoke() },
			back: offer, calls: 1,
		},
		{
			name: "the other relay revokes only its SA for PSP packets",
			away: func(_ *testing.T, g *rowRig) { g.revoke(trunkLanePSP) },
			back: offer, calls: 1,
		},
		{
			name: "the other relay is lost and comes back",
			away: lost,
			back: func(_ *testing.T, g *rowRig) { g.rejoin(trunkRowsRevision, trunkRigAddr) },
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL-downAfter)}}, calls: 2,
		},
		{
			name: "the other relay is lost and comes back at a new address",
			away: lost,
			back: func(_ *testing.T, g *rowRig) { g.rejoin(trunkRowsRevision, moved) },
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL-downAfter)}}, calls: 2,
		},
		{
			name: "the other relay comes back at a new address before it is down",
			away: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.addr = moved
				g.join(trunkRowsRevision)
			},
			back: func(t *testing.T, g *rowRig) {
				offer(t, g)
				g.packets()
			},
			rows: [][]*dp.SPIRow{{liveRow(5, rowTTL)}}, calls: 2,
		},
		{
			name: "the other relay comes back from before the SPI rows, and then at this revision",
			away: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.rejoin(trunkRowsRevision-1, trunkRigAddr)
			},
			back: func(_ *testing.T, g *rowRig) {
				g.end(g.sess, meshLost)
				g.rejoin(trunkRowsRevision, trunkRigAddr)
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
					_, pkts := g.packet(5, 100)
					assert.Empty(t, pkts, "the relay sends no packet with no SA")
				}
				_, v = g.verdict(5)
				assert.Equal(t, DropTrunkKeys, v)
				assert.EqualValues(t, 4, g.r.drops[dropTrunkKeys].Load())
				_, ok := g.row(5)
				require.True(t, ok, "the row stays with no SA")
				assert.Equal(t, 1, g.inbound())

				tc.back(t, g)
				g.pair = g.tk.pair("relay-a")
				row, _ := g.row(5)
				assert.Same(t, g.pair, row.pair, "the row uses the pair that has the keys now")
				sent, pkts := g.packet(5, 100)
				require.Len(t, pkts, 1, "the packets of the row go again")
				payload, tag := g.payload(pkts[0])
				assert.Equal(t, sent, payload)
				assert.EqualValues(t, rowTag, tag)
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

		g.join(trunkRowsRevision)
		require.Same(t, pair, g.pair, "a new session from the same address keeps the pair")
		ofHome := liveRow(3, rowTTL-time.Second)
		ofHome.SenderTag = rowTag + 1
		want := [][]*dp.SPIRow{{
			goneRow(4), liveRow(5, rowTTL-time.Second), liveRow(7, 2*time.Minute-time.Second), liveRow(8, rowTTL), ofHome,
		}}
		assert.Empty(t, diffRows(want, g.a.take()), "rows on the new session, in the order of tag and SPI")
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
		g.join(trunkRowsRevision)
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
				require.Len(t, pkts, 1)
				payload, tag := g.payload(pkts[0])
				assert.Equal(t, sent, payload)
				assert.EqualValues(t, rowTag, tag)

				g.a.fail(nil, nil)
				g.end(s, meshLost)
				g.join(trunkRowsRevision)
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
		// relayB adds relay-b, and keyed gives it trunk keys in both directions.
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
			name:   "to a relay with trunk keys",
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
			// The row waits for the keys of relay-b, which gets it.
			name:   "to a relay with no trunk keys",
			relayB: true,
			move: func(t *testing.T, g *rowRig, b *rowMember) {
				require.NoError(t, g.m.pres.apply(b.sess, &dp.PresenceUpdate{Entries: []*dp.Presence{entryOf("y", other, 3, 20)}}))
			},
			to: "relay-b", tag: 3, verdict: DropTrunkKeys,
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
					if tc.keyed {
						assert.Same(t, g.tk.pair("relay-b"), v.pair)
						assert.Equal(t, b.addr, to)
					} else {
						assert.Nil(t, v.pair)
					}
				}
				assert.True(t, v.trunked)
				assert.Equal(t, tc.to, v.home)
				assert.Equal(t, tc.tag, v.tag)
				assert.Equal(t, 1, g.inbound())
			})
		})
	}
}

// TestTrunkRowForward checks that a PSP packet of a row to another relay goes
// whole in one trunk packet with the tag of its sender, or drops if too long.
func TestTrunkRowForward(t *testing.T) {
	cases := []struct {
		name  string
		path  trunkPath // Result of the full-size probe of the pair.
		inner int       // Bytes of the inner packet of the agent.
		want  Verdict
	}{
		{name: "small packet", path: trunkPathFull, inner: 48, want: Pass},
		{name: "largest packet of a full path", path: trunkPathFull, inner: 1372, want: Pass},
		{name: "one byte more than a full path carries", path: trunkPathFull, inner: 1373, want: DropTrunkMTU},
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
				s := g.join(trunkRowsRevision)
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
				require.Len(t, pkts, 1, "one trunk packet for one packet of the agent")
				assert.Len(t, pkts[0].b, tc.inner+2*pspwire.Overhead)
				assert.LessOrEqual(t, len(pkts[0].b), maxUDP)
				payload, tag := g.payload(pkts[0])
				assert.Equal(t, sent, payload, "the packet of the agent does not change")
				assert.EqualValues(t, rowTag, tag, "the tag is the tag of the sender on this relay")
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

// TestTrunkRowDrops checks the drops of a row to another relay with no trunk
// SA. A packet that the trunk does not carry takes nothing from the meters.
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

		// An SA with no sequence number left seals nothing.
		sa := g.pair.tx.SA(trunkLanePSP)
		for range 3 {
			_, _ = sa.ReserveN(math.MaxInt32)
		}
		_, pkts = g.packet(5, 100)
		assert.Empty(t, pkts, "a packet that the SA does not seal")
		// With no SA the packets drop, and the row stays.
		g.revoke()
		_, pkts = g.packet(5, 100)
		assert.Empty(t, pkts, "a packet with no SA")
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
apoxy_vpc_relay_dropped_packets_total{reason="trunk_keys"} 2
apoxy_vpc_relay_dropped_packets_total{reason="trunk_lane"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_mtu"} 1
apoxy_vpc_relay_dropped_packets_total{reason="trunk_no_row"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_not_local"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_permit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_sender"} 0
apoxy_vpc_relay_dropped_packets_total{reason="tunnel_limit"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_spi"} 0
`
		assert.NoError(t, testutil.CollectAndCompare(g.r, strings.NewReader(want), "apoxy_vpc_relay_dropped_packets_total"))
	})
}

// TestTrunkRowXDP checks that a row to another relay stays on the socket
// path, where the relay seals its packets, and that a row of this relay does not.
func TestTrunkRowXDP(t *testing.T) {
	cfg := trunkRigConfig(t)
	synctest.Test(t, func(t *testing.T) {
		g := newRowRig(t, cfg)
		defer g.stop()
		f := newFakeXDP()
		g.r.setXDP(f, time.Now())
		g.agent(agentID(vpcA, "home"), rowHome, "fd00:3::/96")
		g.start()
		require.NoError(t, g.register(rowDst, rowTTL, 5))
		require.NoError(t, g.register(rowLocal, rowTTL, 6))
		flushXDP(g.r, time.Now())
		assert.Equal(t, map[string]string{rowSrc + "/6": rowHome}, f.installed())
		to, v := g.verdict(5)
		assert.Equal(t, Pass, v, "the socket path has the row")
		assert.Equal(t, trunkRigAddr, to)

		// The row goes to XDP when an agent of this relay takes the address.
		g.agent(agentID(vpcA, "other"), "192.0.2.4:1", prefixA)
		flushXDP(g.r, time.Now())
		assert.Equal(t, map[string]string{rowSrc + "/5": "192.0.2.4:1", rowSrc + "/6": rowHome}, f.installed())
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
	// The first byte of a trunk packet is its next header value.
	if err == nil && n > 0 && b[0] == pspwire.NextHdrPSP && addrPort(from) == c.from {
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

// TestTrunkRowBetweenRelays sends PSP packets of an agent of relay-a to an
// agent of relay-b on loopback sockets. The agent gets each packet unchanged.
func TestTrunkRowBetweenRelays(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		max  int64 // Longest packet that the socket of relay-a sends. Zero is no limit.
		path trunkPath
		fits int // Inner bytes of the largest packet that the trunk carries.
	}{
		{name: "full path", path: trunkPathFull, fits: trunkMTU},
		{name: "limited path", max: maxUDP - 1, path: trunkPathLimited, fits: trunkLimitedMTU},
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
			snd, from := agent(a, laptop, "fd00:1::/96")
			_, to := agent(b, server, prefixA)
			require.Eventually(t, func() bool { return routeTable(a.r, vpcA)[prefixA] == "att-"+prefixA+"@relay-b" },
				10*time.Second, 5*time.Millisecond, "relay-a has the route of the attachment of relay-b")
			require.NoError(t, a.r.registerSPI(snd, register(vpcA, rowDst, time.Minute, 0x501), time.Now()))
			a.r.mu.RLock()
			tag := snd.tag
			a.r.mu.RUnlock()
			require.NotZero(t, tag)

			// The call does not wait for relay-b, which drops the packets of the row
			// before it has the row and the attachment of the sender.
			require.Eventually(t, func() bool {
				b.r.mu.RLock()
				defer b.r.mu.RUnlock()
				in := b.r.in["relay-a"]
				return in != nil && in.rows[rowKey{tag, 0x501}] != nil
			}, 10*time.Second, 5*time.Millisecond, "relay-b has the row of relay-a")
			require.Eventually(t, func() bool { return routeTable(b.r, vpcA)["fd00:1::/96"] == "att-fd00:1::/96@relay-a" },
				10*time.Second, 5*time.Millisecond, "relay-b has the attachment of the sender")

			lane := a.txSPIs("relay-b")[trunkLanePSP]
			send := func(inner int) []byte {
				pkt := pspOfSize(t, 0x501, inner)
				_, err := from.WriteToUDPAddrPort(pkt, a.addr)
				require.NoError(t, err)
				return pkt
			}

			// A packet that is too long for the trunk goes nowhere.
			send(tc.fits + 1)
			require.Eventually(t, func() bool { return a.r.SenderStats(snd).DropTrunk == 1 }, 5*time.Second, 5*time.Millisecond)
			assert.Empty(t, tap.with(lane))

			buf := make([]byte, maxUDP+1)
			sizes := []int{48, tc.fits}
			for i, inner := range sizes {
				sent := send(inner)
				require.NoError(t, to.SetReadDeadline(time.Now().Add(5*time.Second)))
				n, src, err := to.ReadFromUDPAddrPort(buf)
				require.NoError(t, err, "the agent of relay-b gets the packet")
				assert.Equal(t, sent, buf[:n], "the packet of the agent does not change")
				assert.Equal(t, b.addr, src, "the packet comes from the socket of relay-b")
				got := tap.with(lane)
				require.Len(t, got, i+1, "one trunk packet for one packet of the agent")
				assert.Len(t, got[i], inner+2*pspwire.Overhead)
			}
			st := a.r.SenderStats(snd)
			require.Len(t, st.Lanes, 1)
			assert.EqualValues(t, 2, st.Lanes[0].Packets)
			assert.EqualValues(t, 1, st.DropTrunk)
			assert.Equal(t, map[string]uint64{"trunk_mtu": 1}, dropsOf(a.r))
			assert.Empty(t, dropsOf(b.r), "relay-b drops no packet")
			// The attachment of the receiver counts the inner packets.
			rx := b.r.AttachmentStats()
			require.Len(t, rx, 1)
			assert.EqualValues(t, 2, rx[0].TXPackets)
			assert.EqualValues(t, sizes[0]+sizes[1], rx[0].TXBytes)
		})
	}
}
