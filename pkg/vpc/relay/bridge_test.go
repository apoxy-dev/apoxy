// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// testVNI is the network ID of vpcA in fakeNetworks.
const testVNI = 0x0a0b0c

// ipPacket returns an IPv4 or IPv6 packet from src to dst.
func ipPacket(src, dst netip.Addr, payload []byte) []byte {
	if src.Is4() {
		p := make([]byte, 20+len(payload))
		p[0], p[8], p[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		copy(p[12:16], src.AsSlice())
		copy(p[16:20], dst.AsSlice())
		copy(p[20:], payload)
		return p
	}
	p := make([]byte, 40+len(payload))
	p[0], p[6], p[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(len(payload)))
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	copy(p[40:], payload)
	return p
}

// pspAgent is the PSP state of a test agent in PSP mode.
type pspAgent struct {
	relay keys.Request    // Relay SAs for packets to the relay.
	tx    *engine.TxSA    // The relay SA of lane 0.
	rxq   *engine.RxQueue // Opens the packets from the relay.
	req   keys.Request    // SAs of the agent for packets from the relay.
}

// newPSPAgent takes the relay SAs in offer and makes SAs for the relay.
func newPSPAgent(t testing.TB, offer *dp.KeysRequest, now time.Time) *pspAgent {
	t.Helper()
	req, err := keyproto.FromProto(offer)
	require.NoError(t, err)
	snd, err := keys.NewSender(1280)
	require.NoError(t, err)
	tx := snd.NewPeer()
	refused, err := tx.Apply(req, now)
	require.NoError(t, err)
	require.Empty(t, refused)
	table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
	require.NoError(t, err)
	recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
	require.NoError(t, err)
	peer, err := recv.NewPeer(keys.PeerConfig{VNI: testVNI, MTU: 1280, Lanes: 1, Sources: func(netip.Addr) bool { return true }})
	require.NoError(t, err)
	mine, err := peer.Offer(now)
	require.NoError(t, err)
	return &pspAgent{relay: req, tx: tx.SA(0), rxq: table.Queue(0), req: mine}
}

// seal returns inner sealed with the relay SA.
func (p *pspAgent) seal(t testing.TB, inner []byte) []byte {
	t.Helper()
	pkt := make([]byte, len(inner)+pspwire.Overhead)
	n, err := p.tx.Seal(pkt, inner)
	require.NoError(t, err)
	return pkt[:n]
}

// end is a test agent with a relay session, an attachment and, in PSP mode,
// SAs to and from the relay.
type end struct {
	agent
	s    *Session
	st   syncStream
	addr netip.Addr
	psp  *pspAgent
}

func newEnd(t *testing.T, h *harness, ca *testCA, name string, mode dp.Mode) *end {
	t.Helper()
	a := h.mustDial(t, ca.agentCert(t, vpcA, name))
	st, _, _, offer := openMode(t, a, mode)
	res := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: name})
	claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
	require.NoError(t, err)
	e := &end{agent: a, s: h.session(t, a), st: st, addr: netip.MustParsePrefix(claims.Addresses[0]).Addr().Next()}
	if offer != nil {
		e.psp = newPSPAgent(t, offer, time.Now())
	}
	return e
}

// send sends inner to the relay: as a PSP packet in PSP mode, else as a data frame.
func (e *end) send(t *testing.T, inner []byte) {
	t.Helper()
	if e.psp != nil {
		_, err := e.tr.WriteTo(e.psp.seal(t, inner), e.qc.RemoteAddr())
		require.NoError(t, err)
		return
	}
	require.NoError(t, e.qc.SendDatagram(peerconn.EncodeData(nil, testVNI, inner)))
}

// recv returns the next inner packet from the relay and the VNI word that
// came with it.
func (e *end) recv(t *testing.T) ([]byte, uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e.psp != nil {
		buf := make([]byte, 2048)
		n, _, err := e.tr.ReadNonQUICPacket(ctx, buf)
		require.NoError(t, err)
		word := binary.BigEndian.Uint32(buf[pspwire.HeaderLen:])
		inner, _, err := e.psp.rxq.Receive(buf[:n])
		require.NoError(t, err)
		return inner, word
	}
	b, err := e.qc.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, peerconn.TypeData, b[0])
	return b[peerconn.DataLen:], binary.BigEndian.Uint32(b[1:peerconn.DataLen])
}

// giveSAs gives the relay the SAs of e for packets to e.
func (e *end) giveSAs(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := e.c.Rekey(ctx, keyproto.ToProto(e.psp.req))
	require.NoError(t, err)
	require.Empty(t, res.RefusedSpis)
}

// waitNoRoute returns the address of the next NoRoute on st.
func waitNoRoute(t *testing.T, st syncStream) string {
	t.Helper()
	for {
		if m := recv(t, st).GetNoRoute(); m != nil {
			return m.Address
		}
	}
}

// TestBridge sends data between QUIC-mode and PSP-mode agents through the relay.
func TestBridge(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	q1 := newEnd(t, h, ca, "q1", dp.Mode_MODE_QUIC)
	q2 := newEnd(t, h, ca, "q2", dp.Mode_MODE_QUIC)
	p1 := newEnd(t, h, ca, "p1", dp.Mode_MODE_PSP)
	p1.giveSAs(t)

	const quicWord, pspWord = testVNI << 8, testVNI<<8 | uint32(pspwire.FlagSeq)
	cases := []struct {
		name     string
		from, to *end
		word     uint32 // VNI word that the receiver gets.
	}{
		{"QUIC to QUIC", q1, q2, quicWord},
		{"QUIC to QUIC, back", q2, q1, quicWord},
		{"QUIC to PSP", q1, p1, pspWord},
		{"PSP to QUIC", p1, q2, pspWord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := h.r.SenderStats(tc.from.s).DataSent
			inner := ipPacket(tc.from.addr, tc.to.addr, []byte(tc.name))
			tc.from.send(t, inner)
			got, word := tc.to.recv(t)
			assert.Equal(t, inner, got)
			assert.Equal(t, tc.word, word)
			// The relay counts the packet after the send returns.
			require.Eventually(t, func() bool {
				return h.r.SenderStats(tc.from.s).DataSent == before+1
			}, 5*time.Second, time.Millisecond)
		})
	}
}

// TestBridgeDrops checks the drops of the bridge. A drop counts on the
// sender, and the relay sends nothing.
func TestBridgeDrops(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	q1 := newEnd(t, h, ca, "q1", dp.Mode_MODE_QUIC)
	q2 := newEnd(t, h, ca, "q2", dp.Mode_MODE_QUIC)
	p1 := newEnd(t, h, ca, "p1", dp.Mode_MODE_PSP)
	p2 := newEnd(t, h, ca, "p2", dp.Mode_MODE_PSP) // It gives the relay no SAs.
	p1.giveSAs(t)
	nowhere := netip.MustParseAddr("fd00:99::1")

	sendRaw := func(e *end, b []byte) func(t *testing.T) {
		return func(t *testing.T) { require.NoError(t, e.qc.SendDatagram(b)) }
	}
	sendPSP := func(e *end, pkt []byte) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := e.tr.WriteTo(pkt, e.qc.RemoteAddr())
			require.NoError(t, err)
		}
	}
	replayed := p1.psp.seal(t, ipPacket(p1.addr, q1.addr, []byte("once")))
	sa := p1.psp.relay.SAs[0]
	otherVNI, err := engine.NewTxSA(sa.SPI, sa.Key, testVNI+1, 1280)
	require.NoError(t, err)
	wrongVNI := make([]byte, 2048)
	n, err := otherVNI.Seal(wrongVNI, ipPacket(p1.addr, q1.addr, []byte("vni")))
	require.NoError(t, err)

	cases := []struct {
		name    string
		from    *end
		send    func(t *testing.T)
		sent    uint64 // Packets that the relay sends first.
		noRoute netip.Addr
	}{
		{name: "data frame with another VNI", from: q1,
			send: sendRaw(q1, peerconn.EncodeData(nil, testVNI+1, ipPacket(q1.addr, q2.addr, nil)))},
		{name: "data frame with the source of another agent", from: q1,
			send: sendRaw(q1, peerconn.EncodeData(nil, testVNI, ipPacket(q2.addr, q2.addr, nil)))},
		{name: "short data frame", from: q1, send: sendRaw(q1, []byte{peerconn.TypeData, 0, 0})},
		{name: "data frame with no route", from: q1,
			send: sendRaw(q1, peerconn.EncodeData(nil, testVNI, ipPacket(q1.addr, nowhere, nil))), noRoute: nowhere},
		{name: "data frame to a PSP agent with no SAs for the relay", from: q1,
			send: sendRaw(q1, peerconn.EncodeData(nil, testVNI, ipPacket(q1.addr, p2.addr, nil)))},
		{name: "data frame from a PSP-mode session", from: p1,
			send: sendRaw(p1, peerconn.EncodeData(nil, testVNI, ipPacket(p1.addr, q1.addr, nil)))},
		{name: "PSP replay", from: p1, sent: 1, send: func(t *testing.T) {
			sendPSP(p1, replayed)(t)
			sendPSP(p1, replayed)(t)
		}},
		{name: "PSP with the source of another agent", from: p1,
			send: sendPSP(p1, p1.psp.seal(t, ipPacket(q1.addr, q2.addr, nil)))},
		{name: "PSP with another VNI", from: p1, send: sendPSP(p1, wrongVNI[:n])},
		{name: "PSP to a PSP agent", from: p1, send: sendPSP(p1, p1.psp.seal(t, ipPacket(p1.addr, p2.addr, nil)))},
		{name: "PSP with no route", from: p1,
			send: sendPSP(p1, p1.psp.seal(t, ipPacket(p1.addr, nowhere, nil))), noRoute: nowhere},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := h.r.SenderStats(tc.from.s)
			tc.send(t)
			require.Eventually(t, func() bool {
				return h.r.SenderStats(tc.from.s).DataDrops == before.DataDrops+1
			}, 5*time.Second, 5*time.Millisecond)
			assert.Equal(t, before.DataSent+tc.sent, h.r.SenderStats(tc.from.s).DataSent)
			if tc.noRoute.IsValid() {
				assert.Equal(t, tc.noRoute.String(), waitNoRoute(t, tc.from.st))
			}
		})
	}
}

// TestRekey checks the SAs that agents give the relay. The cases run in order.
func TestRekey(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	p1 := newEnd(t, h, ca, "p1", dp.Mode_MODE_PSP)
	p2 := newEnd(t, h, ca, "p2", dp.Mode_MODE_PSP)
	q1 := newEnd(t, h, ca, "q1", dp.Mode_MODE_QUIC)
	idle := h.mustDial(t, ca.agentCert(t, vpcA, "idle"))
	offer := func(spi, vni uint32) *dp.KeysRequest {
		return keyproto.ToProto(keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: spi, Key: make([]byte, 16), VNI: vni, ExpiresIn: time.Minute}}})
	}

	cases := []struct {
		name    string
		from    agent
		req     *dp.KeysRequest
		code    rpc.Code
		refused []uint32
	}{
		{"offer", p1.agent, offer(0x1001, testVNI), rpc.OK, nil},
		{"SPI that another agent gave", p2.agent, offer(0x1001, testVNI), rpc.OK, []uint32{0x1001}},
		{"VNI of another VPC", p1.agent, offer(0x1002, testVNI+1), rpc.InvalidArgument, nil},
		{"no op", p1.agent, &dp.KeysRequest{}, rpc.InvalidArgument, nil},
		{"QUIC-mode session", q1.agent, offer(0x1003, testVNI), rpc.FailedPrecondition, nil},
		{"no Session call", idle, offer(0x1004, testVNI), rpc.FailedPrecondition, nil},
		{"revoke", p1.agent, keyproto.ToProto(keys.Request{Op: keys.OpRevoke, SPIs: []uint32{0x1001}}), rpc.OK, nil},
		{"SPI after the revoke", p2.agent, offer(0x1001, testVNI), rpc.OK, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			res, err := tc.from.c.Rekey(ctx, tc.req)
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			if err == nil {
				assert.Equal(t, tc.refused, res.RefusedSpis)
			}
		})
	}
}

// discardConn drops all writes. Reads wait until Close.
type discardConn struct {
	once sync.Once
	done chan struct{}
}

func newDiscardConn() *discardConn { return &discardConn{done: make(chan struct{})} }

func (c *discardConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.done
	return 0, nil, net.ErrClosed
}
func (c *discardConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *discardConn) Close() error                              { c.once.Do(func() { close(c.done) }); return nil }
func (c *discardConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (c *discardConn) SetDeadline(time.Time) error      { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error  { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error { return nil }

// localRouter returns a router whose bridge writes to a discardConn, and the
// PSP packet handler.
func localRouter(tb testing.TB) (*Router, func([]byte, net.Addr)) {
	tb.Helper()
	conn := newDiscardConn()
	tr := &quic.Transport{Conn: conn}
	tb.Cleanup(func() {
		_ = conn.Close()
		_ = tr.Close()
	})
	r := NewRouter(nil, Config{})
	return r, r.PacketHandler(tr)
}

// localSession adds a session at addr with prefix and a Session call in mode.
// Its datagrams go nowhere.
func localSession(tb testing.TB, r *Router, name, addr, prefix string, mode dp.Mode) *Session {
	tb.Helper()
	ap := netip.MustParseAddrPort(addr)
	s := newSession(Identity{VPC: vpcA, ID: name}, func() netip.AddrPort { return ap })
	s.sendDatagram = func([]byte) error { return nil }
	r.addSession(s, t0)
	require.NoError(tb, r.AddRoute(s, netip.MustParsePrefix(prefix), "att-"+name))
	require.NoError(tb, r.openSync(s, mode, ref(vpcA)))
	return s
}

func spisOf(m *dp.SessionResponse) []uint32 {
	var spis []uint32
	for _, sa := range m.GetRekey().GetOffer().GetSas() {
		spis = append(spis, sa.GetSpi())
	}
	for _, sa := range m.GetRekey().GetRekey().GetSas() {
		spis = append(spis, sa.GetSpi())
	}
	return spis
}

// TestDataShards checks that data frames to a session with shards go on the
// shard of their flow, and that data frames on a shard count as its owner.
func TestDataShards(t *testing.T) {
	r, _ := localRouter(t)
	src := localSession(t, r, "src", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_QUIC)
	dst := localSession(t, r, "dst", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_QUIC)
	// The connections that got each flow, by source port.
	got := map[int][]*Session{}
	count := func(s *Session) {
		s.sendDatagram = func(b []byte) error {
			port := int(binary.BigEndian.Uint16(b[peerconn.DataLen+40:]))
			got[port] = append(got[port], s)
			return nil
		}
	}
	count(dst)
	shardOf := func(owner *Session, att string, i uint32) *Session {
		t.Helper()
		sh := newSession(owner.id, func() netip.AddrPort { return netip.AddrPort{} })
		r.addSession(sh, t0)
		_, _, err := r.joinShard(sh, att, i)
		require.NoError(t, err)
		return sh
	}
	require.NoError(t, r.attach(src, &Attachment{ID: "att-src"}))
	require.NoError(t, r.attach(dst, &Attachment{ID: "att-dst"}))
	shards := []*Session{shardOf(dst, "att-dst", 1), shardOf(dst, "att-dst", 3)}
	for _, sh := range shards {
		count(sh)
	}
	in := shardOf(src, "att-src", 2)

	frame := func(port int) []byte {
		payload := []byte{byte(port >> 8), byte(port), 0, 53}
		return peerconn.EncodeData(nil, testVNI, ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1"), payload))
	}
	buf := make([]byte, maxUDP)
	const flows = 64
	for port := range flows {
		// A flow uses one connection. The frames come on the session or on a shard.
		require.True(t, r.forwardData(src, frame(port), buf, t0))
		require.True(t, r.forwardData(in, frame(port), buf, t0))
	}
	assert.Equal(t, uint64(2*flows), r.SenderStats(src).DataSent)
	assert.Zero(t, r.SenderStats(in).DataSent)
	used := map[*Session]bool{}
	for port, conns := range got {
		require.Len(t, conns, 2)
		assert.Same(t, conns[0], conns[1], "flow %d is on two connections", port)
		used[conns[0]] = true
	}
	assert.Len(t, used, 3, "the flows use the session and its two shards")

	// When the shards go, their flows go to the session.
	clear(got)
	for _, sh := range shards {
		r.leaveShard(sh)
	}
	for port := range flows {
		require.True(t, r.forwardData(src, frame(port), buf, t0))
	}
	for port, conns := range got {
		assert.Equal(t, []*Session{dst}, conns, "flow %d", port)
	}
}

// TestRelaySAs checks the life of the relay SAs and their rows.
func TestRelaySAs(t *testing.T) {
	r, _ := localRouter(t)
	br := r.bridge.Load()
	require.NotNil(t, br)
	p := localSession(t, r, "p", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_PSP)
	m, err := r.offer(p, Network{ID: testVNI, MTU: 1280}, t0)
	require.NoError(t, err)
	first := spisOf(m)
	require.Len(t, first, 1)
	pass := func(spi uint32, now time.Time) bool {
		dst, v := r.Forward(netip.MustParseAddrPort("192.0.2.1:1"), spi, 100, now)
		return v == Pass && !dst.IsValid()
	}
	tick := func(now time.Time) {
		r.Sweep(now)
		r.tickBridge(now)
	}
	assert.True(t, pass(first[0], t0))

	// An idle row of a live SA stays.
	now := t0.Add(rowIdle + time.Minute)
	tick(now)
	assert.True(t, pass(first[0], now))

	// The agent gets new SAs before the old ones end. Both work for a quarter
	// of the lifetime.
	now = t0.Add(br.lifetime * 3 / 4)
	tick(now)
	msgs := r.takeSync(p)
	i := slices.IndexFunc(msgs, func(m *dp.SessionResponse) bool { return m.GetRekey() != nil })
	require.GreaterOrEqual(t, i, 0, "no Rekey in %v", msgs)
	second := spisOf(msgs[i])
	require.Len(t, second, 1)
	assert.NotEqual(t, first, second)
	assert.True(t, pass(first[0], now))
	assert.True(t, pass(second[0], now))
	now = now.Add(br.lifetime / 4)
	tick(now)
	assert.False(t, pass(first[0], now))
	assert.True(t, pass(second[0], now))

	// The SAs go with the session.
	r.removeSession(p)
	r.closeBridge(p)
	assert.Empty(t, br.senders)
	assert.Empty(t, br.peers)
	assert.Empty(t, br.local.inbound)
}

// BenchmarkForwardData measures one data frame from a QUIC-mode session:
// the checks, the next hop and the send to a session that drops it.
func BenchmarkForwardData(b *testing.B) {
	for _, mode := range []dp.Mode{dp.Mode_MODE_QUIC, dp.Mode_MODE_PSP} {
		b.Run("to "+mode.String(), func(b *testing.B) {
			r, _ := localRouter(b)
			q := localSession(b, r, "q", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_QUIC)
			d := localSession(b, r, "d", "192.0.2.2:1", "fd00:2::/96", mode)
			if mode == dp.Mode_MODE_PSP {
				sa := keys.SA{SPI: 0x1001, Key: make([]byte, 16), VNI: testVNI, ExpiresIn: time.Hour}
				_, err := r.rekey(d, keys.Request{Op: keys.OpOffer, SAs: []keys.SA{sa}}, t0)
				require.NoError(b, err)
			}
			frame := peerconn.EncodeData(nil, testVNI, ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1"), make([]byte, 1200)))
			buf := make([]byte, maxUDP)
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			for b.Loop() {
				if !r.forwardData(q, frame, buf, t0) {
					b.Fatal("frame dropped")
				}
			}
		})
	}
}

// BenchmarkReceivePSP measures one PSP packet to the relay from a PSP-mode
// session, from the packet handler to the send to a QUIC-mode session. It
// includes the seal of the packet by the agent.
func BenchmarkReceivePSP(b *testing.B) {
	r, handle := localRouter(b)
	p := localSession(b, r, "p", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_PSP)
	localSession(b, r, "q", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_QUIC)
	// The packet handler uses the wall clock, so the SAs must too.
	now := time.Now()
	m, err := r.offer(p, Network{ID: testVNI, MTU: 1280}, now)
	require.NoError(b, err)
	agent := newPSPAgent(b, m.GetRekey(), now)
	inner := ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1"), make([]byte, 1200))
	from := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:1"))
	pkt := make([]byte, maxUDP)
	b.SetBytes(int64(len(inner)))
	b.ReportAllocs()
	for b.Loop() {
		n, err := agent.tx.Seal(pkt, inner)
		if err != nil {
			b.Fatal(err)
		}
		handle(pkt[:n], from)
	}
	b.StopTimer()
	st := r.SenderStats(p)
	require.Zero(b, st.DataDrops)
	require.Positive(b, st.DataSent)
}
