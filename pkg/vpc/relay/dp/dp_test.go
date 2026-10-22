// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	vpcA, vniA = "uid-a/1", 100
	vpcB, vniB = "uid-b/1", 200
)

var (
	addrA1 = netip.MustParseAddrPort("192.0.2.1:4000")
	addrA2 = netip.MustParseAddrPort("192.0.2.2:4000")
	addrA4 = netip.MustParseAddrPort("192.0.2.4:4000")
	addrT  = netip.MustParseAddrPort("198.51.100.1:1000")
	addrT2 = netip.MustParseAddrPort("198.51.100.2:1000")
)

// The SPIs of the keys entries. Each SPI has its own key.
const (
	spiA1In, spiA1Out = 0x101, 0x111
	spiA2In, spiA2Out = 0x201, 0x211
	spiA4In, spiA4Out = 0x401, 0x411
	spiTIn, spiTOut   = 0x1001, 0x1011
	spiT2Out          = 0x1111
	spiNoPort         = 0x501
)

func key(spi uint32) []byte {
	k := make([]byte, 16)
	binary.BigEndian.PutUint32(k, spi)
	return k
}

func insert(e *p4.TableEntry) *p4.Update {
	return &p4.Update{Type: p4.Update_INSERT, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}}}
}

func modify(e *p4.TableEntry) *p4.Update {
	return &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}}}
}

func remove(e *p4.TableEntry) *p4.Update {
	return &p4.Update{Type: p4.Update_DELETE, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}}}
}

func keys(typ p4.Update_Type, e *dpv1.PspSaEntry) *p4.Update {
	x, err := dp.KeysEntry(e)
	if err != nil {
		panic(err)
	}
	return &p4.Update{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: x}}}
}

func rx(spi uint32, port, session uint64, lane uint32) *p4.Update {
	return keys(p4.Update_INSERT, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spi, Key: key(spi), Port: port, Session: session, Lane: lane})
}

func tx(spi uint32, port, session uint64, lane uint32) *p4.Update {
	return keys(p4.Update_INSERT, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spi, Key: key(spi), Port: port, Session: session, Lane: lane})
}

func meterUpdate(id, index uint32, cfg *p4.MeterConfig) *p4.Update {
	return &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: &p4.MeterEntry{
		MeterId: id, Index: &p4.Index{Index: int64(index)}, Config: cfg,
	}}}}
}

func write(ctx context.Context, tg dp.Target, us ...*p4.Update) error {
	return tg.Write(ctx, &p4.WriteRequest{Atomicity: p4.WriteRequest_DATAPLANE_ATOMIC, Updates: us})
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func access(port uint64, addr netip.AddrPort, tag uint32, lanes uint64) *p4.TableEntry {
	return dp.PortsKey{Port: port}.Entry(dp.PortAction{Session: 1, Tag: tag, Addr: addr, Lanes: lanes, MTU: 1400, MeterIndex: uint32(port)})
}

// lane2 gives A1 only a TX entry of lane 2 (lane port 4002), and the seen bits of its ports entry.
func lane2(seen uint8) []*p4.Update {
	return []*p4.Update{
		keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spiA1Out, Port: 1, Session: 1}),
		tx(0x113, 1, 1, 2),
		modify(dp.PortsKey{Port: 1}.Entry(dp.PortAction{Session: 1, Tag: 7, Addr: addrA1, Lanes: 4001<<32 | 4002<<16, Seen: seen, MTU: 1400, MeterIndex: 1})),
	}
}

func context_(port, session uint64, tag uint32, vpc string, vni, cell uint32) *p4.TableEntry {
	return dp.ClassifyKey{Port: port, Session: session, Tag: tag}.Entry(dp.ContextAction{VPC: vpc, VNI: vni, Cell: cell})
}

func source(port, session uint64, tag uint32, p string, a dp.Action) *p4.TableEntry {
	return dp.SourceKey{Port: port, Session: session, Tag: tag, Src: pfx(p)}.Entry(a)
}

func route(vpc, p string, port uint64, cell uint32, local uint64, localCell uint32) *p4.TableEntry {
	return dp.RouteKey{VPC: vpc, Dst: pfx(p)}.Entry(dp.ForwardAction{Port: port, Cell: cell, LocalPort: local, LocalCell: localCell})
}

// base is the relay of the tests. In VPC A: agents A1 (port 1, two lane ports), A2 (port 2) and A3
// (port 3, QUIC mode), and the peer relays T (port 10, MS 5) and T2 (port 11). In VPC B: A4 (port 4),
// with the prefix of A1.
func base() []*p4.Update {
	return []*p4.Update{
		insert(access(1, addrA1, 7, 4001<<32|4002<<16)),
		insert(access(2, addrA2, 8, 0)),
		insert(access(3, netip.AddrPort{}, 9, 0)),
		insert(access(4, addrA4, 10, 0)),
		insert(dp.PortsKey{Port: 10}.Entry(dp.PortAction{Trunk: true, Session: 5, Addr: addrT, MTU: 9000, MeterIndex: 10})),
		insert(dp.PortsKey{Port: 11}.Entry(dp.PortAction{Trunk: true, Session: 1, Addr: addrT2, MTU: 9000, MeterIndex: 11})),
		insert(context_(1, 1, 0, vpcA, vniA, 1)),
		insert(context_(2, 1, 0, vpcA, vniA, 2)),
		insert(context_(3, 1, 0, vpcA, vniA, 3)),
		insert(context_(4, 1, 0, vpcB, vniB, 4)),
		insert(context_(10, 5, 20, vpcA, vniA, 20)),
		insert(source(1, 1, 0, "100.64.1.0/24", dp.NoAction{})),
		insert(source(1, 1, 0, "100.64.77.7/32", dp.LocalOnlyAction{})),
		insert(source(2, 1, 0, "100.64.2.0/24", dp.NoAction{})),
		insert(source(3, 1, 0, "100.64.3.0/24", dp.NoAction{})),
		insert(source(4, 1, 0, "100.64.1.0/24", dp.NoAction{})),
		insert(source(10, 5, 20, "100.64.9.0/24", dp.NoAction{})),
		insert(route(vpcA, "100.64.1.0/24", 1, 31, 1, 31)),
		insert(route(vpcA, "100.64.2.0/24", 2, 32, 2, 32)),
		insert(route(vpcA, "100.64.3.0/24", 3, 33, 3, 33)),
		insert(route(vpcA, "100.64.4.0/24", 99, 34, 99, 34)),
		insert(route(vpcA, "100.64.5.0/24", 2, 32, 11, 41)),
		insert(route(vpcA, "100.64.6.0/24", 11, 36, 11, 36)),
		insert(route(vpcA, "100.64.8.0/24", 10, 38, 2, 32)),
		insert(route(vpcA, "100.64.9.0/24", 10, 39, 0, 0)),
		insert(route(vpcB, "100.64.1.0/24", 4, 44, 4, 44)),
		rx(spiA1In, 1, 1, 0), tx(spiA1Out, 1, 1, 0),
		rx(spiA2In, 2, 1, 0), tx(spiA2Out, 2, 1, 0),
		rx(spiA4In, 4, 1, 0), tx(spiA4Out, 4, 1, 0),
		rx(spiTIn, 10, 5, 0), tx(spiTOut, 10, 5, 0),
		tx(spiT2Out, 11, 1, 0),
		rx(spiNoPort, 5, 1, 0),
	}
}

// ipv4 returns a UDP packet from src to dst of n bytes.
func ipv4(src, dst string, n int) []byte {
	b := make([]byte, n)
	b[0], b[9] = 0x45, 17
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], 5000)
	binary.BigEndian.PutUint16(b[22:], 6000)
	return b
}

// seal returns a PSP packet as a sender with the key of spi makes it.
func seal(spi, vni, seq uint32, payload []byte) []byte {
	aead, err := psp.NewAEAD(key(spi))
	if err != nil {
		panic(err)
	}
	h := psp.Header{Version: psp.AESGCM128, SPI: spi, IV: uint64(seq), VNI: vni, Flags: psp.FlagSeq, Seq: seq}
	out := make([]byte, len(payload)+psp.Overhead)
	var n int
	if payload[0]>>4 == 4 {
		n, err = psp.Seal(aead, h, out, payload)
	} else {
		n, err = psp.SealPSP(aead, h, out, payload)
	}
	if err != nil {
		panic(err)
	}
	return out[:n]
}

// sent is one packet that the pipeline gave to its Sender.
type sent struct {
	to netip.AddrPort
	b  []byte
}

// opened opens a sealed packet that the relay sent, with the key of its SPI.
func opened(t *testing.T, b []byte) (spi, vni uint32, payload []byte) {
	t.Helper()
	h, err := psp.ParseTrunkHeader(b)
	require.NoError(t, err)
	aead, err := psp.NewAEAD(key(h.SPI))
	require.NoError(t, err)
	p, err := psp.OpenTrunkInPlace(aead, bytes.Clone(b))
	require.NoError(t, err)
	return h.SPI, h.VNI, p
}

// relay is a pipeline with the base entries and what it gave out.
type relay struct {
	*dp.Pipeline
	sent    []sent
	in      []*p4.PacketIn
	frames  map[uint64][][]byte
	full    bool
	dgramEr error
}

func newRelay(t *testing.T, extra ...*p4.Update) *relay {
	t.Helper()
	r := &relay{frames: map[uint64][][]byte{}}
	r.Pipeline = dp.New(func(to netip.AddrPort, b []byte) { r.sent = append(r.sent, sent{to, bytes.Clone(b)}) })
	r.OnPacketIn(func(p *p4.PacketIn) bool {
		if r.full {
			return false
		}
		r.in = append(r.in, p)
		return true
	})
	r.SetFrameWriter(3, func(b []byte) error {
		if r.dgramEr != nil {
			return r.dgramEr
		}
		r.frames[3] = append(r.frames[3], bytes.Clone(b))
		return nil
	})
	require.NoError(t, write(t.Context(), r, base()...))
	if len(extra) > 0 {
		require.NoError(t, write(t.Context(), r, extra...))
	}
	return r
}

// counts returns the indices of a counter that are not zero, with their packet counts.
func counts(t *testing.T, tg dp.Target, id uint32) map[int64]int64 {
	t.Helper()
	got := map[int64]int64{}
	err := tg.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{CounterId: id}}}}},
		func(e *p4.Entity) {
			c := e.GetCounterEntry()
			got[c.GetIndex().GetIndex()] = c.GetData().GetPacketCount()
		})
	require.NoError(t, err)
	return got
}

func frameOut(port, session uint64, b []byte) *p4.PacketOut {
	return &p4.PacketOut{Payload: b, Metadata: dp.PacketOutMeta{Kind: dp.KindFrame, Port: port, Session: session}.Metadata()}
}

func TestPipeline(t *testing.T) {
	probeKey := [32]byte{1}
	probe := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{9}, Counter: 1}, 0, &probeKey)
	stranger := netip.MustParseAddrPort("203.0.113.9:5555")

	type out struct {
		to    netip.AddrPort
		spi   uint32 // 0: a RAW packet.
		vni   uint32
		inner []byte
	}
	type pin struct {
		meta    dp.PacketInMeta
		payload []byte
	}
	cases := []struct {
		name     string
		extra    []*p4.Update
		from     netip.AddrPort
		wire     []byte        // A packet in on UDP 1000, or
		po       *p4.PacketOut // a PacketOut.
		full     bool
		dgramErr bool
		drop     uint8 // The drops index.
		out      *out
		in       *pin
		frame    []byte // A FRAME out to port 3.
		cells    map[int64]int64
	}{
		{
			name: "winner from access",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			out:   &out{to: addrA2, spi: spiA2Out, vni: vniA, inner: ipv4("100.64.1.5", "100.64.2.5", 100)},
			cells: map[int64]int64{2: 1, 2*32 + 1: 1},
		},
		{
			name: "winner on a trunk gets the sender's tag",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.9.5", 100)),
			out: &out{to: addrT, spi: spiTOut, vni: 7, inner: ipv4("100.64.1.5", "100.64.9.5", 100)},
		},
		{
			name: "lane port source",
			from: netip.AddrPortFrom(addrA1.Addr(), 4002), wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			out: &out{to: addrA2, spi: spiA2Out, vni: vniA, inner: ipv4("100.64.1.5", "100.64.2.5", 100)},
		},
		{
			name: "local target from a trunk",
			from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.8.5", 100)),
			out:   &out{to: addrA2, spi: spiA2Out, vni: vniA, inner: ipv4("100.64.9.5", "100.64.8.5", 100)},
			cells: map[int64]int64{40: 1, 2*32 + 1: 1},
		},
		{
			name: "local target for a local_only packet",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.77.7", "100.64.8.5", 100)),
			out: &out{to: addrA2, spi: spiA2Out, vni: vniA, inner: ipv4("100.64.77.7", "100.64.8.5", 100)},
		},
		{
			name: "FRAME out",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.3.5", 100)),
			frame: peerconn.EncodeData(nil, vniA, ipv4("100.64.1.5", "100.64.3.5", 100)),
		},
		{
			name: "FRAME in",
			po:   frameOut(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:  &out{to: addrA1, spi: spiA1Out, vni: vniA, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name:  "a TX entry of a lane sends to the port address before a keepalive of the lane",
			extra: lane2(0),
			po:    frameOut(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:   &out{to: addrA1, spi: 0x113, vni: vniA, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name:  "a keepalive of another lane does not move the lane",
			extra: lane2(0b101),
			po:    frameOut(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:   &out{to: addrA1, spi: 0x113, vni: vniA, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name:  "a TX entry of a lane sends to the lane port after its keepalive",
			extra: lane2(0b010),
			po:    frameOut(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:   &out{to: netip.AddrPortFrom(addrA1.Addr(), 4002), spi: 0x113, vni: vniA, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name: "PUNT of a probe",
			from: stranger, wire: probe,
			in: &pin{meta: dp.PacketInMeta{Kind: dp.KindPunt, From: stranger}, payload: probe},
		},
		{
			name: "PUNT of trunk tag 0",
			from: addrT, wire: seal(spiTIn, 0, 1, []byte("trunk message")),
			in: &pin{meta: dp.PacketInMeta{Kind: dp.KindPunt, Port: 10, Session: 5, From: addrT}, payload: []byte("trunk message")},
		},
		{
			name: "MISS",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.200.1", 100)),
			in: &pin{meta: dp.PacketInMeta{Kind: dp.KindMiss, Port: 1, Session: 1, From: addrA1}, payload: ipv4("100.64.1.5", "100.64.200.1", 100)},
		},
		{
			name: "isolation: no route of another VPC",
			from: addrA4, wire: seal(spiA4In, vniB, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			in: &pin{meta: dp.PacketInMeta{Kind: dp.KindMiss, Port: 4, Session: 1, From: addrA4}, payload: ipv4("100.64.1.5", "100.64.2.5", 100)},
		},
		{
			name: "SEAL",
			po:   &p4.PacketOut{Payload: []byte("mesh probe"), Metadata: dp.PacketOutMeta{Kind: dp.KindSeal, Port: 10, Session: 5}.Metadata()},
			out:  &out{to: addrT, spi: spiTOut, vni: 0, inner: []byte("mesh probe")},
		},
		{
			name: "RAW",
			po:   &p4.PacketOut{Payload: []byte("probe reply"), Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: addrA1}.Metadata()},
			out:  &out{to: addrA1, inner: []byte("probe reply")},
		},
		{
			name: "PUNT of a keepalive",
			from: netip.AddrPortFrom(addrA1.Addr(), 4001), wire: []byte{p2p.TypeKeepalive},
			in: &pin{meta: dp.PacketInMeta{Kind: dp.KindPunt, From: netip.AddrPortFrom(addrA1.Addr(), 4001)}, payload: []byte{p2p.TypeKeepalive}},
		},
		{name: "malformed", from: stranger, wire: []byte("not a packet of the relay"), drop: dp.ReasonMalformed},
		{name: "unknown_spi", from: addrA1, wire: seal(0x999, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonUnknownSPI},
		{
			name: "bad key",
			from: addrA1, wire: func() []byte {
				b := seal(spiA2In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100))
				binary.BigEndian.PutUint32(b[4:], spiA1In)
				return b
			}(),
			drop: dp.ReasonOpen,
		},
		{name: "old_session: no ports entry", from: addrA1, wire: seal(spiNoPort, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonOldSession},
		{
			name:  "old_session after a new MS",
			extra: []*p4.Update{modify(dp.PortsKey{Port: 10}.Entry(dp.PortAction{Trunk: true, Session: 6, Addr: addrT, MTU: 9000, MeterIndex: 10}))},
			from:  addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.8.5", 100)),
			drop: dp.ReasonOldSession,
		},
		{name: "old_session of a FRAME in", po: frameOut(3, 2, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))), drop: dp.ReasonOldSession},
		{name: "unknown_source", from: netip.MustParseAddrPort("192.0.2.99:4000"), wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonUnknownSource},
		{
			name:  "meter",
			extra: []*p4.Update{meterUpdate(dp.MeterPort, 1, &p4.MeterConfig{Cir: 1, Cburst: 64, Pir: 1, Pburst: 64})},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			drop: dp.ReasonMeter,
		},
		{name: "no_context: VNI of another VPC", from: addrA1, wire: seal(spiA1In, vniB, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonNoContext},
		{name: "no_context: unknown trunk tag", from: addrT, wire: seal(spiTIn, 33, 1, ipv4("100.64.9.5", "100.64.2.5", 100)), drop: dp.ReasonNoContext},
		{name: "source", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.50.1", "100.64.2.5", 100)), drop: dp.ReasonSource},
		{name: "no_route: no entry on a trunk", from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.200.1", 100)), drop: dp.ReasonNoRoute},
		{name: "no_route: no local target", from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.9.7", 100)), drop: dp.ReasonNoRoute},
		{name: "no_target", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.4.5", 100)), drop: dp.ReasonNoTarget},
		{name: "trunk_to_trunk", from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.6.5", 100)), drop: dp.ReasonTrunkToTrunk},
		{name: "local_only", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.77.7", "100.64.5.5", 100)), drop: dp.ReasonLocalOnly},
		{name: "mtu", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 1401)), drop: dp.ReasonMTU},
		{
			name:  "no_keys",
			extra: []*p4.Update{keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spiA2Out, Port: 2, Session: 1})},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			drop: dp.ReasonNoKeys,
		},
		{name: "datagram_full", dgramErr: true, from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.3.5", 100)), drop: dp.ReasonDatagramFull},
		{name: "punt queue full", full: true, from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.200.1", 100)), drop: dp.ReasonPuntFull},
		{
			name:  "drop action of an entry",
			extra: []*p4.Update{insert(dp.RouteKey{VPC: vpcA, Dst: pfx("100.64.2.128/25")}.Entry(dp.DropAction{Reason: 63}))},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.200", 100)),
			drop: 63,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, tc.extra...)
			r.full = tc.full
			if tc.dgramErr {
				r.dgramEr = errors.New("datagram queue is full")
			}
			if tc.po != nil {
				require.NoError(t, r.PacketOut(tc.po))
			} else {
				r.Receive(tc.from, bytes.Clone(tc.wire))
			}

			drops := counts(t, r, dp.CounterDrops)
			if tc.drop != 0 {
				assert.Equal(t, map[int64]int64{int64(tc.drop): 1}, drops)
			} else {
				assert.Empty(t, drops)
			}
			if tc.out == nil {
				assert.Empty(t, r.sent)
			} else if assert.Len(t, r.sent, 1) {
				s := r.sent[0]
				assert.Equal(t, tc.out.to, s.to)
				if tc.out.spi == 0 {
					assert.Equal(t, tc.out.inner, s.b)
				} else {
					spi, vni, payload := opened(t, s.b)
					assert.Equal(t, tc.out.spi, spi)
					assert.Equal(t, tc.out.vni, vni)
					assert.Equal(t, tc.out.inner, payload)
				}
			}
			if tc.in == nil {
				assert.Empty(t, r.in)
			} else if assert.Len(t, r.in, 1) {
				md, err := dp.DecodePacketInMeta(r.in[0].GetMetadata())
				require.NoError(t, err)
				md.Hash = 0
				assert.Equal(t, tc.in.meta, md)
				assert.Equal(t, tc.in.payload, r.in[0].GetPayload())
			}
			if tc.frame == nil {
				assert.Empty(t, r.frames[3])
			} else {
				assert.Equal(t, [][]byte{tc.frame}, r.frames[3])
			}
			if tc.cells != nil {
				assert.Equal(t, tc.cells, counts(t, r, dp.CounterCells))
			}
		})
	}
}
