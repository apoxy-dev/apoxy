// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp/aead"
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

// accessPort is the port record of an access port.
func accessPort(port uint64, addr netip.AddrPort, tag uint32, lanes uint64) dp.PortAction {
	return dp.PortAction{Session: 1, Tag: tag, Addr: addr, Lanes: lanes, MTU: 1400, MeterIndex: uint32(port)}
}

// access is the ports entry of an access port.
func access(port uint64, addr netip.AddrPort, tag uint32, lanes uint64) *p4.TableEntry {
	return dp.PortsKey{Port: port}.Entry(accessPort(port, addr, tag, lanes))
}

// outPort is the out_ports action of the port record pa, as the control plane makes it.
func outPort(pa dp.PortAction) dp.OutPortAction {
	return dp.OutPortAction{Trunk: pa.Trunk, Session: pa.Session, Addr: pa.Addr, Lanes: pa.Lanes, Seen: pa.Seen, MTU: pa.MTU, MeterIndex: pa.MeterIndex}
}

// ports gives the updates typ of the ports and the out_ports entry of port with the port record pa,
// as the control plane writes them.
func ports(typ p4.Update_Type, port uint64, pa dp.PortAction) []*p4.Update {
	return []*p4.Update{
		{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: dp.PortsKey{Port: port}.Entry(pa)}}},
		{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: dp.OutPortsKey{Port: port}.Entry(outPort(pa))}}},
	}
}

// lane2 gives A1 only a TX entry of lane 2 (lane port 4002), and the seen bits of its port entries.
func lane2(seen uint8) []*p4.Update {
	return append([]*p4.Update{
		keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spiA1Out, Port: 1, Session: 1}),
		tx(0x113, 1, 1, 2),
	}, ports(p4.Update_MODIFY, 1, dp.PortAction{Session: 1, Tag: 7, Addr: addrA1, Lanes: 4001<<32 | 4002<<16, Seen: seen, MTU: 1400, MeterIndex: 1})...)
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
	us := slices.Concat(
		ports(p4.Update_INSERT, 1, accessPort(1, addrA1, 7, 4001<<32|4002<<16)),
		ports(p4.Update_INSERT, 2, accessPort(2, addrA2, 8, 0)),
		ports(p4.Update_INSERT, 3, accessPort(3, netip.AddrPort{}, 9, 0)),
		ports(p4.Update_INSERT, 4, accessPort(4, addrA4, 10, 0)),
		ports(p4.Update_INSERT, 10, dp.PortAction{Trunk: true, Session: 5, Addr: addrT, MTU: 9000, MeterIndex: 10}),
		ports(p4.Update_INSERT, 11, dp.PortAction{Trunk: true, Session: 1, Addr: addrT2, MTU: 9000, MeterIndex: 11}),
	)
	return append(us,
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
	)
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

// ipv6 returns a UDP packet from src to dst of n bytes.
func ipv6(src, dst string, n int) []byte {
	b := make([]byte, n)
	b[0], b[6], b[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(b[4:], uint16(n-40))
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	binary.BigEndian.PutUint16(b[40:], 5000)
	binary.BigEndian.PutUint16(b[42:], 6000)
	return b
}

// seal returns a PSP packet as a sender with the key of spi makes it: with Next Header 4 or 41 for an
// IPv4 or IPv6 payload, else as a message.
func seal(spi, vni, seq uint32, payload []byte) []byte {
	aead, err := psp.NewAEAD(key(spi))
	if err != nil {
		panic(err)
	}
	h := psp.Header{Version: psp.AESGCM128, SPI: spi, IV: uint64(seq), VNI: vni, Flags: psp.FlagSeq, Seq: seq}
	out := make([]byte, len(payload)+psp.Overhead)
	var n int
	if payload[0]>>4 == 4 || payload[0]>>4 == 6 {
		n, err = psp.Seal(aead, h, out, payload)
	} else {
		n, err = psp.SealMessage(aead, h, out, payload)
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

// sealedHeader is the PSP header of the packet with sequence number seq that the relay seals with
// the TX entry spi, with the Next Header nh and the VNI field vni.
func sealedHeader(nh uint8, spi, vni, seq uint32) psp.Header {
	return psp.Header{NextHdr: nh, Version: psp.AESGCM128, SPI: spi, IV: uint64(seq), VNI: vni, Flags: psp.FlagSeq, Seq: seq}
}

// opened checks that a packet that the relay sealed has the PSP header want, and opens a copy of
// it with the key of want.SPI and the package code. An inner IP packet opens with psp.OpenInPlace,
// which checks Next Header. A message opens as the relay opens a trunk packet: the Open of
// aead.GCM, then psp.CheckTrunk. It returns the payload.
func opened(t *testing.T, b []byte, want psp.Header) []byte {
	t.Helper()
	h, err := psp.ParseTrunkHeader(b)
	require.NoError(t, err)
	require.Equal(t, want, h, "PSP header")
	pkt := bytes.Clone(b)
	if want.NextHdr != psp.NextHdrMessage {
		a, err := psp.NewAEAD(key(want.SPI))
		require.NoError(t, err)
		payload, err := psp.OpenInPlace(a, pkt)
		require.NoError(t, err)
		return payload
	}
	k, err := aead.GCM{}.NewKey(key(want.SPI))
	require.NoError(t, err)
	ops := []dp.AEADOp{{Key: k, Len: len(pkt)}}
	aead.GCM{}.Open([][]byte{pkt}, ops)
	require.True(t, ops[0].OK, "the message authenticates")
	payload := pkt[psp.PrefixLen : len(pkt)-psp.ICVLen]
	require.NoError(t, psp.CheckTrunk(pkt, payload))
	return payload
}

// relay is a pipeline with the base entries and what it gave out.
type relay struct {
	*dp.Pipeline
	sent    []sent
	batches []int // The length of each batch that the pipeline sent.
	in      []*p4.PacketIn
	dgrams  map[uint64][][]byte // The DATAGRAM out of each port.
	full    bool
	dgramEr error
	onSend  func() // Runs at the end of each Send, or nil.
}

// Send keeps a copy of each packet of b.
func (r *relay) Send(b *dp.TxBatch) {
	r.batches = append(r.batches, b.Len())
	for i := range b.Len() {
		to, p := b.Packet(i)
		r.sent = append(r.sent, sent{to, bytes.Clone(p)})
	}
	if r.onSend != nil {
		r.onSend()
	}
}

// receive runs the pipeline on one packet.
func (r *relay) receive(from netip.AddrPort, b []byte) {
	r.Receive([]dp.RxPacket{{From: from, Payload: b}}, &dp.TxBatch{})
}

func newRelay(t *testing.T, extra ...*p4.Update) *relay {
	t.Helper()
	r := &relay{dgrams: map[uint64][][]byte{}}
	r.Pipeline = dp.New(r, aead.GCM{})
	r.OnPacketIn(func(p *p4.PacketIn) bool {
		if r.full {
			return false
		}
		r.in = append(r.in, p)
		return true
	})
	r.SetDatagramWriter(3, func(b []byte) error {
		if r.dgramEr != nil {
			return r.dgramEr
		}
		r.dgrams[3] = append(r.dgrams[3], bytes.Clone(b))
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

// pd returns the port_drops index of a drop at meter index i.
func pd(i int64, reason uint8) int64 { return i<<5 | int64(reason) }

// datagramIn is the PacketOut DATAGRAM of b from port and session: a DATAGRAM in.
func datagramIn(port, session uint64, b []byte) *p4.PacketOut {
	return &p4.PacketOut{Payload: b, Metadata: dp.PacketOutMeta{Kind: dp.KindDatagram, Port: port, Session: session}.Metadata()}
}

func TestPipeline(t *testing.T) {
	probeKey := [32]byte{1}
	probe := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{9}, Counter: 1}, 0, &probeKey)
	stranger := netip.MustParseAddrPort("203.0.113.9:5555")

	type out struct {
		to    netip.AddrPort
		spi   uint32 // 0: a RAW packet.
		vni   uint32
		nh    uint8 // The Next Header of a sealed packet.
		inner []byte
	}
	type pin struct {
		meta    dp.PacketInMeta
		payload []byte
	}
	type dgramOut struct {
		vni   uint32
		inner []byte
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
		portDrop int64 // The port_drops index of the drop: the out port after egress reads its out_ports entry, else the in port (0: none).
		out      *out
		in       *pin
		dgram    *dgramOut // A DATAGRAM out to port 3.
		cells    map[int64]int64
	}{
		{
			name: "winner from access",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			out:   &out{to: addrA2, spi: spiA2Out, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.1.5", "100.64.2.5", 100)},
			cells: map[int64]int64{2: 1, 2*32 + 1: 1},
		},
		{
			name: "winner on a trunk gets the sender's tag",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.9.5", 100)),
			out: &out{to: addrT, spi: spiTOut, vni: 7, nh: psp.NextHdrV4, inner: ipv4("100.64.1.5", "100.64.9.5", 100)},
		},
		{
			name: "lane port source",
			from: netip.AddrPortFrom(addrA1.Addr(), 4002), wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			out: &out{to: addrA2, spi: spiA2Out, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.1.5", "100.64.2.5", 100)},
		},
		{
			name: "local target from a trunk",
			from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.8.5", 100)),
			out:   &out{to: addrA2, spi: spiA2Out, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.9.5", "100.64.8.5", 100)},
			cells: map[int64]int64{40: 1, 2*32 + 1: 1},
		},
		{
			name: "local target for a local_only packet",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.77.7", "100.64.8.5", 100)),
			out: &out{to: addrA2, spi: spiA2Out, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.77.7", "100.64.8.5", 100)},
		},
		{
			name: "DATAGRAM out",
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.3.5", 100)),
			dgram: &dgramOut{vni: vniA, inner: ipv4("100.64.1.5", "100.64.3.5", 100)},
		},
		{
			name: "DATAGRAM in",
			po:   datagramIn(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:  &out{to: addrA1, spi: spiA1Out, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name:  "a TX entry of a lane sends to the port address before a keepalive of the lane",
			extra: lane2(0),
			po:    datagramIn(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:   &out{to: addrA1, spi: 0x113, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name:  "a keepalive of another lane does not move the lane",
			extra: lane2(0b101),
			po:    datagramIn(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:   &out{to: addrA1, spi: 0x113, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		},
		{
			name:  "a TX entry of a lane sends to the lane port after its keepalive",
			extra: lane2(0b010),
			po:    datagramIn(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			out:   &out{to: netip.AddrPortFrom(addrA1.Addr(), 4002), spi: 0x113, vni: vniA, nh: psp.NextHdrV4, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
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
			out:  &out{to: addrT, spi: spiTOut, vni: 0, nh: psp.NextHdrMessage, inner: []byte("mesh probe")},
		},
		{
			name:  "SEAL to a port without an out_ports entry",
			extra: []*p4.Update{remove(dp.OutPortsKey{Port: 10}.Entry(nil))},
			po:    &p4.PacketOut{Payload: []byte("mesh probe"), Metadata: dp.PacketOutMeta{Kind: dp.KindSeal, Port: 10, Session: 5}.Metadata()},
			drop:  dp.ReasonNoTarget,
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
		{
			name: "Next Header 41 on an IPv4 packet that authenticates",
			from: addrA1, wire: func() []byte {
				a, err := psp.NewAEAD(key(spiA1In))
				if err != nil {
					panic(err)
				}
				inner := ipv4("100.64.1.5", "100.64.2.5", 100)
				b := make([]byte, len(inner)+psp.Overhead)
				h := psp.Header{NextHdr: psp.NextHdrV6, Version: psp.AESGCM128, SPI: spiA1In, IV: 1, VNI: vniA, Flags: psp.FlagSeq, Seq: 1}
				if err := psp.PutHeader(h, b); err != nil {
					panic(err)
				}
				a.Seal(b[psp.PrefixLen:psp.PrefixLen], b[4:psp.HeaderLen], inner, b[:psp.PrefixLen])
				return b
			}(),
			drop: dp.ReasonOpen,
		},
		{name: "old_session: no ports entry", from: addrA1, wire: seal(spiNoPort, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonOldSession},
		{
			name:  "old_session after a new MS",
			extra: ports(p4.Update_MODIFY, 10, dp.PortAction{Trunk: true, Session: 6, Addr: addrT, MTU: 9000, MeterIndex: 10}),
			from:  addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.8.5", 100)),
			drop: dp.ReasonOldSession, portDrop: pd(10, dp.ReasonOldSession),
		},
		{name: "old_session of a DATAGRAM in", po: datagramIn(3, 2, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))), drop: dp.ReasonOldSession, portDrop: pd(3, dp.ReasonOldSession)},
		{name: "unknown_source", from: netip.MustParseAddrPort("192.0.2.99:4000"), wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonUnknownSource, portDrop: pd(1, dp.ReasonUnknownSource)},
		{
			name:  "meter",
			extra: []*p4.Update{meterUpdate(dp.MeterPort, 1, &p4.MeterConfig{Cir: 1, Cburst: 64, Pir: 1, Pburst: 64})},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			drop: dp.ReasonMeter, portDrop: pd(1, dp.ReasonMeter),
		},
		{name: "no_context: VNI of another VPC", from: addrA1, wire: seal(spiA1In, vniB, 1, ipv4("100.64.1.5", "100.64.2.5", 100)), drop: dp.ReasonNoContext, portDrop: pd(1, dp.ReasonNoContext)},
		{name: "no_context: unknown trunk tag", from: addrT, wire: seal(spiTIn, 33, 1, ipv4("100.64.9.5", "100.64.2.5", 100)), drop: dp.ReasonNoContext, portDrop: pd(10, dp.ReasonNoContext)},
		{name: "source", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.50.1", "100.64.2.5", 100)), drop: dp.ReasonSource, portDrop: pd(1, dp.ReasonSource)},
		{name: "no_route: no entry on a trunk", from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.200.1", 100)), drop: dp.ReasonNoRoute, portDrop: pd(10, dp.ReasonNoRoute)},
		{name: "no_route: no local target", from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.9.7", 100)), drop: dp.ReasonNoRoute, portDrop: pd(10, dp.ReasonNoRoute)},
		{name: "no_target", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.4.5", 100)), drop: dp.ReasonNoTarget, portDrop: pd(1, dp.ReasonNoTarget)},
		{
			name:  "no_target: a ports entry without an out_ports entry",
			extra: []*p4.Update{insert(access(99, netip.MustParseAddrPort("192.0.2.98:4000"), 11, 0))},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.4.5", 100)),
			drop: dp.ReasonNoTarget, portDrop: pd(1, dp.ReasonNoTarget),
		},
		{
			name: "the MTU of out_ports counts",
			extra: func() []*p4.Update {
				o := outPort(accessPort(2, addrA2, 8, 0))
				o.MTU = 100
				return []*p4.Update{modify(dp.OutPortsKey{Port: 2}.Entry(o))}
			}(),
			from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 101)),
			drop: dp.ReasonMTU, portDrop: pd(2, dp.ReasonMTU),
		},
		{
			name:  "drop_out entry of out_ports",
			extra: []*p4.Update{modify(dp.OutPortsKey{Port: 2}.Entry(dp.DropOutAction{Reason: 31}))},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			drop: 31, portDrop: pd(1, 31),
		},
		{name: "trunk_to_trunk", from: addrT, wire: seal(spiTIn, 20, 1, ipv4("100.64.9.5", "100.64.6.5", 100)), drop: dp.ReasonTrunkToTrunk, portDrop: pd(11, dp.ReasonTrunkToTrunk)},
		{name: "local_only", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.77.7", "100.64.5.5", 100)), drop: dp.ReasonLocalOnly, portDrop: pd(11, dp.ReasonLocalOnly)},
		{name: "mtu", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 1401)), drop: dp.ReasonMTU, portDrop: pd(2, dp.ReasonMTU)},
		{
			name:  "no_keys",
			extra: []*p4.Update{keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spiA2Out, Port: 2, Session: 1})},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			drop: dp.ReasonNoKeys, portDrop: pd(2, dp.ReasonNoKeys),
		},
		{name: "datagram_full", dgramErr: true, from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.3.5", 100)), drop: dp.ReasonDatagramFull, portDrop: pd(3, dp.ReasonDatagramFull)},
		{name: "punt queue full", full: true, from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.200.1", 100)), drop: dp.ReasonPuntFull, portDrop: pd(1, dp.ReasonPuntFull)},
		{
			name:  "drop action of an entry",
			extra: []*p4.Update{insert(dp.RouteKey{VPC: vpcA, Dst: pfx("100.64.2.128/25")}.Entry(dp.DropAction{Reason: 31}))},
			from:  addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.200", 100)),
			drop: 31, portDrop: pd(1, 31),
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
				r.receive(tc.from, bytes.Clone(tc.wire))
			}

			drops := counts(t, r, dp.CounterDrops)
			if tc.drop != 0 {
				assert.Equal(t, map[int64]int64{int64(tc.drop): 1}, drops)
			} else {
				assert.Empty(t, drops)
			}
			portDrops := counts(t, r, dp.CounterPortDrops)
			if tc.portDrop != 0 {
				assert.Equal(t, map[int64]int64{tc.portDrop: 1}, portDrops)
			} else {
				assert.Empty(t, portDrops)
			}
			if tc.out == nil {
				assert.Empty(t, r.sent)
			} else if assert.Len(t, r.sent, 1) {
				assert.Equal(t, []int{1}, r.batches, "one batch of one packet")
				s := r.sent[0]
				assert.Equal(t, tc.out.to, s.to)
				if tc.out.spi == 0 {
					assert.Equal(t, tc.out.inner, s.b)
				} else {
					// The first packet of each TX entry has sequence number 0.
					payload := opened(t, s.b, sealedHeader(tc.out.nh, tc.out.spi, tc.out.vni, 0))
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
			if tc.dgram == nil {
				assert.Empty(t, r.dgrams[3])
			} else if assert.Len(t, r.dgrams[3], 1) {
				vni, inner, err := peerconn.DecodeData(r.dgrams[3][0])
				require.NoError(t, err)
				assert.Equal(t, tc.dgram.vni, vni)
				assert.Equal(t, tc.dgram.inner, inner)
			}
			if tc.cells != nil {
				assert.Equal(t, tc.cells, counts(t, r, dp.CounterCells))
			}
		})
	}
}

// TestSealNextHdr parses the Next Header of each packet that the relay seals. The path sets it, not
// the first byte of the payload: a SEAL is a message, and apply seals only IPv4 or IPv6.
func TestSealNextHdr(t *testing.T) {
	sealOut := func(b []byte) *p4.PacketOut {
		return &p4.PacketOut{Payload: b, Metadata: dp.PacketOutMeta{Kind: dp.KindSeal, Port: 10, Session: 5}.Metadata()}
	}
	v6 := []*p4.Update{
		insert(source(1, 1, 0, "fd00:1::/64", dp.NoAction{})),
		insert(source(3, 1, 0, "fd00:3::/64", dp.NoAction{})),
		insert(route(vpcA, "fd00:1::/64", 1, 31, 1, 31)),
		insert(route(vpcA, "fd00:2::/64", 2, 32, 2, 32)),
	}
	// The packets that drop have the addresses of A1 to A2.
	notIP := append([]byte{0x10}, ipv4("100.64.1.5", "100.64.2.5", 100)[1:]...)
	shortV4 := ipv4("100.64.1.5", "100.64.2.5", 24)[:19]
	cases := []struct {
		name     string
		extra    []*p4.Update
		from     netip.AddrPort
		wire     []byte        // A packet in on UDP 1000, or
		po       *p4.PacketOut // a PacketOut.
		to       netip.AddrPort
		spi      uint32
		nextHdr  uint8 // 0: the packet drops as malformed, at portDrop.
		inner    []byte
		portDrop int64
	}{
		{name: "SEAL of a message", po: sealOut([]byte("mesh probe")), to: addrT, spi: spiTOut, nextHdr: psp.NextHdrMessage, inner: []byte("mesh probe")},
		{name: "SEAL of a message that starts with 0x45", po: sealOut(ipv4("100.64.1.5", "100.64.2.5", 100)),
			to: addrT, spi: spiTOut, nextHdr: psp.NextHdrMessage, inner: ipv4("100.64.1.5", "100.64.2.5", 100)},
		{name: "SEAL of a message that starts with 0x60", po: sealOut(ipv6("fd00:1::5", "fd00:2::5", 100)),
			to: addrT, spi: spiTOut, nextHdr: psp.NextHdrMessage, inner: ipv6("fd00:1::5", "fd00:2::5", 100)},
		{name: "IPv4 from an agent", from: addrA1, wire: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100)),
			to: addrA2, spi: spiA2Out, nextHdr: psp.NextHdrV4, inner: ipv4("100.64.1.5", "100.64.2.5", 100)},
		{name: "IPv6 from an agent", extra: v6, from: addrA1, wire: seal(spiA1In, vniA, 1, ipv6("fd00:1::5", "fd00:2::5", 100)),
			to: addrA2, spi: spiA2Out, nextHdr: psp.NextHdrV6, inner: ipv6("fd00:1::5", "fd00:2::5", 100)},
		{name: "IPv4 in a DATAGRAM", po: datagramIn(3, 1, peerconn.EncodeData(nil, vniA, ipv4("100.64.3.5", "100.64.1.5", 100))),
			to: addrA1, spi: spiA1Out, nextHdr: psp.NextHdrV4, inner: ipv4("100.64.3.5", "100.64.1.5", 100)},
		{name: "IPv6 in a DATAGRAM", extra: v6, po: datagramIn(3, 1, peerconn.EncodeData(nil, vniA, ipv6("fd00:3::5", "fd00:1::5", 100))),
			to: addrA1, spi: spiA1Out, nextHdr: psp.NextHdrV6, inner: ipv6("fd00:3::5", "fd00:1::5", 100)},
		// The sender labels these as a message (NextHdrMessage) or as IPv4.
		{name: "not IP from an agent", from: addrA1, wire: seal(spiA1In, vniA, 1, notIP), portDrop: pd(1, dp.ReasonMalformed)},
		{name: "short IPv4 from an agent", from: addrA1, wire: seal(spiA1In, vniA, 1, shortV4), portDrop: pd(1, dp.ReasonMalformed)},
		{name: "not IP in a DATAGRAM", po: datagramIn(3, 1, peerconn.EncodeData(nil, vniA, notIP)), portDrop: pd(3, dp.ReasonMalformed)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, tc.extra...)
			if tc.po != nil {
				require.NoError(t, r.PacketOut(tc.po))
			} else {
				r.receive(tc.from, bytes.Clone(tc.wire))
			}
			if tc.nextHdr == 0 {
				assert.Empty(t, r.sent)
				assert.Equal(t, map[int64]int64{int64(dp.ReasonMalformed): 1}, counts(t, r, dp.CounterDrops))
				assert.Equal(t, map[int64]int64{tc.portDrop: 1}, counts(t, r, dp.CounterPortDrops))
				// The next packet to A2 must get the first sequence number of its TX entry.
				r.receive(addrA1, seal(spiA1In, vniA, 2, ipv4("100.64.1.5", "100.64.2.5", 100)))
				tc.to, tc.spi, tc.nextHdr, tc.inner = addrA2, spiA2Out, psp.NextHdrV4, ipv4("100.64.1.5", "100.64.2.5", 100)
			}
			require.Len(t, r.sent, 1)
			assert.Equal(t, tc.to, r.sent[0].to)
			// A message has no VNI. The packet has the first sequence number of its TX entry.
			vni := uint32(vniA)
			if tc.nextHdr == psp.NextHdrMessage {
				vni = 0
			}
			payload := opened(t, r.sent[0].b, sealedHeader(tc.nextHdr, tc.spi, vni, 0))
			assert.Equal(t, tc.inner, payload)
		})
	}
}

func TestReceiveBatch(t *testing.T) {
	toA2 := func(seq uint32) dp.RxPacket {
		return dp.RxPacket{From: addrA1, Payload: seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100+int(seq)))}
	}
	type out struct {
		to       netip.AddrPort
		spi, vni uint32
		inner    []byte
	}
	a2 := func(seq uint32) out {
		return out{addrA2, spiA2Out, vniA, ipv4("100.64.1.5", "100.64.2.5", 100+int(seq))}
	}
	many := func(n uint32) ([]dp.RxPacket, []out) {
		var rx []dp.RxPacket
		var want []out
		for seq := uint32(1); seq <= n; seq++ {
			rx, want = append(rx, toA2(seq)), append(want, a2(seq))
		}
		return rx, want
	}
	rx100, want100 := many(100)
	cases := []struct {
		name    string
		rx      []dp.RxPacket
		want    []out
		batches []int // nil: each batch has at most 64 packets.
	}{
		{
			name: "all packets in order in one batch",
			rx: []dp.RxPacket{
				toA2(1),
				{From: addrA1, Payload: seal(spiA1In, vniA, 2, ipv4("100.64.1.5", "100.64.9.5", 100))},
				toA2(3),
			},
			want:    []out{a2(1), {addrT, spiTOut, 7, ipv4("100.64.1.5", "100.64.9.5", 100)}, a2(3)},
			batches: []int{3},
		},
		{
			name: "drops and punts are not in the batch",
			rx: []dp.RxPacket{
				toA2(1),
				{From: addrA1, Payload: []byte("not a packet of the relay")},
				{From: addrA1, Payload: []byte{p2p.TypeKeepalive}},
				toA2(2),
			},
			want:    []out{a2(1), a2(2)},
			batches: []int{2},
		},
		{name: "more than 64 packets", rx: rx100, want: want100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			tx := &dp.TxBatch{}
			r.Receive(tc.rx, tx)
			assert.Zero(t, tx.Len(), "the batch is reset")
			if tc.batches != nil {
				assert.Equal(t, tc.batches, r.batches)
			}
			total := 0
			for _, n := range r.batches {
				assert.LessOrEqual(t, n, 64)
				total += n
			}
			assert.Equal(t, len(tc.want), total)
			require.Len(t, r.sent, len(tc.want))
			seq := map[uint32]uint32{} // The next sequence number of each TX entry.
			for i, w := range tc.want {
				assert.Equal(t, w.to, r.sent[i].to)
				inner := opened(t, r.sent[i].b, sealedHeader(psp.NextHdrV4, w.spi, w.vni, seq[w.spi]))
				seq[w.spi]++
				assert.Equal(t, w.inner, inner, "packet %d", i)
			}
		})
	}
}

// dropCounts returns the drop reasons that are not zero, with their packets and bytes.
func dropCounts(t *testing.T, tg dp.Target) map[int64][2]int64 {
	t.Helper()
	got := map[int64][2]int64{}
	err := tg.Read(t.Context(), &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{CounterId: dp.CounterDrops}}}}},
		func(e *p4.Entity) {
			c := e.GetCounterEntry()
			got[c.GetIndex().GetIndex()] = [2]int64{c.GetData().GetPacketCount(), c.GetData().GetByteCount()}
		})
	require.NoError(t, err)
	return got
}

// sealWith returns a PSP packet of A1 with header h for payload, sealed with the key of spiA1In.
func sealWith(t *testing.T, h psp.Header, payload []byte) []byte {
	t.Helper()
	out := make([]byte, len(payload)+psp.Overhead)
	require.NoError(t, psp.PutHeader(h, out))
	a, err := psp.NewAEAD(key(spiA1In))
	require.NoError(t, err)
	a.Seal(out[psp.PrefixLen:psp.PrefixLen], out[4:psp.HeaderLen], payload, out[:psp.PrefixLen])
	return out
}

// TestReceiveParts checks the parts of Receive. A part of up to 64 packets opens its packets with
// one AEAD call and then applies them in RX order: the drops, the replay window and the punts
// follow the RX order, and a Write between two parts applies to the second part. A batch with no
// memories of a device opens copies, so the RX payloads stay as they are.
func TestReceiveParts(t *testing.T) {
	// Packet seq from A1 to A2 has an inner packet of 100+seq bytes.
	toA2 := func(seq uint32) dp.RxPacket {
		return dp.RxPacket{From: addrA1, Payload: seal(spiA1In, vniA, seq, ipv4("100.64.1.5", "100.64.2.5", 100+int(seq)))}
	}
	run := func(lo, hi uint32) ([]dp.RxPacket, []uint32) {
		var rx []dp.RxPacket
		var seqs []uint32
		for seq := lo; seq <= hi; seq++ {
			rx, seqs = append(rx, toA2(seq)), append(seqs, seq)
		}
		return rx, seqs
	}
	forged := func(seq uint32) dp.RxPacket {
		p := toA2(seq)
		p.Payload[len(p.Payload)-1] ^= 1
		return p
	}
	from := func(a netip.AddrPort, b []byte) dp.RxPacket { return dp.RxPacket{From: a, Payload: b} }
	wire := func(seq uint32) int64 { return int64(100 + int(seq) + psp.Overhead) }
	probeKey := [32]byte{1}
	probe := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{9}, Counter: 1}, 0, &probeKey)
	probe2 := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{8}, Counter: 2}, 0, &probeKey)
	miss := seal(spiA1In, vniA, 5, ipv4("100.64.1.5", "100.64.200.1", 100))
	tag0 := seal(spiTIn, 0, 1, []byte("trunk message"))
	h := func(v psp.Version) psp.Header {
		return psp.Header{NextHdr: psp.NextHdrV4, Version: v, SPI: spiA1In, IV: 1, VNI: vniA, Flags: psp.FlagSeq, Seq: 1}
	}
	inner6 := make([]byte, 60)
	inner6[0] = 0x60
	part1, seqs1 := run(1, 64)
	cases := []struct {
		name    string
		extra   []*p4.Update
		rx      []dp.RxPacket
		onSend  []*p4.Update // A Write in the Send of the first part.
		sent    []uint32     // The seq of each packet to A2, in order.
		batches []int
		drops   map[int64][2]int64 // Packets and bytes of each drop reason.
		punts   [][]byte
	}{
		{
			name: "an auth failure does not move the replay window",
			rx:   []dp.RxPacket{toA2(1), forged(2), toA2(3), toA2(2)},
			sent: []uint32{1, 3, 2}, batches: []int{3},
			drops: map[int64][2]int64{int64(dp.ReasonOpen): {1, wire(2)}},
		},
		{
			name: "a replay inside a part",
			rx:   []dp.RxPacket{toA2(1), toA2(2), toA2(1)},
			sent: []uint32{1, 2}, batches: []int{2},
			drops: map[int64][2]int64{int64(dp.ReasonOpen): {1, wire(1)}},
		},
		{
			name: "a replay of the first part in the second part",
			rx:   append(append([]dp.RxPacket{}, part1...), toA2(1)),
			sent: seqs1, batches: []int{64},
			drops: map[int64][2]int64{int64(dp.ReasonOpen): {1, wire(1)}},
		},
		{
			name:   "a key removal between parts",
			rx:     append(append([]dp.RxPacket{}, part1...), toA2(65)),
			onSend: []*p4.Update{keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spiA1In, Port: 1, Session: 1})},
			sent:   seqs1, batches: []int{64},
			drops: map[int64][2]int64{int64(dp.ReasonUnknownSPI): {1, wire(65)}},
		},
		{
			name: "a bad Next Header, then a packet with the same sequence number",
			rx:   []dp.RxPacket{from(addrA1, sealWith(t, h(psp.AESGCM128), inner6)), toA2(1)},
			sent: []uint32{1}, batches: []int{1},
			drops: map[int64][2]int64{int64(dp.ReasonOpen): {1, int64(len(inner6) + psp.Overhead)}},
		},
		{
			name: "no sequence number flag",
			rx: []dp.RxPacket{from(addrA1, func() []byte {
				hd := h(psp.AESGCM128)
				hd.Flags = 0
				return sealWith(t, hd, ipv4("100.64.1.5", "100.64.2.5", 120))
			}()), toA2(1)},
			sent: []uint32{1}, batches: []int{1},
			drops: map[int64][2]int64{int64(dp.ReasonOpen): {1, 120 + psp.Overhead}},
		},
		{
			name: "a wrong version",
			rx:   []dp.RxPacket{from(addrA1, sealWith(t, h(psp.AESGCM256), ipv4("100.64.1.5", "100.64.2.5", 120))), toA2(2)},
			sent: []uint32{2}, batches: []int{1},
			drops: map[int64][2]int64{int64(dp.ReasonOpen): {1, 120 + psp.Overhead}},
		},
		{
			name: "punts in RX order",
			rx:   []dp.RxPacket{from(addrA2, probe), toA2(1), from(addrA1, miss), from(addrA1, []byte{p2p.TypeKeepalive}), from(addrT, tag0), from(addrA2, probe2)},
			sent: []uint32{1}, batches: []int{1},
			punts: [][]byte{probe, ipv4("100.64.1.5", "100.64.200.1", 100), {p2p.TypeKeepalive}, []byte("trunk message"), probe2},
		},
		{
			name: "keepalive and probe lengths",
			rx: []dp.RxPacket{
				from(addrA1, []byte{p2p.TypeKeepalive}), from(addrA1, []byte{p2p.TypeKeepalive, 0}),
				from(addrA2, probe[:p2p.MinProbeLen-1]), from(addrA2, probe[:p2p.MinProbeLen]),
			},
			punts: [][]byte{{p2p.TypeKeepalive}, probe[:p2p.MinProbeLen]},
			drops: map[int64][2]int64{int64(dp.ReasonMalformed): {2, 2 + p2p.MinProbeLen - 1}},
		},
		{
			name: "the bytes of each drop reason",
			extra: []*p4.Update{
				keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spiA2Out, Port: 2, Session: 1}),
			},
			rx: []dp.RxPacket{
				from(addrA1, []byte("not a packet of the relay")),
				from(addrA1, seal(0x999, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 110))),
				from(netip.MustParseAddrPort("192.0.2.99:4000"), seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 120))),
				from(addrA1, seal(spiA1In, vniA, 2, ipv4("100.64.1.5", "100.64.4.5", 130))),
				toA2(3),
			},
			drops: map[int64][2]int64{
				int64(dp.ReasonMalformed):     {1, int64(len("not a packet of the relay"))},
				int64(dp.ReasonUnknownSPI):    {1, 110 + psp.Overhead},
				int64(dp.ReasonUnknownSource): {1, 120 + psp.Overhead},
				int64(dp.ReasonNoTarget):      {1, 130 + psp.Overhead},
				int64(dp.ReasonNoKeys):        {1, 103}, // The inner packet: the seal fails.
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, tc.extra...)
			if tc.onSend != nil {
				once := false
				r.onSend = func() {
					if !once {
						once = true
						require.NoError(t, write(t.Context(), r, tc.onSend...))
					}
				}
			}
			var payloads [][]byte
			for _, p := range tc.rx {
				payloads = append(payloads, bytes.Clone(p.Payload))
			}
			r.Receive(tc.rx, &dp.TxBatch{})

			var got, want [][]byte
			for i, s := range r.sent {
				assert.Equal(t, addrA2, s.to)
				got = append(got, opened(t, s.b, sealedHeader(psp.NextHdrV4, spiA2Out, vniA, uint32(i))))
			}
			for _, seq := range tc.sent {
				want = append(want, ipv4("100.64.1.5", "100.64.2.5", 100+int(seq)))
			}
			assert.Equal(t, want, got, "the packets to A2")
			assert.Equal(t, tc.batches, r.batches, "one batch for each part with packets")
			drops := dropCounts(t, r)
			if tc.drops == nil {
				assert.Empty(t, drops)
			} else {
				assert.Equal(t, tc.drops, drops)
			}
			var punts [][]byte
			for _, p := range r.in {
				punts = append(punts, p.GetPayload())
			}
			assert.Equal(t, tc.punts, punts, "the punts in RX order")
			for i, p := range tc.rx {
				assert.Equal(t, payloads[i], p.Payload, "RX payload %d", i)
			}
		})
	}
}

// TestReceiveWriteInPart checks that a Write waits for the part of Receive that runs. The Write
// starts in the punt of the first packet: the other packets of the part use the key that it
// removes, and the next packet does not.
func TestReceiveWriteInPart(t *testing.T) {
	r := newRelay(t)
	removed := make(chan error, 1)
	r.OnPacketIn(func(*p4.PacketIn) bool {
		started := make(chan struct{})
		go func() {
			close(started)
			removed <- write(context.Background(), r, keys(p4.Update_DELETE, &dpv1.PspSaEntry{
				Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spiA1In, Port: 1, Session: 1,
			}))
		}()
		<-started
		// The Write cannot end while the part runs. 50 ms is time for it to end if it did not wait.
		select {
		case err := <-removed:
			t.Errorf("the Write did not wait for the part: %v", err)
			removed <- err
		case <-time.After(50 * time.Millisecond):
		}
		return true
	})
	r.Receive([]dp.RxPacket{
		{From: addrA1, Payload: []byte{p2p.TypeKeepalive}},
		{From: addrA1, Payload: seal(spiA1In, vniA, 1, ipv4("100.64.1.5", "100.64.2.5", 100))},
		{From: addrA1, Payload: seal(spiA1In, vniA, 2, ipv4("100.64.1.5", "100.64.2.5", 100))},
	}, &dp.TxBatch{})
	select {
	case err := <-removed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the Write did not end after the part")
	}
	assert.Len(t, r.sent, 2, "the packets of the part")
	r.receive(addrA1, seal(spiA1In, vniA, 3, ipv4("100.64.1.5", "100.64.2.5", 100)))
	assert.Len(t, r.sent, 2)
	assert.Equal(t, map[int64]int64{int64(dp.ReasonUnknownSPI): 1}, counts(t, r, dp.CounterDrops))
}

// TestPacketOutMaxPacket sends SEAL packets at and over maxPacket, the largest UDP payload.
func TestPacketOutMaxPacket(t *testing.T) {
	cases := []struct {
		name string
		n    int // The size of the payload.
		sent bool
	}{
		{name: "the largest packet", n: 65535 - psp.Overhead, sent: true},
		{name: "one byte over", n: 65535 - psp.Overhead + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t)
			po := &p4.PacketOut{Payload: bytes.Repeat([]byte{'x'}, tc.n), Metadata: dp.PacketOutMeta{Kind: dp.KindSeal, Port: 10, Session: 5}.Metadata()}
			require.NoError(t, r.PacketOut(po))
			if tc.sent {
				require.Len(t, r.sent, 1)
				assert.Equal(t, addrT, r.sent[0].to)
				payload := opened(t, r.sent[0].b, sealedHeader(psp.NextHdrMessage, spiTOut, 0, 0))
				assert.Equal(t, bytes.Repeat([]byte{'x'}, tc.n), payload)
				assert.Empty(t, dropCounts(t, r))
				return
			}
			assert.Empty(t, r.sent)
			assert.Equal(t, map[int64][2]int64{int64(dp.ReasonNoKeys): {1, int64(tc.n)}}, dropCounts(t, r))
			assert.Empty(t, counts(t, r, dp.CounterPortDrops))
		})
	}
}
