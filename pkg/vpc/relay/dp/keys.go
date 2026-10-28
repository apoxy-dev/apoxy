// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/replay"

	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// lanes is the number of lanes of a port session.
const lanes = 4

// portSession names the TX entries of one port session.
type portSession struct {
	port, session uint64
}

// rxSA is an RX entry of the keys extern: the receive SA of one SPI.
type rxSA struct {
	spi           uint32
	port, session uint64
	lane          uint8
	version       psp.Version
	key           AEADKey

	mu      sync.Mutex
	window  replay.Window
	packets atomic.Uint64
	seq     atomic.Uint32
}

// txSA is a TX entry of the keys extern: the send SA of one lane of a port session.
type txSA struct {
	spi     uint32
	lane    uint8
	version psp.Version
	key     AEADKey
	next    atomic.Uint64 // The next sequence number. The IV has the same value.
}

// txLanes has the TX entry of each lane of a port session, or nil.
type txLanes [lanes]*txSA

// pick returns the TX entry of the lane that hash selects from the lanes with an entry.
func (l *txLanes) pick(hash uint32) *txSA {
	if l == nil {
		return nil
	}
	n := 0
	for _, sa := range l {
		if sa != nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	i := int(hash % uint32(n))
	for _, sa := range l {
		if sa == nil {
			continue
		}
		if i == 0 {
			return sa
		}
		i--
	}
	return nil
}

func (l *txLanes) empty() bool { return *l == txLanes{} }

// newKey returns the key of a for an SA key of 16 or 32 bytes, and its PSP version.
func newKey(a AEAD, key []byte) (AEADKey, psp.Version, error) {
	v := psp.AESGCM128
	if len(key) == psp.AESGCM256.KeyLen() {
		v = psp.AESGCM256
	}
	k, err := a.NewKey(key)
	return k, v, err
}

var _ PspSa = (*part)(nil)

// Open is the first half of keys.open, in parse. With the RX entry of spi, and the version of the
// entry and a sequence number in the packet, it adds one open op of the packet to the batch and
// gives 0. Else it gives the drop reason. It sets the port, session, SPI and lane of the RX entry
// and the VNI of the packet in m.
func (x *part) Open(pkt *packet, spi uint32, m *meta) uint8 {
	sa := x.st.rx[spi]
	switch {
	case sa == nil:
		return ReasonUnknownSPI
	case psp.Version(pkt.h.psp.version) != sa.version || pkt.h.vc.flags&psp.FlagSeq == 0:
		return ReasonOpen
	}
	mem, off := x.tx.in(pkt.mem, pkt.in)
	pkt.mem, pkt.sa, pkt.op = mem, sa, len(x.tx.opens)
	x.tx.opens = append(x.tx.opens, AEADOp{Key: sa.key, Mem: mem, Off: off, Len: len(pkt.in)})
	m.port, m.saSession, m.spi, m.lane, m.vni = sa.port, sa.session, sa.spi, sa.lane, pkt.h.vc.vni
	return 0
}

// Opened is the second half of keys.open, in apply in RX order, after the AEAD: the result of the
// open op, Next Header and the replay window. Then the packet after the PSP header is the payload.
func (x *part) Opened(pkt *packet, m *meta) uint8 {
	op := &x.tx.opens[pkt.op]
	payload, ok := pkt.sa.opened(pkt.h.vc.seq, x.tx.memories()[op.Mem][op.Off:op.Off+op.Len], op.OK)
	if !ok {
		return ReasonOpen
	}
	pkt.data = payload
	return 0
}

// Count is keys.count: it adds a packet to the RX entry of spi.
func (x *part) Count(_ *packet, spi uint32) { x.st.count(spi) }

// opened is keys.open after the AEAD opened the PSP packet pkt with the sequence number seq in
// place: ok tells that pkt authenticates. It checks Next Header and the replay window, and moves
// seq. It returns the payload, or false. It does not count the packet: check_in counts it after the
// meters.
func (sa *rxSA) opened(seq uint32, pkt []byte, ok bool) ([]byte, bool) {
	if !ok {
		return nil, false
	}
	end := len(pkt) - psp.ICVLen
	payload := pkt[psp.PrefixLen:end:end]
	if psp.CheckTrunk(pkt, payload) != nil {
		return nil, false
	}
	sa.mu.Lock()
	ok = sa.window.Check(seq)
	last := sa.window.Last()
	sa.mu.Unlock()
	if !ok {
		return nil, false
	}
	sa.seq.Store(last)
	return payload, true
}

// count adds a packet to the RX entry of spi. Then seq minus packets includes the meter drops.
func (s *state) count(spi uint32) {
	if sa := s.rx[spi]; sa != nil {
		sa.packets.Add(1)
	}
}

var errSeqLimit = errors.New("dp: the TX entry has used all sequence numbers")

// put writes the 24-byte prefix of the next packet of sa into dst, with the Next Header nh and the
// VNI field vni: it takes the next sequence number. The AEAD seals the payload later.
func (sa *txSA) put(dst []byte, nh uint8, vni uint32) error {
	seq := sa.next.Add(1) - 1
	if seq > math.MaxUint32 {
		return errSeqLimit
	}
	h := psp.Header{NextHdr: nh, Version: sa.version, SPI: sa.spi, IV: seq, VNI: vni, Flags: psp.FlagSeq, Seq: uint32(seq)}
	return psp.PutHeader(h, dst)
}

// writeKeys applies one update of the keys extern to the copy, with the keys of a. A key is never
// changed in place, so MODIFY is not valid.
func (c *change) writeKeys(typ p4.Update_Type, ee *p4.ExternEntry, a AEAD) error {
	if ee.GetExternTypeId() != ExternPspSa || ee.GetExternId() != ExternKeys {
		return status.Errorf(codes.NotFound, "unknown extern %#x instance %#x", ee.GetExternTypeId(), ee.GetExternId())
	}
	if ee.GetEntry() == nil {
		return status.Error(codes.InvalidArgument, "the keys entry is empty")
	}
	e := &dpv1.PspSaEntry{}
	if err := ee.GetEntry().UnmarshalTo(e); err != nil {
		return status.Errorf(codes.InvalidArgument, "the keys entry is not a PspSaEntry: %v", err)
	}
	switch {
	case typ == p4.Update_MODIFY:
		return status.Error(codes.InvalidArgument, "a key is never changed in place: delete it and insert a new SPI")
	case typ != p4.Update_INSERT && typ != p4.Update_DELETE:
		return status.Error(codes.InvalidArgument, "the update has no type")
	case psp.ReservedSPI(e.GetSpi()):
		return status.Errorf(codes.InvalidArgument, "SPI %#x is reserved", e.GetSpi())
	case typ == p4.Update_INSERT && e.GetLane() >= lanes:
		return status.Errorf(codes.InvalidArgument, "lane %d is not 0 to %d", e.GetLane(), lanes-1)
	}
	var key AEADKey
	var version psp.Version
	if typ == p4.Update_INSERT {
		var err error
		if key, version, err = newKey(a, e.GetKey()); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	st := c.st
	switch e.GetDirection() {
	case dpv1.PspSaDirection_PSP_SA_DIRECTION_RX:
		_, had := st.rx[e.GetSpi()]
		if typ == p4.Update_DELETE {
			if !had {
				return status.Errorf(codes.NotFound, "no RX entry for SPI %#x", e.GetSpi())
			}
			delete(own(&st.rx, &c.rx), e.GetSpi())
			return nil
		}
		if had {
			return status.Errorf(codes.AlreadyExists, "SPI %#x has an RX entry", e.GetSpi())
		}
		own(&st.rx, &c.rx)[e.GetSpi()] = &rxSA{
			spi: e.GetSpi(), port: e.GetPort(), session: e.GetSession(), lane: uint8(e.GetLane()),
			version: version, key: key,
		}
		return nil
	case dpv1.PspSaDirection_PSP_SA_DIRECTION_TX:
		k := portSession{e.GetPort(), e.GetSession()}
		l := st.tx[k]
		lane := -1
		if l != nil {
			for i, sa := range l {
				if sa != nil && sa.spi == e.GetSpi() {
					lane = i
				}
			}
		}
		if typ == p4.Update_DELETE {
			if lane < 0 {
				return status.Errorf(codes.NotFound, "no TX entry for SPI %#x of this port session", e.GetSpi())
			}
			l = c.ownLanes(k)
			l[lane] = nil
			if l.empty() {
				delete(st.tx, k)
			}
			return nil
		}
		if lane >= 0 || (l != nil && l[e.GetLane()] != nil) {
			return status.Errorf(codes.AlreadyExists, "SPI %#x or lane %d of this port session has a TX entry", e.GetSpi(), e.GetLane())
		}
		c.ownLanes(k)[e.GetLane()] = &txSA{spi: e.GetSpi(), lane: uint8(e.GetLane()), version: version, key: key}
		return nil
	}
	return status.Errorf(codes.InvalidArgument, "unknown direction %d", e.GetDirection())
}

// ownLanes returns the TX lanes of k to change. At the first change it copies them, or makes new
// lanes, and copies the map of them. The TX entries stay shared, with their sequence numbers.
func (c *change) ownLanes(k portSession) *txLanes {
	l := c.st.tx[k]
	if l != nil && c.lanes[k] {
		return l
	}
	n := &txLanes{}
	if l != nil {
		*n = *l
	}
	own(&c.st.tx, &c.tx)[k] = n
	if c.lanes == nil {
		c.lanes = map[portSession]bool{}
	}
	c.lanes[k] = true
	return n
}

// readKeys gives the keys entries that match ee, with no key. An RX entry also has its packet
// count and its highest accepted sequence number. A filter with an SPI gives only that SPI.
func (s *state) readKeys(ee *p4.ExternEntry, out *[]*p4.Entity) error {
	if (ee.GetExternTypeId() != 0 && ee.GetExternTypeId() != ExternPspSa) || (ee.GetExternId() != 0 && ee.GetExternId() != ExternKeys) {
		return status.Errorf(codes.NotFound, "unknown extern %#x instance %#x", ee.GetExternTypeId(), ee.GetExternId())
	}
	var f *dpv1.PspSaEntry
	if ee.GetEntry() != nil {
		f = &dpv1.PspSaEntry{}
		if err := ee.GetEntry().UnmarshalTo(f); err != nil {
			return status.Errorf(codes.InvalidArgument, "the keys entry is not a PspSaEntry: %v", err)
		}
		if f.GetSpi() == 0 {
			f = nil
		}
	}
	add := func(e *dpv1.PspSaEntry) error {
		if f != nil && (f.GetDirection() != e.GetDirection() || f.GetSpi() != e.GetSpi()) {
			return nil
		}
		x, err := KeysEntry(e)
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		*out = append(*out, &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: x}})
		return nil
	}
	for _, sa := range s.rx {
		if err := add(&dpv1.PspSaEntry{
			Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: sa.spi, Port: sa.port, Session: sa.session,
			Lane: uint32(sa.lane), Packets: sa.packets.Load(), Seq: sa.seq.Load(),
		}); err != nil {
			return err
		}
	}
	for k, l := range s.tx {
		for _, sa := range l {
			if sa == nil {
				continue
			}
			if err := add(&dpv1.PspSaEntry{
				Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: sa.spi, Port: k.port, Session: k.session, Lane: uint32(sa.lane),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
