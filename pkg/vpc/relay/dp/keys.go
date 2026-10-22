// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"crypto/cipher"
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
	aead          cipher.AEAD

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
	aead    cipher.AEAD
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

func newAEAD(key []byte) (cipher.AEAD, psp.Version, error) {
	v := psp.AESGCM128
	if len(key) == psp.AESGCM256.KeyLen() {
		v = psp.AESGCM256
	}
	aead, err := psp.NewAEAD(key)
	return aead, v, err
}

// open opens the PSP packet b with header h in place and moves seq. It returns the payload, or
// false when the packet does not authenticate, has no sequence number or is a replay. It does not
// count the packet: check_in counts it after the meters.
func (sa *rxSA) open(h psp.Header, b []byte) ([]byte, bool) {
	if h.Version != sa.version || h.Flags&psp.FlagSeq == 0 {
		return nil, false
	}
	payload, err := psp.OpenTrunkInPlace(sa.aead, b)
	if err != nil {
		return nil, false
	}
	sa.mu.Lock()
	ok := sa.window.Check(h.Seq)
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

// seal seals payload into dst with the VNI field vni. An IPv4 or IPv6 payload gets its own Next
// Header; any other payload, such as a trunk message, gets the PSP Next Header.
func (sa *txSA) seal(dst []byte, vni uint32, payload []byte) (int, error) {
	seq := sa.next.Add(1) - 1
	if seq > math.MaxUint32 {
		return 0, errSeqLimit
	}
	h := psp.Header{Version: sa.version, SPI: sa.spi, IV: seq, VNI: vni, Flags: psp.FlagSeq, Seq: uint32(seq)}
	if len(payload) > 0 && (payload[0]>>4 == 4 || payload[0]>>4 == 6) {
		return psp.Seal(sa.aead, h, dst, payload)
	}
	return psp.SealPSP(sa.aead, h, dst, payload)
}

// writeKeys applies one update of the keys extern. A key is never changed in place, so MODIFY is
// not valid.
func (s *state) writeKeys(t *txn, typ p4.Update_Type, ee *p4.ExternEntry) error {
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
	var aead cipher.AEAD
	var version psp.Version
	if typ == p4.Update_INSERT {
		var err error
		if aead, version, err = newAEAD(e.GetKey()); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	switch e.GetDirection() {
	case dpv1.PspSaDirection_PSP_SA_DIRECTION_RX:
		_, had := s.rx[e.GetSpi()]
		if typ == p4.Update_DELETE {
			if !had {
				return status.Errorf(codes.NotFound, "no RX entry for SPI %#x", e.GetSpi())
			}
			del(t, s.rx, e.GetSpi())
			return nil
		}
		if had {
			return status.Errorf(codes.AlreadyExists, "SPI %#x has an RX entry", e.GetSpi())
		}
		set(t, s.rx, e.GetSpi(), &rxSA{
			spi: e.GetSpi(), port: e.GetPort(), session: e.GetSession(), lane: uint8(e.GetLane()),
			version: version, aead: aead,
		})
		return nil
	case dpv1.PspSaDirection_PSP_SA_DIRECTION_TX:
		k := portSession{e.GetPort(), e.GetSession()}
		l := s.tx[k]
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
			setLane(t, l, lane, nil)
			if l.empty() {
				del(t, s.tx, k)
			}
			return nil
		}
		if lane >= 0 || (l != nil && l[e.GetLane()] != nil) {
			return status.Errorf(codes.AlreadyExists, "SPI %#x or lane %d of this port session has a TX entry", e.GetSpi(), e.GetLane())
		}
		if l == nil {
			l = &txLanes{}
			set(t, s.tx, k, l)
		}
		setLane(t, l, int(e.GetLane()), &txSA{spi: e.GetSpi(), lane: uint8(e.GetLane()), version: version, aead: aead})
		return nil
	}
	return status.Errorf(codes.InvalidArgument, "unknown direction %d", e.GetDirection())
}

func setLane(t *txn, l *txLanes, i int, sa *txSA) {
	old := l[i]
	l[i] = sa
	t.onUndo(func() { l[i] = old })
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
