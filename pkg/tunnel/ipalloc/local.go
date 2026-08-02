package ipalloc

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// maxSlots is the size of a network's slot id space (16 bits).
const maxSlots = 1 << 16

// LocalSlotLeaser is the OSS/single-tenant SlotLeaser. It tracks each network's
// slot ids entirely in process memory — there is no infra tier, so leases have
// no TTL (Renew is a no-op) and nothing survives a restart. The API is
// identical to the cloud infra-backed implementation so the relay wiring is the
// same in both modes.
//
// It is correct only while a single process allocates for a network. Two
// processes each start from an empty bitmap and both hand out the lowest free
// id, so their connections collide on identical /96s. Any deployment running
// more than one relay per network must use an infra-backed leaser.
type LocalSlotLeaser struct {
	mu   sync.Mutex
	nets map[tunnet.NetworkID]*bitmap.Bitmap
	// v4 backs each leased slot with a /24 of 100.64.0.0/10. The pool spans
	// every network the process serves: a single process is the whole
	// deployment here, so process-wide uniqueness is global uniqueness — the
	// property the infra leaser provides with 240.0.0.0/4 in cloud.
	v4 *V4SlicePool
}

// NewLocalSlotLeaser returns a LocalSlotLeaser.
func NewLocalSlotLeaser() *LocalSlotLeaser {
	return &LocalSlotLeaser{
		nets: make(map[tunnet.NetworkID]*bitmap.Bitmap),
		v4:   NewV4SlicePool(),
	}
}

// Lease reserves an unused slot id in the network.
func (l *LocalSlotLeaser) Lease(_ context.Context, network tunnet.NetworkID) (Slot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	bm, ok := l.nets[network]
	if !ok {
		b := bitmap.New(maxSlots)
		bm = &b
		l.nets[network] = bm
	}

	// Scan from MinSlotID: the reserved low ids must never be handed out, and
	// starting the scan past them is cheaper than allocating and rejecting.
	i, err := bm.FirstZero(MinSlotID)
	if err != nil || i >= maxSlots {
		return Slot{}, ErrNoSlots
	}
	bm.Add(i)

	s := Slot{Network: network, ID: tunnet.EndpointID{byte(i >> 8), byte(i)}}
	// v4 is best-effort (§2.4): an exhausted pool leases the slot v6-only.
	if base, ok := l.v4.take(i); ok {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base)
		s.V4 = netip.PrefixFrom(netip.AddrFrom4(b), 24)
	}
	return s, nil
}

// Renew is a no-op: local leases have no TTL.
func (l *LocalSlotLeaser) Renew(_ context.Context, _ Slot) error {
	return nil
}

// Release returns a slot to the network's pool.
func (l *LocalSlotLeaser) Release(_ context.Context, s Slot) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	bm, ok := l.nets[s.Network]
	if !ok {
		return nil
	}
	bm.Remove(uint32(s.ID[0])<<8 | uint32(s.ID[1]))
	if s.V4.IsValid() {
		l.v4.put(binary.BigEndian.Uint32(s.V4.Masked().Addr().AsSlice()))
	}
	return nil
}
