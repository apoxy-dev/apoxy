package ipalloc

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"
)

const (
	// connSlots is the size of a slot's connection index space (byte 11). Index
	// 0 is the slot's own endpoint address and is permanently marked in use, so
	// ConnsPerSlot of these are actually allocatable.
	connSlots = 1 << 8

	// v4PerSlot is how many IPv4 addresses a slot gets: one /24, matching the
	// connection count.
	v4PerSlot = 1 << 8

	// v4Slices is how many /24s 100.64.0.0/10 holds: 22 host bits, 8 of them
	// taken by the connection index.
	v4Slices = 1 << (32 - 10 - 8)
)

// v4CGNATBase is the uint32 of 100.64.0.0, the base of the 100.64.0.0/10 range
// (§2.4) the local leaser slices into a /24 per v4-backed slot.
var v4CGNATBase = binary.BigEndian.Uint32(netip.MustParseAddr("100.64.0.0").AsSlice())

// V4SlicePool hands out the /24s of 100.64.0.0/10, one per slot. It backs
// LocalSlotLeaser, where one process is the whole deployment; cloud slots get
// their /24 from the infra endpoint allocator instead, which allocates
// globally so the same /32 can never reach one agent from two relays.
type V4SlicePool struct {
	mu   sync.Mutex
	used bitmap.Bitmap
}

// NewV4SlicePool returns an empty pool over 100.64.0.0/10.
func NewV4SlicePool() *V4SlicePool {
	return &V4SlicePool{used: bitmap.New(v4Slices)}
}

// take reserves a /24 and returns its base as a uint32, preferring the slice
// the slot id names. ok is false when every slice is held, which runs the slot
// v6-only (§2.4).
func (p *V4SlicePool) take(slot uint32) (base uint32, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Preferred slice first, then wrap, so only a full pool comes up empty.
	pref := slot % v4Slices
	for _, span := range [2][2]uint32{{pref, v4Slices}, {0, pref}} {
		free, err := p.used.FirstZero(span[0])
		if err != nil || free >= span[1] {
			continue
		}
		p.used.Add(free)
		return v4CGNATBase + free<<8, true
	}
	return 0, false
}

// put returns a /24 to the pool.
func (p *V4SlicePool) put(base uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used.Remove((base - v4CGNATBase) >> 8)
}

// ConnAllocator sub-allocates per-connection addresses from a single leased
// slot, entirely in-process. It is the sole allocator within its slot,
// so no cross-process coordination is needed; a mutex guards the two bitmaps
// against concurrent connect/disconnect.
//
// Each connection gets a /96 (IPv6, always) and a /32 (IPv4, best-effort). The
// v4 side is the weaker of the two by design: v4 is egress-only, so v4
// exhaustion — or a slot leased without a /24 — degrades a connection to
// v6-only rather than failing it. The /24 is the slot's own (Slot.V4); its
// lifetime is the lease's, so there is nothing to return here when the slot
// goes away.
type ConnAllocator struct {
	slot    Slot
	hasV4   bool   // false when the leaser had no /24 to back this slot
	v4slice uint32 // uint32 base of this slot's /24

	mu sync.Mutex
	v6 bitmap.Bitmap
	v4 bitmap.Bitmap
}

// NewConnAllocator returns an allocator over a leased slot.
func NewConnAllocator(s Slot) *ConnAllocator {
	a := &ConnAllocator{
		slot: s,
		v6:   bitmap.New(connSlots),
	}
	// Connection index 0 is the slot's own endpoint /96: the infrastructure
	// allocator owns that address, so it is never available to a connection.
	a.v6.Add(0)

	if s.V4.IsValid() {
		a.hasV4 = true
		a.v4slice = binary.BigEndian.Uint32(s.V4.Masked().Addr().AsSlice())
		a.v4 = bitmap.New(v4PerSlot)
	}
	return a
}

// Slot returns the immutable leased slot that backs this allocator.
func (a *ConnAllocator) Slot() Slot {
	return a.slot
}

// Allocate returns a connection's /96 and, best-effort, its /32. A zero-value
// (invalid) v4 prefix means this slot has no v4 space left (or never had any);
// the caller should run the connection v6-only. ErrSlotExhausted means the v6
// pool is full; the caller should lease another slot (see Full).
func (a *ConnAllocator) Allocate() (v6 netip.Prefix, v4 netip.Prefix, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	i6, err := a.v6.FirstZero(0)
	if err != nil || i6 >= connSlots {
		return netip.Prefix{}, netip.Prefix{}, ErrSlotExhausted
	}
	a.v6.Add(i6)
	v6 = ConnPrefix(a.slot, uint8(i6))

	// v4 is best-effort: exhaustion degrades to v6-only, not an error.
	if a.hasV4 {
		if i4, err4 := a.v4.FirstZero(0); err4 == nil && i4 < v4PerSlot {
			a.v4.Add(i4)
			v4 = a.v4PrefixAt(i4)
		}
	}

	return v6, v4, nil
}

// Release returns a connection's addresses to the slot's pools. A zero-value
// prefix for either family is ignored (e.g. a v6-only connection, or a
// connection whose /32 was dropped because it could not be programmed).
func (a *ConnAllocator) Release(v6, v4 netip.Prefix) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// A network may hold several slots (§2.8: "lease another block under
	// pressure"), each with its own allocator. Guard against a prefix from a
	// foreign slot: for v6 it would free the wrong connection's index (byte 11
	// encodes only the connection, not the slot), and for v4 the index would
	// underflow and index the bitmap out of range (a panic).
	if v6.IsValid() {
		if s, conn, ok := SlotOf(v6); ok && s.Network == a.slot.Network && s.ID == a.slot.ID {
			a.v6.Remove(uint32(conn))
		}
	}
	if a.hasV4 && v4.IsValid() {
		if au := v4.Addr().Unmap(); au.Is4() {
			if u := binary.BigEndian.Uint32(au.AsSlice()); u >= a.v4slice && u < a.v4slice+v4PerSlot {
				a.v4.Remove(u - a.v4slice)
			}
		}
	}
}

// Full reports whether the v6 pool is exhausted, i.e. the caller must lease
// another slot to accept more connections.
func (a *ConnAllocator) Full() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.v6.FirstZero(0)
	return err != nil
}

// v4PrefixAt returns the /32 for v4 index i within the slot's /24 slice.
func (a *ConnAllocator) v4PrefixAt(i uint32) netip.Prefix {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], a.v4slice+i)
	return netip.PrefixFrom(netip.AddrFrom4(b), 32)
}

// slotID is a slot's 16-bit identifier as a number.
func slotID(s Slot) uint32 {
	return uint32(s.ID[0])<<8 | uint32(s.ID[1])
}
