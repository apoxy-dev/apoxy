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

	// v4PerSlot is how many IPv4 addresses a slot gets: a /24 of
	// 100.64.0.0/10, matching the connection count.
	v4PerSlot = 1 << 8

	// maxV4Slot is the exclusive upper bound of slot ids that get a v4 slice.
	// 100.64.0.0/10 has 22 host bits and each slot takes 8 of them, so only the
	// first 2^14 slot ids fit. Slots above it run v6-only — the same documented
	// degradation as v4 exhaustion within a slot, since v4 is egress-only
	// (§2.4).
	maxV4Slot = 1 << (32 - 10 - 8)
)

// v4CGNATBase is the uint32 of 100.64.0.0, the base of the 100.64.0.0/10 range
// (§2.4) sliced into a /24 per slot id.
var v4CGNATBase = binary.BigEndian.Uint32(netip.MustParseAddr("100.64.0.0").AsSlice())

// ConnAllocator sub-allocates per-connection addresses from a single leased
// slot, entirely in-process (§2.8). It is the sole allocator within its slot,
// so no cross-process coordination is needed; a mutex guards the two bitmaps
// against concurrent connect/disconnect.
//
// Each connection gets a /96 (IPv6, always) and a /32 (IPv4, best-effort). The
// v4 pool is the weaker of the two by design: v4 is egress-only, so v4
// exhaustion — or a slot id too high to have a v4 slice at all — degrades a
// connection to v6-only rather than failing it. The v4 /24 is keyed on slot id
// alone, so it intentionally overlaps across networks — safe because v4 never
// leaves its per-network forwarding domain and the shared zone is AAAA-only
// (§2.2/§2.4).
type ConnAllocator struct {
	slot    Slot
	hasV4   bool   // false for slot ids past the end of 100.64.0.0/10
	v4slice uint32 // uint32 base of this slot's /24 of 100.64.0.0/10

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

	slotID := uint32(s.ID[0])<<8 | uint32(s.ID[1])
	if slotID < maxV4Slot {
		a.hasV4 = true
		a.v4slice = v4CGNATBase + slotID<<8
		a.v4 = bitmap.New(v4PerSlot)
	}
	return a
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
// prefix for either family is ignored (e.g. a v6-only connection).
func (a *ConnAllocator) Release(v6, v4 netip.Prefix) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// A network may hold several slots (§2.8: "lease another block under
	// pressure"), each with its own allocator. Guard against a prefix from a
	// foreign slot: for v6 it would free the wrong connection's index (byte 11
	// encodes only the connection, not the slot), and for v4 the index would
	// underflow and index the bitmap out of range (a panic).
	if v6.IsValid() {
		if s, conn, ok := SlotOf(v6); ok && s == a.slot {
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
