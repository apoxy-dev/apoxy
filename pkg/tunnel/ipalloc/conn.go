package ipalloc

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"
)

const (
	// connBitsV6 is the width of the per-connection index within a /80 block:
	// the /80→/96 gap, i.e. 65536 connections per block.
	connBitsV6 = 16
	maxConnV6  = 1 << connBitsV6

	// connBitsV4 is the width of the per-connection v4 index: a block maps to a
	// /18 of 100.64.0.0/10 (32−18 = 14 host bits), i.e. 16384 v4 addresses.
	connBitsV4 = 14
	maxConnV4  = 1 << connBitsV4
)

// v4CGNATBase is the uint32 of 100.64.0.0, the base of the 100.64.0.0/10 range
// (§2.4) sliced into a /18 per block index.
var v4CGNATBase = binary.BigEndian.Uint32(netip.MustParseAddr("100.64.0.0").AsSlice())

// ConnAllocator sub-allocates per-connection addresses from a single leased
// /80 block, entirely in-process (§2.8). It is the sole allocator within its
// block, so no cross-process coordination is needed; a mutex guards the two
// bitmaps against concurrent connect/disconnect.
//
// Each connection gets a /96 (IPv6, always) and a /32 (IPv4, best-effort). The
// v4 pool is smaller than the v6 pool by design: v4 is egress-only, so v4
// exhaustion degrades a connection to v6-only rather than failing it. The v4
// /18 is keyed on block index alone, so it intentionally overlaps across
// networks — safe because v4 never leaves its per-network forwarding domain and
// the shared zone is AAAA-only (§2.2/§2.4).
type ConnAllocator struct {
	block   Block
	v4slice uint32 // uint32 base of this block's /18 of 100.64.0.0/10

	mu sync.Mutex
	v6 bitmap.Bitmap
	v4 bitmap.Bitmap
}

// NewConnAllocator returns an allocator over a leased block.
func NewConnAllocator(b Block) *ConnAllocator {
	return &ConnAllocator{
		block:   b,
		v4slice: v4CGNATBase + uint32(b.Index)<<connBitsV4,
		v6:      bitmap.New(maxConnV6),
		v4:      bitmap.New(maxConnV4),
	}
}

// Allocate returns a connection's /96 and, best-effort, its /32. A zero-value
// (invalid) v4 prefix means the block's v4 pool is exhausted and the caller
// should run the connection v6-only. ErrBlockExhausted means the v6 pool is
// full; the caller should lease another block (see Full).
func (a *ConnAllocator) Allocate() (v6 netip.Prefix, v4 netip.Prefix, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	i6, err := a.v6.FirstZero(0)
	if err != nil || i6 >= maxConnV6 {
		return netip.Prefix{}, netip.Prefix{}, ErrBlockExhausted
	}
	a.v6.Add(i6)
	v6 = a.v6PrefixAt(uint16(i6))

	// v4 is best-effort: exhaustion degrades to v6-only, not an error.
	if i4, err4 := a.v4.FirstZero(0); err4 == nil && i4 < maxConnV4 {
		a.v4.Add(i4)
		v4 = a.v4PrefixAt(i4)
	}

	return v6, v4, nil
}

// Release returns a connection's addresses to the block's pools. A zero-value
// prefix for either family is ignored (e.g. a v6-only connection).
func (a *ConnAllocator) Release(v6, v4 netip.Prefix) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// A network may hold several blocks (§2.8: "lease another block under
	// pressure"), each with its own allocator. Guard against a prefix from a
	// foreign block: for v6 it would free the wrong connection's slot (bytes
	// 10–11 encode only the connection index, not the block), and for v4 the
	// index would underflow and index the bitmap out of range (a panic).
	if v6.IsValid() && a.block.Prefix.Contains(v6.Addr()) {
		b := v6.Addr().As16()
		a.v6.Remove(uint32(b[10])<<8 | uint32(b[11]))
	}
	if v4.IsValid() {
		if au := v4.Addr().Unmap(); au.Is4() {
			if u := binary.BigEndian.Uint32(au.AsSlice()); u >= a.v4slice && u < a.v4slice+maxConnV4 {
				a.v4.Remove(u - a.v4slice)
			}
		}
	}
}

// Full reports whether the v6 pool is exhausted, i.e. the caller must lease
// another block to accept more connections.
func (a *ConnAllocator) Full() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.v6.FirstZero(0)
	return err != nil
}

// v6PrefixAt returns the /96 for connection index i within the block, writing
// i into bytes 10–11 (the endpoint field) of the block's /80 base address.
func (a *ConnAllocator) v6PrefixAt(i uint16) netip.Prefix {
	addr := a.block.Prefix.Masked().Addr().As16()
	addr[10] = byte(i >> 8)
	addr[11] = byte(i)
	return netip.PrefixFrom(netip.AddrFrom16(addr), 96)
}

// v4PrefixAt returns the /32 for v4 index i within the block's /18 slice.
func (a *ConnAllocator) v4PrefixAt(i uint32) netip.Prefix {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], a.v4slice+i)
	return netip.PrefixFrom(netip.AddrFrom4(b), 32)
}
