package ipalloc

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

func TestSlotAddressRoundTrip(t *testing.T) {
	id := tunnet.NetworkID{0x12, 0x34, 0x56}
	net72 := tunnet.NetworkPrefix(id)

	for _, slotID := range []tunnet.EndpointID{{0x01, 0x00}, {0x01, 0x23}, {0x12, 0x34}, {0xff, 0xff}} {
		s := Slot{Network: id, ID: slotID}
		slot88 := SlotPrefix(s)
		require.Equal(t, 88, slot88.Bits())

		for _, conn := range []uint8{1, 2, 128, 255} {
			p := ConnPrefix(s, conn)
			require.Equal(t, 96, p.Bits())
			require.True(t, net72.Contains(p.Addr()), "connection stays within its network /72")
			require.True(t, slot88.Contains(p.Addr()), "connection stays within its slot /88")
			require.Equal(t, slot88, SlotPrefixOf(p.Addr()), "slot /88 recovers from any of its addresses")

			gotSlot, gotConn, ok := SlotOf(p)
			require.True(t, ok, "%s is a connection address", p)
			require.Equal(t, s, gotSlot, "slot round-trips")
			require.Equal(t, conn, gotConn, "connection index round-trips")

			b := p.Addr().As16()
			require.Equal(t, id[:], b[6:9], "network id preserved")
			require.Equal(t, slotID[:], b[9:11], "slot id lands in bytes 9-10")
			require.Equal(t, conn, b[11], "connection index lands in byte 11")
		}
	}
}

// TestSlotPrefixDiscriminatesRelays is the property that makes a blanket route
// safe: an address's slot must be decidable from bits ABOVE the per-connection
// index. Two relays' addresses must never share more prefix with each other
// than two addresses of the same relay do, or longest-prefix source selection
// picks an address the destination's relay never leased — and relays do not
// federate, so the packet is dropped.
func TestSlotPrefixDiscriminatesRelays(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x00, 0x01}
	west := Slot{Network: id, ID: tunnet.EndpointID{0x01, 0x09}}
	east := Slot{Network: id, ID: tunnet.EndpointID{0x01, 0x0a}}

	// Same relay, different connection indices: the addresses an agent and its
	// peer hold on one relay.
	ours := ConnPrefix(west, 3)
	peer := ConnPrefix(west, 4)
	// A different relay, at the connection index that used to win the match.
	other := ConnPrefix(east, 4)

	require.Greater(t,
		commonPrefixBits(ours.Addr(), peer.Addr()),
		commonPrefixBits(other.Addr(), peer.Addr()),
		"an address on the peer's own relay must match it more closely than one on another relay")
	require.Equal(t, SlotPrefix(west), SlotPrefixOf(peer.Addr()))
	require.NotEqual(t, SlotPrefix(west), SlotPrefixOf(other.Addr()))
}

// commonPrefixBits is what RFC 6724 rule 8 compares when the kernel picks a
// source address among several on one device.
func commonPrefixBits(a, b netip.Addr) int {
	x, y := a.As16(), b.As16()
	for i := 0; i < 128; i++ {
		if (x[i/8]>>(7-i%8))&1 != (y[i/8]>>(7-i%8))&1 {
			return i
		}
	}
	return 128
}

// TestConnAddressesNeverCollideWithEndpoints pins the invariant MinSlotID
// exists for: an infrastructure endpoint /96 — the shape NetULA hands out, and
// what every legacy tunnelproxy connection holds — can never equal a relay
// connection address.
//
// Infra puts its endpoint identifier in bytes 10-11 and leaves byte 9 zero; a
// slot puts its identifier in bytes 9-10, so reserving slot ids below 0x0100
// keeps byte 9 nonzero on every relay-minted address and the two spaces
// disjoint. That is what SlotOf's byte-9 test decides.
func TestConnAddressesNeverCollideWithEndpoints(t *testing.T) {
	ctx := context.Background()
	id := tunnet.NetworkID{0x00, 0x00, 0x00} // the legacy "default" network

	endpoints := map[netip.Addr]bool{}
	for _, epID := range []tunnet.EndpointID{{0x00, 0x00}, {0x00, 0x01}, {0x12, 0x34}, {0xff, 0xff}} {
		ula, err := tunnet.NewULA(ctx, id).WithEndpoint(ctx, epID)
		require.NoError(t, err)
		ep := ula.FullPrefix()
		require.Equal(t, 96, ep.Bits())
		require.Equal(t, byte(0), ep.Addr().As16()[9],
			"infra leaves byte 9 zero, which is what makes the reservation work")

		// An endpoint address is never mistaken for a connection address.
		_, _, ok := SlotOf(ep)
		require.False(t, ok, "endpoint %s must not decode as a connection", ep)
		endpoints[ep.Addr()] = true
	}

	// Nothing a relay allocates from an id at or above MinSlotID can land on
	// one of them.
	for _, epID := range []tunnet.EndpointID{{0x01, 0x00}, {0x12, 0x34}, {0xff, 0xff}} {
		a := NewConnAllocator(Slot{Network: id, ID: epID})
		for i := 0; i < 4; i++ {
			v6, _, err := a.Allocate()
			require.NoError(t, err)
			require.False(t, endpoints[v6.Addr()], "connection %s collided with an endpoint", v6)
			require.NotEqual(t, byte(0), v6.Addr().As16()[9])
		}
	}

	// A reserved id would break it, which is why no leaser may hand one out.
	reserved := ConnPrefix(Slot{Network: id, ID: tunnet.EndpointID{0x00, 0x09}}, 4)
	_, _, ok := SlotOf(reserved)
	require.False(t, ok, "an address from a reserved slot id must not decode as a connection")
}

func TestLocalSlotLeaser(t *testing.T) {
	ctx := context.Background()
	idA := tunnet.NetworkID{0x00, 0x00, 0x01}
	idB := tunnet.NetworkID{0x00, 0x00, 0x02}

	t.Run("distinct slots per network", func(t *testing.T) {
		l := NewLocalSlotLeaser()
		seen := map[tunnet.EndpointID]bool{}
		for i := 0; i < 8; i++ {
			s, err := l.Lease(ctx, idA)
			require.NoError(t, err)
			require.Equal(t, idA, s.Network)
			require.False(t, seen[s.ID], "slot %v handed out twice", s.ID)
			seen[s.ID] = true
		}
	})

	t.Run("never leases a reserved slot id", func(t *testing.T) {
		l := NewLocalSlotLeaser()
		for i := 0; i < 8; i++ {
			s, err := l.Lease(ctx, idA)
			require.NoError(t, err)
			require.GreaterOrEqual(t, int(s.ID[0])<<8|int(s.ID[1]), MinSlotID,
				"a reserved id would collide with the pre-slot addressing scheme")
		}
	})

	t.Run("release returns slot to pool", func(t *testing.T) {
		l := NewLocalSlotLeaser()
		s, err := l.Lease(ctx, idA)
		require.NoError(t, err)
		require.NoError(t, l.Release(ctx, s))
		s2, err := l.Lease(ctx, idA)
		require.NoError(t, err)
		require.Equal(t, s.ID, s2.ID, "freed slot id is reused")
	})

	t.Run("exhaustion after every slot", func(t *testing.T) {
		l := NewLocalSlotLeaser()
		// The reserved low ids are not leasable, so the pool is that much
		// smaller than the raw 16-bit id space.
		for i := 0; i < maxSlots-MinSlotID; i++ {
			_, err := l.Lease(ctx, idA)
			require.NoError(t, err, "lease %d", i)
		}
		_, err := l.Lease(ctx, idA)
		require.ErrorIs(t, err, ErrNoSlots, "one lease past the end fails")
	})

	t.Run("networks have independent slot spaces", func(t *testing.T) {
		l := NewLocalSlotLeaser()
		a, err := l.Lease(ctx, idA)
		require.NoError(t, err)
		b, err := l.Lease(ctx, idB)
		require.NoError(t, err)
		// Same slot id (both first slots) but disjoint networks.
		require.Equal(t, a.ID, b.ID)
		require.NotEqual(t, ConnPrefix(a, 1).Addr(), ConnPrefix(b, 1).Addr(),
			"different networks' connections are disjoint")
	})
}

// newConnAllocator leases a slot and returns an allocator over it.
func newConnAllocator(t *testing.T, id tunnet.NetworkID) *ConnAllocator {
	t.Helper()
	l := NewLocalSlotLeaser()
	s, err := l.Lease(context.Background(), id)
	require.NoError(t, err)
	return NewConnAllocator(s)
}

func TestConnAllocatorV6(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0a, 0x01}
	a := newConnAllocator(t, id)

	first, _, err := a.Allocate()
	require.NoError(t, err)
	require.Equal(t, 96, first.Bits())
	require.Equal(t, byte(1), first.Addr().As16()[9], "first connection skips the endpoint index")

	second, _, err := a.Allocate()
	require.NoError(t, err)
	require.NotEqual(t, first.Addr(), second.Addr(), "distinct /96s")

	// Release the first and confirm it is reused (lowest free wins).
	a.Release(first, netip.Prefix{})
	reused, _, err := a.Allocate()
	require.NoError(t, err)
	require.Equal(t, first.Addr(), reused.Addr(), "freed /96 is reused")
}

func TestConnAllocatorV4Derivation(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0b, 0x01}
	a := newConnAllocator(t, id)

	// The slot's whole v4 space is the /24 keyed on slot id.
	wantSlice := netip.PrefixFrom(u32Addr(a.v4slice), 24)
	require.True(t, netip.MustParsePrefix("100.64.0.0/10").Overlaps(wantSlice))

	prev := map[netip.Addr]bool{}
	for i := 0; i < 4; i++ {
		_, v4, err := a.Allocate()
		require.NoError(t, err)
		require.True(t, v4.IsValid())
		require.Equal(t, 32, v4.Bits())
		require.True(t, wantSlice.Contains(v4.Addr()), "/32 falls in the slot's /24")
		require.False(t, prev[v4.Addr()], "distinct /32s")
		prev[v4.Addr()] = true
	}
}

// TestV4SlicePoolHighSlot covers slot ids past the end of the /24 space: the
// preferred slice wraps, and every slot still gets one while the pool has any
// free. The old "high slot ids are v6-only" rule went with the derivation.
func TestV4SlicePoolHighSlot(t *testing.T) {
	pool := NewV4SlicePool()

	cases := []struct {
		name string
		slot uint32
	}{
		{"first wrapped id", v4Slices},
		{"last id", 0xffff},
		{"last unwrapped id", v4Slices - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, ok := pool.take(tc.slot)
			require.True(t, ok, "a slice is still available")
			require.True(t, netip.MustParsePrefix("100.64.0.0/10").Contains(u32Addr(base)),
				"the slice stays inside CGNAT space")
		})
	}
}

// TestConnAllocatorNoSliceV6Only pins the §2.4 degradation: a slot leased
// without a /24 (the leaser's pool was dry) runs v6-only rather than failing.
func TestConnAllocatorNoSliceV6Only(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0b, 0x03}

	a := NewConnAllocator(Slot{Network: id, ID: tunnet.EndpointID{0x01, 0x00}})
	v6, v4, err := a.Allocate()
	require.NoError(t, err, "a v4-less slot still allocates")
	require.True(t, v6.IsValid())
	require.Equal(t, 96, v6.Bits())
	require.False(t, v4.IsValid(), "no slice backs this slot")

	// Releasing must not touch the absent v4 bitmap.
	require.NotPanics(t, func() { a.Release(v6, netip.MustParsePrefix("100.64.0.1/32")) })
}

func TestConnAllocatorV4ExhaustionV6Only(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0c, 0x01}
	a := newConnAllocator(t, id)

	// The v4 pool has one more address than the slot has connections, so drain
	// it while releasing each v6 index to keep the v6 pool available.
	for i := 0; i < v4PerSlot; i++ {
		v6, v4, err := a.Allocate()
		require.NoError(t, err)
		require.True(t, v4.IsValid(), "v4 available for the first %d", v4PerSlot)
		a.Release(v6, netip.Prefix{}) // free v6 only; v4 stays held
	}

	// Next allocation still yields a v6 /96, but no v4 — and no error.
	v6, v4, err := a.Allocate()
	require.NoError(t, err, "v4 exhaustion is not an error")
	require.True(t, v6.IsValid(), "v6 keeps flowing")
	require.Equal(t, 96, v6.Bits())
	require.False(t, v4.IsValid(), "connection degrades to v6-only")
}

func TestConnAllocatorV6Exhaustion(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0d, 0x01}
	a := newConnAllocator(t, id)

	require.False(t, a.Full())
	for i := 0; i < ConnsPerSlot; i++ {
		_, _, err := a.Allocate()
		require.NoError(t, err, "connection %d", i)
	}
	require.True(t, a.Full(), "slot reports full once its 255 connections are taken")
	_, _, err := a.Allocate()
	require.ErrorIs(t, err, ErrSlotExhausted)
}

func TestConnAllocatorReleaseReuse(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0e, 0x01}
	a := newConnAllocator(t, id)

	v6a, v4a, err := a.Allocate()
	require.NoError(t, err)
	v6b, v4b, err := a.Allocate()
	require.NoError(t, err)

	// Free the first connection; both families' slots return to the pool.
	a.Release(v6a, v4a)
	v6c, v4c, err := a.Allocate()
	require.NoError(t, err)
	require.Equal(t, v6a.Addr(), v6c.Addr(), "v6 index reused")
	require.Equal(t, v4a.Addr(), v4c.Addr(), "v4 index reused")
	require.NotEqual(t, v6b.Addr(), v6c.Addr(), "still-held index untouched")
	require.NotEqual(t, v4b.Addr(), v4c.Addr())
}

// TestLocalLeaserCrossNetworkV4Disjoint pins what the relay's single
// forwarding domain requires: two networks whose slots share an id — the norm,
// since slot ids are numbered per network — must not get the same /24. They
// once did, and the second network's connect died on an EEXIST route add.
func TestLocalLeaserCrossNetworkV4Disjoint(t *testing.T) {
	ctx := context.Background()
	l := NewLocalSlotLeaser()
	sa, err := l.Lease(ctx, tunnet.NetworkID{0x00, 0x00, 0x01})
	require.NoError(t, err)
	sb, err := l.Lease(ctx, tunnet.NetworkID{0x00, 0x00, 0x02})
	require.NoError(t, err)
	require.Equal(t, sa.ID, sb.ID, "both first slots share an id")

	aa, ab := NewConnAllocator(sa), NewConnAllocator(sb)
	v6a, v4a, err := aa.Allocate()
	require.NoError(t, err)
	v6b, v4b, err := ab.Allocate()
	require.NoError(t, err)

	require.True(t, v4a.IsValid() && v4b.IsValid(), "both networks keep v4")
	require.NotEqual(t, v4a.Addr(), v4b.Addr(), "one leaser never repeats a /24 across networks")
	require.NotEqual(t, v6a.Addr(), v6b.Addr(), "v6 stays globally unique via disjoint networks")

	require.Equal(t, v4CGNATBase+slotID(sa)<<8, binary.BigEndian.Uint32(v4a.Addr().AsSlice()),
		"the uncontended slot keeps its preferred slice")
}

// TestLocalLeaserV4Lifecycle covers the /24's lifetime, which is the lease's:
// a released slot's slice comes back for the next lease, and a slice is never
// shared while its slot is held.
func TestLocalLeaserV4Lifecycle(t *testing.T) {
	ctx := context.Background()
	l := NewLocalSlotLeaser()
	idA := tunnet.NetworkID{0x00, 0x00, 0x03}
	idB := tunnet.NetworkID{0x00, 0x00, 0x04}

	sa, err := l.Lease(ctx, idA)
	require.NoError(t, err)
	require.True(t, sa.V4.IsValid())
	sb, err := l.Lease(ctx, idB)
	require.NoError(t, err)
	require.True(t, sb.V4.IsValid())
	require.NotEqual(t, sa.V4, sb.V4, "a held slice is not re-handed")

	// Re-leasing in network A reuses the freed slot id, whose preferred slice
	// is exactly the one the release returned.
	require.NoError(t, l.Release(ctx, sa))
	sc, err := l.Lease(ctx, idA)
	require.NoError(t, err)
	require.Equal(t, sa.ID, sc.ID, "freed slot id is reused")
	require.Equal(t, sa.V4, sc.V4, "the released slice is back in the pool")
}

// TestConnAllocatorReleaseForeignSlot pins the §2.8 multi-slot guard: a prefix
// from a different slot must be ignored, never panicking (v4 underflow) or
// freeing a live index in the wrong slot (v6 collision on connection index).
func TestConnAllocatorReleaseForeignSlot(t *testing.T) {
	ctx := context.Background()
	l := NewLocalSlotLeaser()
	id := tunnet.NetworkID{0x00, 0x0f, 0x01}
	s0, err := l.Lease(ctx, id)
	require.NoError(t, err)
	s1, err := l.Lease(ctx, id)
	require.NoError(t, err)
	require.NotEqual(t, s0.ID, s1.ID, "two distinct slots of one network")

	a0, a1 := NewConnAllocator(s0), NewConnAllocator(s1)

	// a0's first connection: v4 index 0 sits below a1's v4 slice, so an
	// unguarded Release on a1 would underflow and index the bitmap OOB.
	v6, v4, err := a0.Allocate()
	require.NoError(t, err)
	require.True(t, v4.IsValid())

	// a1 holds its own connection at the same v6 index (1) and same v4 index (0).
	v6a1, v4a1, err := a1.Allocate()
	require.NoError(t, err)

	// Releasing a0's addresses on a1 must be a safe no-op.
	require.NotPanics(t, func() { a1.Release(v6, v4) })

	// a1's live indices are untouched: its next alloc advances past them.
	v6next, v4next, err := a1.Allocate()
	require.NoError(t, err)
	require.NotEqual(t, v6a1.Addr(), v6next.Addr(), "a1 v6 index still held")
	require.NotEqual(t, v4a1.Addr(), v4next.Addr(), "a1 v4 index still held")
}

// u32Addr is the inverse of the binary.BigEndian.Uint32 conversion used for v4.
func u32Addr(u uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}
