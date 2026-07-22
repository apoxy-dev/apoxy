package ipalloc

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// blockPrefix builds the expected /80 block prefix for a /72 and an index by
// writing the index into byte 9; used to check blockIndex round-trips.
func blockPrefix(net72 netip.Prefix, idx uint8) netip.Prefix {
	addr := net72.Masked().Addr().As16()
	addr[9] = idx
	return netip.PrefixFrom(netip.AddrFrom16(addr), 80)
}

func TestBlockIndexRoundTrip(t *testing.T) {
	id := tunnet.NetworkID{0x12, 0x34, 0x56}
	parent := network72(id)

	for _, idx := range []uint8{0, 1, 42, 128, 255} {
		p := blockPrefix(parent, idx)
		require.Equal(t, 80, p.Bits(), "block is a /80")
		require.Equal(t, idx, blockIndex(p), "index round-trips through byte 9")
		require.True(t, parent.Contains(p.Addr()), "block stays within its /72")

		// Network bytes (6–8) are preserved; byte 9 carries the index.
		b := p.Addr().As16()
		require.Equal(t, id[:], b[6:9], "network id preserved")
		require.Equal(t, idx, b[9], "index lands in byte 9")
	}
}

func TestLocalBlockLeaser(t *testing.T) {
	ctx := context.Background()
	l := NewLocalBlockLeaser(ctx)
	idA := tunnet.NetworkID{0x00, 0x00, 0x01}
	idB := tunnet.NetworkID{0x00, 0x00, 0x02}

	t.Run("distinct blocks per network", func(t *testing.T) {
		seen := map[uint8]bool{}
		for i := 0; i < 8; i++ {
			b, err := l.Lease(ctx, idA)
			require.NoError(t, err)
			require.Equal(t, idA, b.Network)
			require.False(t, seen[b.Index], "index %d handed out twice", b.Index)
			seen[b.Index] = true
			require.Equal(t, b.Index, blockIndex(b.Prefix))
		}
	})

	t.Run("release returns block to pool", func(t *testing.T) {
		l := NewLocalBlockLeaser(ctx)
		b, err := l.Lease(ctx, idA)
		require.NoError(t, err)
		require.NoError(t, l.Release(ctx, b))
		b2, err := l.Lease(ctx, idA)
		require.NoError(t, err)
		require.Equal(t, b.Index, b2.Index, "freed block index is reused")
	})

	t.Run("exhaustion after 256 blocks", func(t *testing.T) {
		l := NewLocalBlockLeaser(ctx)
		for i := 0; i < 256; i++ {
			_, err := l.Lease(ctx, idA)
			require.NoError(t, err, "lease %d", i)
		}
		_, err := l.Lease(ctx, idA)
		require.ErrorIs(t, err, ErrNoBlocks, "257th lease fails")
	})

	t.Run("networks have independent block spaces", func(t *testing.T) {
		l := NewLocalBlockLeaser(ctx)
		a, err := l.Lease(ctx, idA)
		require.NoError(t, err)
		b, err := l.Lease(ctx, idB)
		require.NoError(t, err)
		// Same index (both first blocks) but disjoint /72s.
		require.Equal(t, a.Index, b.Index)
		require.False(t, a.Prefix.Overlaps(b.Prefix), "different networks' blocks are disjoint")
	})
}

// newConnAllocator leases a block and returns an allocator over it.
func newConnAllocator(t *testing.T, id tunnet.NetworkID) *ConnAllocator {
	t.Helper()
	l := NewLocalBlockLeaser(context.Background())
	b, err := l.Lease(context.Background(), id)
	require.NoError(t, err)
	return NewConnAllocator(b)
}

func TestConnAllocatorV6(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0a, 0x01}
	a := newConnAllocator(t, id)

	first, _, err := a.Allocate()
	require.NoError(t, err)
	require.Equal(t, 96, first.Bits())
	require.True(t, a.block.Prefix.Contains(first.Addr()), "/96 sits inside the /80 block")

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

	// The block's whole v4 space is the /18 keyed on block index.
	wantSlice := netip.PrefixFrom(u32Addr(v4CGNATBase+uint32(a.block.Index)<<connBitsV4), 18)
	require.True(t, netip.MustParsePrefix("100.64.0.0/10").Overlaps(wantSlice))

	prev := map[netip.Addr]bool{}
	for i := 0; i < 4; i++ {
		_, v4, err := a.Allocate()
		require.NoError(t, err)
		require.True(t, v4.IsValid())
		require.Equal(t, 32, v4.Bits())
		require.True(t, wantSlice.Contains(v4.Addr()), "/32 falls in the block's /18")
		require.False(t, prev[v4.Addr()], "distinct /32s")
		prev[v4.Addr()] = true
	}
}

func TestConnAllocatorV4ExhaustionV6Only(t *testing.T) {
	id := tunnet.NetworkID{0x00, 0x0c, 0x01}
	a := newConnAllocator(t, id)

	// Drain the v4 pool (maxConnV4 addresses).
	for i := 0; i < maxConnV4; i++ {
		_, v4, err := a.Allocate()
		require.NoError(t, err)
		require.True(t, v4.IsValid(), "v4 available for the first %d", maxConnV4)
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
	for i := 0; i < maxConnV6; i++ {
		_, _, err := a.Allocate()
		require.NoError(t, err)
	}
	require.True(t, a.Full(), "block reports full once v6 space is drained")
	_, _, err := a.Allocate()
	require.ErrorIs(t, err, ErrBlockExhausted)
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
	require.Equal(t, v6a.Addr(), v6c.Addr(), "v6 slot reused")
	require.Equal(t, v4a.Addr(), v4c.Addr(), "v4 slot reused")
	require.NotEqual(t, v6b.Addr(), v6c.Addr(), "still-held slot untouched")
	require.NotEqual(t, v4b.Addr(), v4c.Addr())
}

// TestConnAllocatorCrossNetworkV4Overlap pins the intended §2.4 overlap: two
// distinct networks whose blocks share an index get the *same* v4 /18 (v4 never
// leaves its per-network forwarding domain), while their v6 /96s stay disjoint.
func TestConnAllocatorCrossNetworkV4Overlap(t *testing.T) {
	ctx := context.Background()
	l := NewLocalBlockLeaser(ctx)
	ba, err := l.Lease(ctx, tunnet.NetworkID{0x00, 0x00, 0x01})
	require.NoError(t, err)
	bb, err := l.Lease(ctx, tunnet.NetworkID{0x00, 0x00, 0x02})
	require.NoError(t, err)
	require.Equal(t, ba.Index, bb.Index, "both first blocks share an index")

	aa, ab := NewConnAllocator(ba), NewConnAllocator(bb)
	v6a, v4a, err := aa.Allocate()
	require.NoError(t, err)
	v6b, v4b, err := ab.Allocate()
	require.NoError(t, err)

	require.Equal(t, v4a.Addr(), v4b.Addr(), "v4 intentionally overlaps across networks")
	require.NotEqual(t, v6a.Addr(), v6b.Addr(), "v6 stays globally unique via disjoint /72s")
}

// TestConnAllocatorReleaseForeignBlock pins the §2.8 multi-block guard: a
// prefix from a different block must be ignored, never panicking (v4 underflow)
// or freeing a live slot in the wrong block (v6 collision on connection index).
func TestConnAllocatorReleaseForeignBlock(t *testing.T) {
	ctx := context.Background()
	l := NewLocalBlockLeaser(ctx)
	id := tunnet.NetworkID{0x00, 0x0f, 0x01}
	b0, err := l.Lease(ctx, id)
	require.NoError(t, err)
	b1, err := l.Lease(ctx, id)
	require.NoError(t, err)
	require.NotEqual(t, b0.Index, b1.Index, "two distinct blocks of one network")

	a0, a1 := NewConnAllocator(b0), NewConnAllocator(b1)

	// a0's first connection: v4 index 0 sits below a1's v4 slice, so an
	// unguarded Release on a1 would underflow and index the bitmap OOB.
	v6, v4, err := a0.Allocate()
	require.NoError(t, err)
	require.True(t, v4.IsValid())

	// a1 holds its own connection at the same v6 index (0) and same v4 index (0).
	v6a1, v4a1, err := a1.Allocate()
	require.NoError(t, err)

	// Releasing a0's addresses on a1 must be a safe no-op.
	require.NotPanics(t, func() { a1.Release(v6, v4) })

	// a1's live slots are untouched: its next alloc advances past index 0.
	v6next, v4next, err := a1.Allocate()
	require.NoError(t, err)
	require.NotEqual(t, v6a1.Addr(), v6next.Addr(), "a1 v6 slot 0 still held")
	require.NotEqual(t, v4a1.Addr(), v4next.Addr(), "a1 v4 slot 0 still held")
}

// u32Addr is the inverse of the binary.BigEndian.Uint32 conversion used for v4.
func u32Addr(u uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}
