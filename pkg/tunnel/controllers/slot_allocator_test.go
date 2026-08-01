package controllers

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// countingLeaser wraps a real SlotLeaser to count Lease/Release calls and to
// optionally inject a lease error.
type countingLeaser struct {
	inner    ipalloc.SlotLeaser
	leases   int
	releases int
	leaseErr error
}

func (c *countingLeaser) Lease(ctx context.Context, net tunnet.NetworkID) (ipalloc.Slot, error) {
	if c.leaseErr != nil {
		return ipalloc.Slot{}, c.leaseErr
	}
	b, err := c.inner.Lease(ctx, net)
	if err == nil {
		c.leases++
	}
	return b, err
}

func (c *countingLeaser) Renew(ctx context.Context, b ipalloc.Slot) error {
	return c.inner.Renew(ctx, b)
}

func (c *countingLeaser) Release(ctx context.Context, b ipalloc.Slot) error {
	c.releases++
	return c.inner.Release(ctx, b)
}

func TestSlotAllocator(t *testing.T) {
	ctx := context.Background()
	netA := tunnet.NetworkID{0x00, 0x20, 0x01}
	netB := tunnet.NetworkID{0x00, 0x20, 0x02}

	t.Run("allocates a dual-stack address and frees it for reuse", func(t *testing.T) {
		b := newSlotAllocator(ipalloc.NewLocalSlotLeaser(), ipalloc.NewV4SlicePool())

		v6a, v4a, alloc, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.NotNil(t, alloc)
		require.True(t, v6a.IsValid())
		require.Equal(t, 96, v6a.Bits())
		require.True(t, v4a.IsValid())
		require.Equal(t, 32, v4a.Bits())

		v6b, _, _, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.NotEqual(t, v6a.Addr(), v6b.Addr(), "distinct connections get distinct /96s")

		// Freeing the first connection returns its slot; the next allocation reuses it.
		b.Release(alloc, v6a, v4a)
		v6c, _, _, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.Equal(t, v6a.Addr(), v6c.Addr(), "released /96 is reused")
	})

	t.Run("surfaces a lease failure", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser(), leaseErr: errors.New("no slots")}
		b := newSlotAllocator(leaser, ipalloc.NewV4SlicePool())

		_, _, _, err := b.Allocate(ctx, netA)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to lease slot")
	})

	t.Run("never repeats a /32 across the networks it serves", func(t *testing.T) {
		b := newSlotAllocator(ipalloc.NewLocalSlotLeaser(), ipalloc.NewV4SlicePool())

		// Slot ids are numbered per network, so every network's first slot
		// carries the same id; one route table means the /32s must still come
		// out distinct.
		seen := make(map[netip.Addr]tunnet.NetworkID)
		for _, netID := range []tunnet.NetworkID{netA, netB, {0x00, 0x20, 0x03}} {
			for i := 0; i < 3; i++ {
				_, v4, _, err := b.Allocate(ctx, netID)
				require.NoError(t, err)
				require.True(t, v4.IsValid(), "v4 stays available across networks")
				prev, dup := seen[v4.Addr()]
				require.False(t, dup, "%s handed to both %v and %v", v4, prev, netID)
				seen[v4.Addr()] = netID
			}
		}
	})

	t.Run("Release tolerates a nil allocator", func(t *testing.T) {
		b := newSlotAllocator(ipalloc.NewLocalSlotLeaser(), ipalloc.NewV4SlicePool())
		require.NotPanics(t, func() {
			b.Release(nil, netip.MustParsePrefix("fd00::/96"), netip.MustParsePrefix("10.0.0.0/32"))
		})
	})

	t.Run("ReleaseAll drains every leased slot exactly once", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newSlotAllocator(leaser, ipalloc.NewV4SlicePool())

		// First allocation on each network leases one block apiece.
		_, _, _, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		_, _, _, err = b.Allocate(ctx, netB)
		require.NoError(t, err)
		require.Equal(t, 2, leaser.leases)

		b.ReleaseAll(ctx)
		require.Equal(t, 2, leaser.releases, "every leased slot returned")

		// State is cleared: a second drain releases nothing more.
		b.ReleaseAll(ctx)
		require.Equal(t, 2, leaser.releases, "drain is idempotent")
	})
}
