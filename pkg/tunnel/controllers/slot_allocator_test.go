package controllers

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	waitFor = 5 * time.Second
	tick    = 5 * time.Millisecond
)

// blockingLeaser counts lease starts and holds every Lease until its gate
// closes, so a test can pile concurrent allocations behind an in-flight lease.
type blockingLeaser struct {
	inner   ipalloc.SlotLeaser
	gate    <-chan struct{}
	started atomic.Int64
}

func (b *blockingLeaser) Lease(ctx context.Context, net tunnet.NetworkID) (ipalloc.Slot, error) {
	b.started.Add(1)
	select {
	case <-b.gate:
	case <-ctx.Done():
		return ipalloc.Slot{}, ctx.Err()
	}
	return b.inner.Lease(ctx, net)
}

func (b *blockingLeaser) Renew(ctx context.Context, s ipalloc.Slot) error {
	return b.inner.Renew(ctx, s)
}

func (b *blockingLeaser) Release(ctx context.Context, s ipalloc.Slot) error {
	return b.inner.Release(ctx, s)
}

// countingLeaser wraps a real SlotLeaser to count Lease/Release calls and to
// optionally inject errors. It is safe for the allocator's background leases.
type countingLeaser struct {
	inner ipalloc.SlotLeaser

	mu         sync.Mutex
	leases     int
	releases   int
	leaseErr   error
	releaseErr error
}

func (c *countingLeaser) Lease(ctx context.Context, net tunnet.NetworkID) (ipalloc.Slot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releases++
	if c.releaseErr != nil {
		return c.releaseErr
	}
	return c.inner.Release(ctx, b)
}

func (c *countingLeaser) setErrors(lease, release error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaseErr, c.releaseErr = lease, release
}

func (c *countingLeaser) leaseCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leases
}

func (c *countingLeaser) releaseCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.releases
}

// slotStates returns, per held slot of the network, whether it is empty.
func slotStates(b *slotAllocator, netID tunnet.NetworkID) []bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	na := b.nets[netID]
	if na == nil {
		return nil
	}
	out := make([]bool, len(na.allocs))
	for i, a := range na.allocs {
		out[i] = a.Empty()
	}
	return out
}

// leaseSettled reports whether no lease is in flight for the network.
func leaseSettled(b *slotAllocator, netID tunnet.NetworkID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	na := b.nets[netID]
	return na == nil || na.lease == nil
}

// newTestAllocator returns a slotAllocator that is released when the test ends,
// so no background lease or retry outlives it.
func newTestAllocator(t *testing.T, leaser ipalloc.SlotLeaser) *slotAllocator {
	t.Helper()
	b := newSlotAllocator(leaser)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		_ = b.ReleaseAll(ctx)
	})
	return b
}

func TestSlotAllocator(t *testing.T) {
	ctx := context.Background()
	netA := tunnet.NetworkID{0x00, 0x20, 0x01}
	netB := tunnet.NetworkID{0x00, 0x20, 0x02}

	t.Run("allocates a dual-stack address and frees it for reuse", func(t *testing.T) {
		b := newTestAllocator(t, ipalloc.NewLocalSlotLeaser())

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
		b := newTestAllocator(t, leaser)

		_, _, _, err := b.Allocate(ctx, netA)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to lease slot")
	})

	t.Run("never repeats a /32 across the networks it serves", func(t *testing.T) {
		b := newTestAllocator(t, ipalloc.NewLocalSlotLeaser())

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
		b := newTestAllocator(t, ipalloc.NewLocalSlotLeaser())
		require.NotPanics(t, func() {
			b.Release(nil, netip.MustParsePrefix("fd00::/96"), netip.MustParsePrefix("10.0.0.0/32"))
		})
	})

	t.Run("concurrent allocations on an empty network share one lease", func(t *testing.T) {
		release := make(chan struct{})
		leaser := &blockingLeaser{inner: ipalloc.NewLocalSlotLeaser(), gate: release}
		b := newTestAllocator(t, leaser)

		const conns = 16
		var wg sync.WaitGroup
		errs := make([]error, conns)
		for i := 0; i < conns; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, _, _, errs[i] = b.Allocate(ctx, netA)
			}(i)
		}

		// Let every goroutine reach Allocate before the first lease returns,
		// so all of them are queued behind the single in-flight lease.
		require.Eventually(t, func() bool { return leaser.started.Load() == 1 }, waitFor, tick)
		close(release)
		wg.Wait()

		for i, err := range errs {
			require.NoError(t, err, "connection %d", i)
		}
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)
		require.Equal(t, int64(2), leaser.started.Load(), "one lease covers every queued waiter; the other is the spare")
		require.Equal(t, []bool{false, true}, slotStates(b, netA))
	})

	t.Run("keeps one spare slot before any connection", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newTestAllocator(t, leaser)

		b.EnsureSpare(netA)
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)
		b.EnsureSpare(netA)
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)
		require.Equal(t, []bool{true}, slotStates(b, netA))
		require.Equal(t, 1, leaser.leaseCount(), "a network with a spare leased again")
	})

	t.Run("leases a new spare when the spare takes a connection", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newTestAllocator(t, leaser)
		b.EnsureSpare(netA)
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)

		_, _, first, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.Equal(t, 1, leaser.leaseCount(), "the connect did not use the spare")
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)
		require.Equal(t, []bool{false, true}, slotStates(b, netA))

		// A partly used slot takes the next connection; the spare stays empty.
		_, _, second, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.Same(t, first, second)
		require.Equal(t, []bool{false, true}, slotStates(b, netA))
		require.Equal(t, 2, leaser.leaseCount())
	})

	t.Run("uses a partly used slot before an empty one", func(t *testing.T) {
		b := newTestAllocator(t, ipalloc.NewLocalSlotLeaser())

		// Fill the first slot, so the next connection opens the second one.
		type held struct {
			v6, v4 netip.Prefix
			alloc  *ipalloc.ConnAllocator
		}
		var first []held
		for i := 0; i < ipalloc.ConnsPerSlot; i++ {
			v6, v4, a, err := b.Allocate(ctx, netA)
			require.NoError(t, err)
			first = append(first, held{v6, v4, a})
		}
		_, _, second, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.NotSame(t, first[0].alloc, second)

		// Empty the first slot. It now comes after the partly used second slot.
		for _, h := range first {
			b.Release(h.alloc, h.v6, h.v4)
		}
		_, _, got, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.Same(t, second, got)
	})

	t.Run("leases the spare again after a failed lease", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser(), leaseErr: errors.New("infra-apiserver is down")}
		b := newTestAllocator(t, leaser)

		b.EnsureSpare(netA)
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)
		require.Empty(t, slotStates(b, netA))

		leaser.setErrors(nil, nil)
		b.mu.Lock()
		na := b.nets[netA]
		b.mu.Unlock()
		b.retrySpare(netA, na)
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)
		require.Equal(t, []bool{true}, slotStates(b, netA))
	})

	t.Run("hands back a slot leased for a released network", func(t *testing.T) {
		gate := make(chan struct{})
		counting := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newTestAllocator(t, &blockingLeaser{inner: counting, gate: gate})

		b.EnsureSpare(netA)
		b.ReleaseNetwork(ctx, netA)
		close(gate)
		require.Eventually(t, func() bool { return counting.releaseCount() == 1 }, waitFor, tick)
		require.Equal(t, 1, counting.leaseCount())
		require.Empty(t, slotStates(b, netA))
	})

	t.Run("ReleaseAll drains every leased slot exactly once", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newTestAllocator(t, leaser)

		// First allocation on each network leases a slot and a spare.
		for _, netID := range []tunnet.NetworkID{netA, netB} {
			_, _, _, err := b.Allocate(ctx, netID)
			require.NoError(t, err)
			require.Eventually(t, func() bool { return leaseSettled(b, netID) }, waitFor, tick)
		}
		require.Equal(t, 4, leaser.leaseCount())

		require.NoError(t, b.ReleaseAll(ctx))
		require.Equal(t, 4, leaser.releaseCount(), "every leased slot returned")

		// State is cleared: a second drain releases nothing more.
		require.NoError(t, b.ReleaseAll(ctx))
		require.Equal(t, 4, leaser.releaseCount(), "drain is idempotent")
	})

	t.Run("ReleaseAll waits for a lease in flight and stops leasing", func(t *testing.T) {
		gate := make(chan struct{})
		counting := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newTestAllocator(t, &blockingLeaser{inner: counting, gate: gate})

		b.EnsureSpare(netA)
		released := make(chan error, 1)
		go func() { released <- b.ReleaseAll(ctx) }()
		require.Eventually(t, func() bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.closed
		}, waitFor, tick)
		close(gate)
		require.NoError(t, <-released)
		require.Equal(t, 1, counting.leaseCount())
		require.Equal(t, 1, counting.releaseCount(), "the slot of the lease in flight was not released")

		b.EnsureSpare(netA)
		_, _, _, err := b.Allocate(ctx, netA)
		require.ErrorIs(t, err, errAllocatorClosed)
		require.Equal(t, 1, counting.leaseCount(), "the allocator leased after ReleaseAll")
	})

	t.Run("ReleaseAll reports a failed release and still drops the slot", func(t *testing.T) {
		leaser := &countingLeaser{inner: ipalloc.NewLocalSlotLeaser()}
		b := newTestAllocator(t, leaser)

		_, _, alloc, err := b.Allocate(ctx, netA)
		require.NoError(t, err)
		require.Eventually(t, func() bool { return leaseSettled(b, netA) }, waitFor, tick)

		leaser.setErrors(nil, errors.New("apiserver timeout"))
		require.Error(t, b.ReleaseAll(ctx))
		require.Equal(t, 2, leaser.releaseCount())
		require.False(t, b.Contains(alloc), "the leaser owns the retry; the allocator lets go")

		require.NoError(t, b.ReleaseAll(ctx))
		require.Equal(t, 2, leaser.releaseCount(), "nothing left to release")
	})
}
