package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// slotAllocator sub-allocates connection addresses from per-network leased
// slots. It leases a fresh slot from the SlotLeaser under exhaustion pressure
// and hands back best-effort dual-stack (/96 + /32) allocations, returning the
// owning ConnAllocator so a disconnect frees exactly what it took. It owns no
// apiserver or relay state; the TunnelPublisher composes it.
type slotAllocator struct {
	leaser ipalloc.SlotLeaser

	mu   sync.Mutex
	nets map[tunnet.NetworkID]*netAllocs
}

// netAllocs holds a network's leased slots and their in-process allocators.
type netAllocs struct {
	slots  []ipalloc.Slot
	allocs []*ipalloc.ConnAllocator

	// leasing is non-nil while a Lease for this network is in flight; it is
	// closed (under mu) when that lease settles. Concurrent Allocate calls
	// wait on it and re-check capacity instead of starting redundant leases —
	// one slot lease typically covers every waiter queued behind it.
	leasing chan struct{}
}

// newSlotAllocator creates a slotAllocator over the given leaser. A slot's
// v4 /24 comes with the lease (Slot.V4), so the leaser — not this allocator —
// is where cross-network and cross-tenant v4 disjointness is established.
func newSlotAllocator(leaser ipalloc.SlotLeaser) *slotAllocator {
	return &slotAllocator{
		leaser: leaser,
		nets:   make(map[tunnet.NetworkID]*netAllocs),
	}
}

// Allocate finds a non-full allocator for the network (leasing a fresh slot
// under pressure) and sub-allocates a connection's /96 and best-effort /32,
// returning the owning allocator so Release can free exactly what was taken.
//
// The lease itself runs OUTSIDE the mutex: Lease is network I/O with a
// multi-second worst case, and holding mu across it would serialize every
// connection on every network behind one slow lease. At most one lease per
// network is in flight; concurrent callers wait for it and re-check capacity,
// so a reconnect stampede costs one lease, not one per queued connection.
func (b *slotAllocator) Allocate(ctx context.Context, netID tunnet.NetworkID) (v6, v4 netip.Prefix, alloc *ipalloc.ConnAllocator, err error) {
	b.mu.Lock()
	for {
		na := b.nets[netID]
		if na == nil {
			na = &netAllocs{}
			b.nets[netID] = na
		}

		for _, a := range na.allocs {
			if a.Full() {
				continue
			}
			if v6, v4, err = a.Allocate(); err == nil {
				b.mu.Unlock()
				return v6, v4, a, nil
			}
		}

		if na.leasing == nil {
			// Every slot is full and no lease is in flight: this caller
			// leases the network's next slot.
			na.leasing = make(chan struct{})
			b.mu.Unlock()
			return b.leaseAndAllocate(ctx, netID, na)
		}

		// Another caller is already leasing: wait for it to settle, then
		// re-check capacity instead of leasing redundantly.
		done := na.leasing
		b.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return netip.Prefix{}, netip.Prefix{}, nil, ctx.Err()
		}
		b.mu.Lock()
	}
}

// leaseAndAllocate leases a fresh slot and allocates from it. The lease runs
// outside the mutex — it is network I/O with a multi-second worst case, and
// holding mu across it would serialize every connection on every network.
// The caller must have set na.leasing; it is closed here when the lease
// settles, releasing any waiters queued in Allocate.
func (b *slotAllocator) leaseAndAllocate(ctx context.Context, netID tunnet.NetworkID, na *netAllocs) (v6, v4 netip.Prefix, alloc *ipalloc.ConnAllocator, err error) {
	blk, err := b.leaser.Lease(ctx, netID)

	b.mu.Lock()
	defer b.mu.Unlock()
	close(na.leasing)
	na.leasing = nil

	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, nil, fmt.Errorf("failed to lease slot: %w", err)
	}
	if b.nets[netID] != na {
		// The network was released while the lease was in flight; hand the
		// slot straight back so it is not orphaned.
		relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if rerr := b.leaser.Release(relCtx, blk); rerr != nil {
			slog.Warn("Failed to release slot leased for a deleted network", slog.Any("error", rerr))
		}
		return netip.Prefix{}, netip.Prefix{}, nil, fmt.Errorf("network %s released during slot lease", netID)
	}

	a := ipalloc.NewConnAllocator(blk)
	na.slots = append(na.slots, blk)
	na.allocs = append(na.allocs, a)

	if v6, v4, err = a.Allocate(); err != nil {
		return netip.Prefix{}, netip.Prefix{}, nil, err
	}
	return v6, v4, a, nil
}

// Release returns a connection's addresses to their owning allocator. It is safe
// to call with a nil allocator (a connect that failed before allocating).
func (b *slotAllocator) Release(alloc *ipalloc.ConnAllocator, v6, v4 netip.Prefix) {
	if alloc != nil {
		alloc.Release(v6, v4)
	}
}

// Contains reports whether alloc is still backed by a slot that this
// allocator holds. Pointer identity distinguishes a lost allocation from a
// later lease that reuses the same network, slot ID, and generation value.
func (b *slotAllocator) Contains(alloc *ipalloc.ConnAllocator) bool {
	if alloc == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	na := b.nets[alloc.Slot().Network]
	if na == nil {
		return false
	}
	for _, current := range na.allocs {
		if current == alloc {
			return true
		}
	}
	return false
}

// ReleaseNetwork returns every slot leased for one network. Called when the
// network is deleted, so its identifiers stop being renewed against a network
// that no longer exists.
func (b *slotAllocator) ReleaseNetwork(ctx context.Context, netID tunnet.NetworkID) {
	b.mu.Lock()
	na := b.nets[netID]
	delete(b.nets, netID)
	b.mu.Unlock()
	if na == nil {
		return
	}
	for _, blk := range na.slots {
		if err := b.leaser.Release(ctx, blk); err != nil {
			slog.Warn("Failed to release slot for deleted network", slog.Any("error", err))
		}
	}
}

// InvalidateSlot drops a lost slot's allocator so no new connections are
// assigned addresses from an identifier the leaser no longer holds.
// The publisher closes connections that already hold addresses in the slot;
// their Release still goes directly to the owning ConnAllocator.
func (b *slotAllocator) InvalidateSlot(s ipalloc.Slot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	na := b.nets[s.Network]
	if na == nil {
		return
	}
	for i, blk := range na.slots {
		if blk.Network == s.Network && blk.ID == s.ID && blk.Generation == s.Generation {
			na.slots = append(na.slots[:i], na.slots[i+1:]...)
			na.allocs = append(na.allocs[:i], na.allocs[i+1:]...)
			return
		}
	}
}

// ReleaseAll returns every leased slot to the leaser. Called at drain; for the
// local (OSS) leaser this is a cleanliness nicety since process exit frees them.
func (b *slotAllocator) ReleaseAll(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for netID, na := range b.nets {
		for _, blk := range na.slots {
			if err := b.leaser.Release(ctx, blk); err != nil {
				slog.Warn("Failed to release slot during drain", slog.Any("error", err))
			}
		}
		delete(b.nets, netID)
	}
}
