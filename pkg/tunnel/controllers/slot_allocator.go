package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

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
func (b *slotAllocator) Allocate(ctx context.Context, netID tunnet.NetworkID) (v6, v4 netip.Prefix, alloc *ipalloc.ConnAllocator, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

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
			return v6, v4, a, nil
		}
	}

	// Every existing slot is full (or raced to full): lease another.
	blk, err := b.leaser.Lease(ctx, netID)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, nil, fmt.Errorf("failed to lease slot: %w", err)
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
// Connections already holding addresses in the slot are unaffected: their
// Release goes directly to the owning ConnAllocator.
func (b *slotAllocator) InvalidateSlot(s ipalloc.Slot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	na := b.nets[s.Network]
	if na == nil {
		return
	}
	for i, blk := range na.slots {
		if blk.Network == s.Network && blk.ID == s.ID {
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
