package controllers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	// slotLeaseTimeout bounds one background slot lease, adoption included.
	slotLeaseTimeout = time.Minute
	// spareRetryDelay is the wait before a failed spare lease is tried again.
	spareRetryDelay = 30 * time.Second
)

// errAllocatorClosed is returned by Allocate after ReleaseAll.
var errAllocatorClosed = errors.New("slot allocator is closed")

// slotAllocator sub-allocates connection addresses from per-network leased
// slots and hands back best-effort dual-stack (/96 + /32) allocations,
// returning the owning ConnAllocator so a disconnect frees exactly what it
// took. It keeps at least one empty slot (a spare) leased in each network it
// serves, so a connect takes addresses from a held slot and does not wait for
// a lease. It owns no apiserver or relay state; the TunnelPublisher composes it.
type slotAllocator struct {
	leaser ipalloc.SlotLeaser

	mu     sync.Mutex
	nets   map[tunnet.NetworkID]*netAllocs
	closed bool
	// leases counts background leases in flight, so ReleaseAll can wait for
	// them to hand their slots back.
	leases sync.WaitGroup
}

// netAllocs holds a network's leased slots and their in-process allocators.
type netAllocs struct {
	slots  []ipalloc.Slot
	allocs []*ipalloc.ConnAllocator

	// lease is non-nil while a lease for this network is in flight. At most
	// one runs per network; Allocate calls with no capacity wait for it.
	lease *slotLease
}

// slotLease is one background lease. err is set before done is closed.
type slotLease struct {
	done chan struct{}
	err  error
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

// EnsureSpare starts a background lease when the network has no empty slot.
func (b *slotAllocator) EnsureSpare(netID tunnet.NetworkID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.ensureSpareLocked(netID, b.network(netID))
}

// Allocate sub-allocates a connection's /96 and best-effort /32 from a held
// slot, returning the owning allocator so Release can free exactly what was
// taken. It waits for a lease only when no held slot has room, which the
// spare prevents unless leases fail or a burst fills the spare first.
func (b *slotAllocator) Allocate(ctx context.Context, netID tunnet.NetworkID) (v6, v4 netip.Prefix, alloc *ipalloc.ConnAllocator, err error) {
	b.mu.Lock()
	for {
		if b.closed {
			b.mu.Unlock()
			return netip.Prefix{}, netip.Prefix{}, nil, errAllocatorClosed
		}
		na := b.network(netID)
		if a := na.pick(); a != nil {
			if v6, v4, err = a.Allocate(); err == nil {
				b.ensureSpareLocked(netID, na)
				b.mu.Unlock()
				return v6, v4, a, nil
			}
		}

		// No held slot has room. Wait for the lease in flight (or a new one)
		// and check capacity again: one lease usually serves every waiter.
		l := b.startLeaseLocked(netID, na)
		b.mu.Unlock()
		select {
		case <-l.done:
		case <-ctx.Done():
			return netip.Prefix{}, netip.Prefix{}, nil, ctx.Err()
		}
		if l.err != nil {
			return netip.Prefix{}, netip.Prefix{}, nil, fmt.Errorf("failed to lease slot: %w", l.err)
		}
		b.mu.Lock()
	}
}

// network returns the network's entry, creating it on first use. The caller
// must hold mu.
func (b *slotAllocator) network(netID tunnet.NetworkID) *netAllocs {
	na := b.nets[netID]
	if na == nil {
		na = &netAllocs{}
		b.nets[netID] = na
	}
	return na
}

// pick returns the allocator for a new connection: the first partly used slot
// with room, else an empty slot. Empty slots go last so the spare stays empty.
func (na *netAllocs) pick() *ipalloc.ConnAllocator {
	var empty *ipalloc.ConnAllocator
	for _, a := range na.allocs {
		switch {
		case a.Full():
		case a.Empty():
			if empty == nil {
				empty = a
			}
		default:
			return a
		}
	}
	return empty
}

// hasSpare reports whether the network holds a slot with no connections.
func (na *netAllocs) hasSpare() bool {
	for _, a := range na.allocs {
		if a.Empty() {
			return true
		}
	}
	return false
}

// ensureSpareLocked starts a lease when the network has no spare and no lease
// in flight. The caller must hold mu.
func (b *slotAllocator) ensureSpareLocked(netID tunnet.NetworkID, na *netAllocs) {
	if b.closed || na.lease != nil || na.hasSpare() {
		return
	}
	b.startLeaseLocked(netID, na)
}

// startLeaseLocked returns the network's lease in flight, or starts one. The
// caller must hold mu and must have checked that the allocator is open.
func (b *slotAllocator) startLeaseLocked(netID tunnet.NetworkID, na *netAllocs) *slotLease {
	if na.lease != nil {
		return na.lease
	}
	l := &slotLease{done: make(chan struct{})}
	na.lease = l
	b.leases.Add(1)
	go b.lease(netID, na, l)
	return l
}

// lease runs one lease outside mu: it is network I/O with a multi-second worst
// case, and it must not depend on the context of the connect that started it.
// A slot leased for a network that was released in the meantime goes back to
// the leaser; a failed lease is tried again after spareRetryDelay.
func (b *slotAllocator) lease(netID tunnet.NetworkID, na *netAllocs, l *slotLease) {
	defer b.leases.Done()
	ctx, cancel := context.WithTimeout(context.Background(), slotLeaseTimeout)
	defer cancel()
	slot, err := b.leaser.Lease(ctx, netID)

	b.mu.Lock()
	na.lease = nil
	current := !b.closed && b.nets[netID] == na
	l.err = err
	switch {
	case err == nil && current:
		na.slots = append(na.slots, slot)
		na.allocs = append(na.allocs, ipalloc.NewConnAllocator(slot))
	case err == nil:
		l.err = fmt.Errorf("network %x released during slot lease", netID[:])
	}
	close(l.done)
	b.mu.Unlock()

	switch {
	case err != nil && current:
		slog.Warn("Failed to lease overlay slot; retrying",
			slog.String("network", fmt.Sprintf("%x", netID[:])), slog.Any("error", err))
		time.AfterFunc(spareRetryDelay, func() { b.retrySpare(netID, na) })
	case err == nil && !current:
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer relCancel()
		if rerr := b.leaser.Release(relCtx, slot); rerr != nil {
			slog.Warn("Failed to release slot leased for a released network", slog.Any("error", rerr))
		}
	}
}

// retrySpare leases a spare again after a failed lease, unless the network or
// the allocator was released since.
func (b *slotAllocator) retrySpare(netID tunnet.NetworkID, na *netAllocs) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nets[netID] == na {
		b.ensureSpareLocked(netID, na)
	}
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
			// The lost slot can be the spare.
			b.ensureSpareLocked(s.Network, na)
			return
		}
	}
}

// ReleaseAll returns every leased slot to the leaser and reports the slots
// it could not release. The slots leave this allocator either way, per the
// SlotLeaser.Release contract. The allocator leases nothing after this, and
// ReleaseAll waits, within ctx, for leases in flight to return their slots.
func (b *slotAllocator) ReleaseAll(ctx context.Context) error {
	b.mu.Lock()
	b.closed = true
	nets := b.nets
	b.nets = make(map[tunnet.NetworkID]*netAllocs)
	b.mu.Unlock()

	var errs []error
	for _, na := range nets {
		for _, blk := range na.slots {
			if err := b.leaser.Release(ctx, blk); err != nil {
				errs = append(errs, err)
			}
		}
	}

	leased := make(chan struct{})
	go func() {
		b.leases.Wait()
		close(leased)
	}()
	select {
	case <-leased:
	case <-ctx.Done():
	}
	return errors.Join(errs...)
}
