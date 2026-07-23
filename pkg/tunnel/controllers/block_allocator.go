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

// blockAllocator sub-allocates connection addresses from per-network leased /80
// blocks. It leases a fresh block from the BlockLeaser under exhaustion pressure
// and hands back best-effort dual-stack (/96 + /32) allocations, returning the
// owning ConnAllocator so a disconnect frees exactly what it took. It owns no
// apiserver or relay state; the TunnelPublisher composes it.
type blockAllocator struct {
	leaser ipalloc.BlockLeaser

	mu   sync.Mutex
	nets map[tunnet.NetworkID]*netAllocs
}

// netAllocs holds a network's leased blocks and their in-process allocators.
type netAllocs struct {
	blocks []ipalloc.Block
	allocs []*ipalloc.ConnAllocator
}

// newBlockAllocator creates a blockAllocator over the given leaser.
func newBlockAllocator(leaser ipalloc.BlockLeaser) *blockAllocator {
	return &blockAllocator{
		leaser: leaser,
		nets:   make(map[tunnet.NetworkID]*netAllocs),
	}
}

// Allocate finds a non-full allocator for the network (leasing a fresh block
// under pressure) and sub-allocates a connection's /96 and best-effort /32,
// returning the owning allocator so Release can free exactly what was taken.
func (b *blockAllocator) Allocate(ctx context.Context, netID tunnet.NetworkID) (v6, v4 netip.Prefix, alloc *ipalloc.ConnAllocator, err error) {
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

	// Every existing block is full (or raced to full): lease another.
	blk, err := b.leaser.Lease(ctx, netID)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, nil, fmt.Errorf("failed to lease block: %w", err)
	}
	a := ipalloc.NewConnAllocator(blk)
	na.blocks = append(na.blocks, blk)
	na.allocs = append(na.allocs, a)

	if v6, v4, err = a.Allocate(); err != nil {
		return netip.Prefix{}, netip.Prefix{}, nil, err
	}
	return v6, v4, a, nil
}

// Release returns a connection's addresses to their owning allocator. It is safe
// to call with a nil allocator (a connect that failed before allocating).
func (b *blockAllocator) Release(alloc *ipalloc.ConnAllocator, v6, v4 netip.Prefix) {
	if alloc != nil {
		alloc.Release(v6, v4)
	}
}

// ReleaseAll returns every leased block to the leaser. Called at drain; for the
// local (OSS) leaser this is a cleanliness nicety since process exit frees them.
func (b *blockAllocator) ReleaseAll(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for netID, na := range b.nets {
		for _, blk := range na.blocks {
			if err := b.leaser.Release(ctx, blk); err != nil {
				slog.Warn("Failed to release block during drain", slog.Any("error", err))
			}
		}
		delete(b.nets, netID)
	}
}
