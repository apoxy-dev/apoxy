// Package ipalloc holds the relay-side, in-process connection address
// allocators for the vpc.apoxy.dev relay (APO-825 §2.8). A relay leases a /80
// block of a network's /72 (one block per relay × network), then sub-allocates
// per-connection /96 (IPv6) and /32 (IPv4) prefixes from that block with no
// apiserver round-trip on the connect path.
//
// Conflict-freedom is structural, not lock-based: the /72 is partitioned into
// 256 disjoint /80 blocks, each leased to exactly one relay, so a relay is the
// sole allocator within its own block. The single coordination point is the
// BlockLeaser. Callers must pass the infra-assigned NetworkID; its uniqueness
// (and thus the disjointness of every /72) is the network provisioner's
// contract (§2.8), not something this package establishes or checks.
package ipalloc

import (
	"context"
	"errors"
	"net/netip"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

var (
	// ErrNoBlocks is returned when a network's 256 /80 blocks are all leased.
	ErrNoBlocks = errors.New("no available blocks in network")
	// ErrBlockExhausted is returned when a block's 65536 connection /96s are
	// all in use; the caller should lease another block.
	ErrBlockExhausted = errors.New("connection block exhausted")
)

// Block is a /80 child of a network's /72, identified by an 8-bit index that
// occupies byte 9 of the ULA (the reserved field between the /72 network and
// the /96 connection). Up to 256 blocks per network, i.e. 256 relays.
type Block struct {
	// Network is the infra-assigned 24-bit network identifier.
	Network tunnet.NetworkID
	// Index is the block index (0–255), equal to byte 9 of Prefix's address.
	Index uint8
	// Prefix is the /80 block, e.g. fd61:706f:7879:nnnn:nnII::/80.
	Prefix netip.Prefix
}

// BlockLeaser hands out /80 blocks of a network /72. The relay holds one lease
// per (relay × network), renewed on the relay Lease cadence and released at
// drain (§5). OSS satisfies this from the local system ULA (LocalBlockLeaser);
// cloud satisfies it from infra-apiz Endpoints (step-4 ticket) — same seam.
type BlockLeaser interface {
	// Lease reserves and returns an unused /80 block of the network's /72, or
	// ErrNoBlocks if all 256 are taken.
	Lease(ctx context.Context, network tunnet.NetworkID) (Block, error)
	// Renew extends a held lease. OSS has no lease TTL, so this is a no-op
	// there; cloud renews the backing infra Endpoint.
	Renew(ctx context.Context, b Block) error
	// Release returns a block to the pool.
	Release(ctx context.Context, b Block) error
}

// network72 returns the masked /72 overlay prefix for a network id, writing the
// 24-bit id into bytes 6–8 of the ULA base (mirroring NetULA's byte layout)
// without spinning up a go-ipam instance.
func network72(id tunnet.NetworkID) netip.Prefix {
	addr := tunnet.ULAPrefix().Addr().As16()
	copy(addr[6:9], id[:])
	return netip.PrefixFrom(netip.AddrFrom16(addr), 72)
}

// blockIndex extracts the block index (byte 9) from a /80 block prefix.
func blockIndex(p netip.Prefix) uint8 {
	return p.Addr().As16()[9]
}
