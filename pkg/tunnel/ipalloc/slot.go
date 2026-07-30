// Package ipalloc holds the relay-side, in-process connection address
// allocators for the vpc.apoxy.dev relay (APO-825 §2.8, where a slot is called
// a "block").
//
// A relay serving a network holds one or more slots in it. A slot is a 16-bit
// endpoint identifier — the same identifier the infrastructure endpoint
// allocator hands out — and it owns the addresses formed by varying byte 9 of
// the overlay ULA, the byte the layout reserves and nothing else uses:
//
//	fd61:706f:7879:nnnn:nncc:ssss::/96
//	               ^^^^^^^^ ^^ ^^^^
//	               network  |  slot (endpoint id)
//	                        connection index, 1-255
//
// Byte 9 == 0 is the slot's own endpoint /96 — the address the infrastructure
// allocator assigned — and is never handed to a connection. So "byte 9 != 0"
// separates relay-allocated connection addresses from every infrastructure
// endpoint address in one byte, including the legacy tunnelproxy endpoints that
// share this ULA.
//
// Conflict-freedom is structural, not lock-based: a slot is held by exactly one
// relay, so within its own slots a relay is the sole allocator and needs no
// apiserver round-trip on the connect path. The single coordination point is
// the SlotLeaser, and the property it must provide is narrow — two relays
// serving one network never hold the same slot. Slot count is the scarce
// dimension (65536 per network, bounding relays times held slots); connection
// count is elastic, because a relay that fills a slot simply leases another.
//
// Callers must pass the infra-assigned NetworkID; its uniqueness (and thus the
// disjointness of every network's address space) is the network provisioner's
// contract (§2.8), not something this package establishes or checks.
package ipalloc

import (
	"context"
	"errors"
	"net/netip"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// ConnsPerSlot is how many connections one slot carries: byte 9 takes the
// values 1-255, since 0 is the slot's own endpoint /96.
const ConnsPerSlot = 255

var (
	// ErrNoSlots is returned when a network's slots are all leased.
	ErrNoSlots = errors.New("no available slots in network")
	// ErrSlotExhausted is returned when a slot's connection addresses are all
	// in use; the caller should lease another slot.
	ErrSlotExhausted = errors.New("connection slot exhausted")
)

// Slot is an endpoint identifier held by exactly one relay within one network,
// together with the 255 connection addresses hanging off it.
type Slot struct {
	// Network is the infra-assigned 24-bit network identifier.
	Network tunnet.NetworkID
	// ID is the 16-bit endpoint identifier, unique within Network.
	ID tunnet.EndpointID
}

// SlotLeaser hands out endpoint slots within a network. A relay holds at least
// one lease per (relay × network) and takes more as connections fill them,
// renewed on the relay's heartbeat cadence and released at drain (§5). OSS
// satisfies this from the local process's own view of the network
// (LocalSlotLeaser); cloud satisfies it from infra-apiz Endpoints, whose
// allocator is already the single writer of endpoint identifiers per shard.
type SlotLeaser interface {
	// Lease reserves and returns a slot nobody else holds in the network, or
	// ErrNoSlots if the network's identifier space is exhausted.
	Lease(ctx context.Context, network tunnet.NetworkID) (Slot, error)
	// Renew extends a held lease. OSS has no lease TTL, so this is a no-op
	// there; cloud refreshes the backing Endpoint's heartbeat.
	Renew(ctx context.Context, s Slot) error
	// Release returns a slot to the pool.
	Release(ctx context.Context, s Slot) error
}

// EndpointPrefix returns the slot's own /96 — the address the infrastructure
// allocator assigned it (byte 9 == 0). It is never handed to a connection.
func EndpointPrefix(s Slot) netip.Prefix {
	return connPrefix(s, 0)
}

// ConnPrefix returns the /96 for connection index i within a slot. Index 0 is
// the slot's endpoint address, so connections are numbered from 1.
func ConnPrefix(s Slot, i uint8) netip.Prefix {
	return connPrefix(s, i)
}

func connPrefix(s Slot, i uint8) netip.Prefix {
	addr := tunnet.ULAPrefix().Addr().As16()
	copy(addr[6:9], s.Network[:])
	addr[9] = i
	copy(addr[10:12], s.ID[:])
	return netip.PrefixFrom(netip.AddrFrom16(addr), 96)
}

// SlotOf decomposes an overlay address into the slot that owns it and the
// connection index within that slot. ok is false when the address is an
// infrastructure endpoint address rather than a connection one (byte 9 == 0),
// which is the test that keeps relay space and endpoint space apart.
func SlotOf(p netip.Prefix) (s Slot, conn uint8, ok bool) {
	b := p.Addr().As16()
	if b[9] == 0 {
		return Slot{}, 0, false
	}
	return Slot{
		Network: tunnet.NetworkID{b[6], b[7], b[8]},
		ID:      tunnet.EndpointID{b[10], b[11]},
	}, b[9], true
}
