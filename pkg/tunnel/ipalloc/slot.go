// Package ipalloc holds the relay-side, in-process connection address
// allocators for the vpc.apoxy.dev relay (APO-825 §2.8, where a slot is called
// a "block").
//
// A relay serving a network holds one or more slots in it. A slot is a 16-bit
// endpoint identifier — the same identifier the infrastructure endpoint
// allocator hands out — and it owns the addresses formed by varying byte 11 of
// the overlay ULA:
//
//	fd61:706f:7879:nnnn:nnss:sscc::/96
//	               ^^^^^^^^ ^^^^ ^^
//	               network  |    connection index, 1-255
//	                        slot (endpoint id)
//
// The slot sits ABOVE the connection index, so a slot is a single /88 and every
// address it owns shares 88 bits. Both properties are load-bearing and neither
// survives the two fields being swapped:
//
//   - A slot is advertisable as one route. Relays do not federate, so an agent
//     must route each relay's addresses over that relay's own session; with the
//     connection index above the slot a slot is a strided set, not a prefix,
//     and cannot be expressed as a route at all.
//   - Source address selection lands on the right relay. An agent connected to
//     several relays carries one address per relay on one device, so the kernel
//     picks the source by longest matching prefix (RFC 6724 rule 8). That has
//     to discriminate on the slot; with the connection index above it, it
//     discriminates on a per-connection counter instead and sources traffic
//     from an address the destination's relay never leased.
//
// Byte 11 == 0 is the slot's own endpoint /96 — the address the infrastructure
// allocator assigned — and is never handed to a connection.
//
// Slot ids below MinSlotID are reserved: see its doc comment.
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
	"fmt"
	"net/netip"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// ConnsPerSlot is how many connections one slot carries: byte 11 takes the
// values 1-255, since 0 is the slot's own endpoint /96.
const ConnsPerSlot = 255

const (
	// LabelSlot identifies the leased relay slot that owns a Tunnel. Its value
	// is the slot's network and endpoint identifiers, formatted as NNNNNN-SSSS.
	LabelSlot = "vpc.apoxy.dev/slot"
	// LabelSlotGeneration identifies one ownership lifecycle of a relay slot.
	// A relay increments it before it adopts a surviving slot Endpoint.
	LabelSlotGeneration = "vpc.apoxy.dev/slot-gen"
)

// MinSlotID is the lowest slot id a leaser may hand out. Ids below it have a
// zero high byte, which puts a zero in ULA byte 9 — and byte 9 is where the
// pre-slot addressing scheme carried its own fields, so such a connection
// address is indistinguishable from an address minted under the old scheme.
// Reserving the low 256 ids keeps the two disjoint for as long as both are on
// the wire; it costs 0.4% of the slot space. Drop the reservation once the old
// scheme is gone.
const MinSlotID = 1 << 8

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
	// Generation identifies one ownership lifecycle of this slot. It starts at
	// one for a new lease and increases when a surviving lease is adopted.
	Generation uint64
	// V4 is the /24 backing the slot's best-effort IPv4, assigned by the
	// leaser. Its uniqueness domain is wider than the slot id's: the id is
	// unique per network, but an agent connected to several relays demuxes v4
	// by bare source address, and a relay routes every network through one
	// route table — so the /24 must not repeat across relays or networks. The
	// infra leaser allocates it globally (from 240.0.0.0/4); the local leaser
	// from its process-wide pool, which is the whole world in OSS. A zero
	// value runs the slot v6-only (§2.4).
	V4 netip.Prefix
}

// SlotLabelValue returns the stable label value for a slot's network and
// endpoint identifiers. Generation is carried in LabelSlotGeneration.
func SlotLabelValue(s Slot) string {
	return fmt.Sprintf("%02x%02x%02x-%02x%02x",
		s.Network[0], s.Network[1], s.Network[2], s.ID[0], s.ID[1])
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

// SlotPrefix returns the slot's /88 — the whole range it owns, its endpoint
// address and all 255 connection addresses. This is the unit a relay advertises
// to its agents: one route per slot it holds, so an agent routes each relay's
// addresses over that relay's own session and no more.
func SlotPrefix(s Slot) netip.Prefix {
	return netip.PrefixFrom(connPrefix(s, 0).Addr(), 88)
}

// SlotPrefixOf returns the /88 containing addr. It is meaningful only for
// addresses minted by ConnPrefix or EndpointPrefix.
func SlotPrefixOf(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, 88).Masked()
}

// EndpointPrefix returns connection index 0 of the slot, which is reserved and
// never handed to a connection.
//
// It is NOT the address the infrastructure allocator assigned the backing
// Endpoint: infra places an endpoint identifier in ULA bytes 10-11, while a
// slot places it in bytes 9-10. The identifier is borrowed as an opaque
// uniqueness token — that is the only property the leaser has to provide — and
// the address space it names here is derived independently.
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
	copy(addr[9:11], s.ID[:])
	addr[11] = i
	return netip.PrefixFrom(netip.AddrFrom16(addr), 96)
}

// SlotOf decomposes an overlay address into the slot that owns it and the
// connection index within that slot. ok is false when the address is an
// infrastructure endpoint address rather than a connection one (byte 11 == 0),
// or when it predates slot addressing (slot id below MinSlotID) — together
// those are the test that keeps relay space and endpoint space apart.
func SlotOf(p netip.Prefix) (s Slot, conn uint8, ok bool) {
	b := p.Addr().As16()
	if b[11] == 0 || b[9] == 0 {
		return Slot{}, 0, false
	}
	return Slot{
		Network: tunnet.NetworkID{b[6], b[7], b[8]},
		ID:      tunnet.EndpointID{b[9], b[10]},
	}, b[11], true
}
