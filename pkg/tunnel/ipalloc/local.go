package ipalloc

import (
	"context"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// maxSlots is the size of a network's slot id space (16 bits).
const maxSlots = 1 << 16

// LocalSlotLeaser is the OSS/single-tenant SlotLeaser. It tracks each network's
// slot ids entirely in process memory — there is no infra tier, so leases have
// no TTL (Renew is a no-op) and nothing survives a restart. The API is
// identical to the cloud infra-backed implementation so the relay wiring is the
// same in both modes.
//
// It is correct only while a single process allocates for a network. Two
// processes each start from an empty bitmap and both hand out the lowest free
// id, so their connections collide on identical /96s. Any deployment running
// more than one relay per network must use an infra-backed leaser.
type LocalSlotLeaser struct {
	mu   sync.Mutex
	nets map[tunnet.NetworkID]*bitmap.Bitmap
}

// NewLocalSlotLeaser returns a LocalSlotLeaser.
func NewLocalSlotLeaser() *LocalSlotLeaser {
	return &LocalSlotLeaser{
		nets: make(map[tunnet.NetworkID]*bitmap.Bitmap),
	}
}

// Lease reserves an unused slot id in the network.
func (l *LocalSlotLeaser) Lease(_ context.Context, network tunnet.NetworkID) (Slot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	bm, ok := l.nets[network]
	if !ok {
		b := bitmap.New(maxSlots)
		bm = &b
		l.nets[network] = bm
	}

	// Scan from MinSlotID: the reserved low ids must never be handed out, and
	// starting the scan past them is cheaper than allocating and rejecting.
	i, err := bm.FirstZero(MinSlotID)
	if err != nil || i >= maxSlots {
		return Slot{}, ErrNoSlots
	}
	bm.Add(i)

	return Slot{Network: network, ID: tunnet.EndpointID{byte(i >> 8), byte(i)}}, nil
}

// Renew is a no-op: local leases have no TTL.
func (l *LocalSlotLeaser) Renew(_ context.Context, _ Slot) error {
	return nil
}

// Release returns a slot to the network's pool.
func (l *LocalSlotLeaser) Release(_ context.Context, s Slot) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	bm, ok := l.nets[s.Network]
	if !ok {
		return nil
	}
	bm.Remove(uint32(s.ID[0])<<8 | uint32(s.ID[1]))
	return nil
}
