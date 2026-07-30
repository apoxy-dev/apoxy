package vni

import (
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"
)

const (
	maxVNI = 1 << 24 // 24-bit space
)

// TODO: support for some kind of persistent bitmap datastructure (sqlite3?).
type VNIPool struct {
	mu   sync.Mutex
	pool bitmap.Bitmap
	// base is where FirstZero scans start. VNIs are unique only per relay, but
	// an agent holds sessions to many relays in one icx handler keyed globally
	// by VNI — if every relay allocates from 1 they all hand the same low VNIs
	// to the same agent and its reconnects collide indefinitely. A per-process
	// random base makes overlap across relays vanishingly unlikely.
	base uint32
}

func NewVNIPool() *VNIPool {
	return NewVNIPoolWithBase(1)
}

// NewVNIPoolWithBase creates a pool whose allocation scan starts at base,
// wrapping around to 1 when the space above base is exhausted. base is clamped
// into [1, maxVNI).
func NewVNIPoolWithBase(base uint32) *VNIPool {
	if base < 1 || base >= maxVNI {
		base = 1
	}
	return &VNIPool{
		pool: bitmap.New(maxVNI),
		base: base,
	}
}

func (v *VNIPool) Allocate() (uint, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	vni, err := v.pool.FirstZero(v.base)
	if err != nil || vni >= maxVNI {
		// Space above base exhausted; wrap and scan [1, base).
		vni, err = v.pool.FirstZero(1)
		if err != nil || uint32(vni) >= v.base {
			return 0, fmt.Errorf("no available virtual network IDs")
		}
	}
	v.pool.Add(vni)
	return uint(vni), nil
}

func (v *VNIPool) Release(vni uint) {
	if vni >= maxVNI {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pool.Remove(uint32(vni))
}
