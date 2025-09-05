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
}

func NewVNIPool() *VNIPool {
	return &VNIPool{
		pool: bitmap.New(maxVNI),
	}
}

func (v *VNIPool) Allocate() (uint, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	vni, err := v.pool.FirstZero(1)
	if err != nil || vni >= maxVNI {
		return 0, fmt.Errorf("no available virtual network IDs")
	}
	v.pool.Add(vni)
	return uint(vni), nil
}

func (v *VNIPool) Free(vni uint) {
	if vni >= maxVNI {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pool.Remove(uint32(vni))
}
