package kex

import (
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"
)

const (
	maxVNI = 1 << 24 // 24-bit space
)

// TODO: support for some kind of persistent bitmap datastructure.
type VNIPool struct {
	mu   sync.Mutex
	pool bitmap.Bitmap
}

func NewVNIPool() *VNIPool {
	return &VNIPool{
		pool: bitmap.New(maxVNI),
	}
}

func (v *VNIPool) Allocate() (uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	vni, err := v.pool.FirstZero(0)
	if err != nil || vni >= maxVNI {
		return 0, fmt.Errorf("no available virtual network IDs")
	}
	v.pool.Add(vni)
	return vni, nil
}

func (v *VNIPool) Free(vni uint32) {
	if vni >= maxVNI {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pool.Remove(vni)
}
