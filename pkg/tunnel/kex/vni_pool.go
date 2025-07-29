package kex

import (
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/bitmap"
)

// TODO: support for some kind of persistent bitmap datastructure.
type VNIPool struct {
	mu    sync.Mutex
	pool  bitmap.Bitmap
	limit uint32
}

func NewVNIPool(limit uint32) *VNIPool {
	return &VNIPool{
		pool:  bitmap.New(limit),
		limit: limit,
	}
}

func (v *VNIPool) Allocate() (uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	vni, err := v.pool.FirstZero(0)
	if err != nil || vni >= v.limit {
		return 0, fmt.Errorf("no available virtual network IDs")
	}
	v.pool.Add(vni)
	return vni, nil
}

func (v *VNIPool) Free(vni uint32) {
	if vni >= v.limit {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pool.Remove(vni)
}
