package vni

import (
	"sync"
	"time"
)

const (
	// defaultQuarantineWindow is how long a released VNI is withheld from reuse.
	// It must comfortably exceed the icx SA teardown latency so a new connection
	// never reuses a VNI whose old security association is still installed.
	defaultQuarantineWindow = 30 * time.Second
)

// VNIAllocator is a relay-local VNI allocator with quarantine-on-release: a
// released VNI is held for a quarantine window before it can be handed out
// again, so a new connection never reuses a VNI whose icx SA teardown may still
// be in flight (which would let a stale SA match the new peer). VNIs are unique
// only per relay (§2.5) and nothing stores them durably; a relay restart
// abandons the whole space and agents reconnect with fresh VNIs.
//
// Quarantined VNIs keep their bit set in the pool (so FirstZero skips them) and
// carry a release deadline; the next Allocate sweeps any whose deadline has
// passed back into the free pool.
type VNIAllocator struct {
	mu         sync.Mutex
	pool       *VNIPool
	quarantine map[uint]time.Time // vni -> time it becomes reusable
	window     time.Duration
	now        func() time.Time
}

// AllocatorOption configures a VNIAllocator.
type AllocatorOption func(*VNIAllocator)

// WithQuarantineWindow overrides how long a released VNI is withheld from reuse.
func WithQuarantineWindow(d time.Duration) AllocatorOption {
	return func(a *VNIAllocator) { a.window = d }
}

// NewVNIAllocator creates a relay-local quarantine-aware VNI allocator.
func NewVNIAllocator(opts ...AllocatorOption) *VNIAllocator {
	a := &VNIAllocator{
		pool:       NewVNIPool(),
		quarantine: make(map[uint]time.Time),
		window:     defaultQuarantineWindow,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// sweep returns any quarantined VNIs whose window has elapsed to the pool.
// Caller holds mu.
func (a *VNIAllocator) sweep() {
	now := a.now()
	for vni, deadline := range a.quarantine {
		if !now.Before(deadline) {
			a.pool.Release(vni)
			delete(a.quarantine, vni)
		}
	}
}

// Allocate reserves and returns an unused VNI. VNI 0 is reserved (the icx
// handler rejects it), so allocation starts at 1 (VNIPool.Allocate begins at 1).
func (a *VNIAllocator) Allocate() (uint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.sweep()
	return a.pool.Allocate()
}

// Release moves a VNI into quarantine; it becomes reusable only after the
// quarantine window elapses (enforced lazily on the next Allocate).
func (a *VNIAllocator) Release(vni uint) {
	if vni == 0 || vni >= maxVNI {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// Keep the bit set (already set from Allocate) so the VNI is skipped until
	// the window elapses; record when it may be reused.
	if _, ok := a.quarantine[vni]; ok {
		return
	}
	a.quarantine[vni] = a.now().Add(a.window)
}
