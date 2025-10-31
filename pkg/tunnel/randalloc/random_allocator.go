package randalloc

import (
	"context"
	"math/rand"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

// RandAllocator hands out items such that, at any moment,
// no two callers hold the same item concurrently.
// Call Acquire() to get exclusive use of an item, and Release() when done.
//
// If all items are busy, Acquire() will block until one is released
// or the context is canceled.
type RandAllocator[T comparable] struct {
	mu    sync.Mutex
	items []T
	inUse map[T]bool

	// waitCh is used to notify waiters that something changed
	// (i.e. an item was released). It's always a non-nil channel.
	// On every Release(), we close the old channel and make a new one.
	waitCh chan struct{}
}

// NewRandAllocator constructs a RandAllocator[T] from a set of items.
func NewRandAllocator[T comparable](vals sets.Set[T]) *RandAllocator[T] {
	list := vals.UnsortedList()

	ra := &RandAllocator[T]{
		items:  list,
		inUse:  make(map[T]bool, len(list)),
		waitCh: make(chan struct{}), // open, will be closed to wake waiters
	}
	return ra
}

// Acquire returns an item that is not currently in use by any other caller.
// It randomizes selection among the currently-free items.
// If none are free, it waits until one is released or ctx is canceled.
func (ra *RandAllocator[T]) Acquire(ctx context.Context) (T, error) {
	var zero T

	for {
		ra.mu.Lock()

		// Try to grab a free item immediately.
		if item, ok := ra.pickFreeLocked(); ok {
			ra.inUse[item] = true
			ra.mu.Unlock()
			return item, nil
		}

		// No item free right now.
		// If the caller's context is already done, abort.
		if err := ctx.Err(); err != nil {
			ra.mu.Unlock()
			return zero, err
		}

		// Take a snapshot of the current waitCh so we can wait
		// without holding the mutex.
		ch := ra.waitCh

		ra.mu.Unlock()

		// Wait until either:
		// - context is canceled, or
		// - someone calls Release() and closes ch.
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-ch:
			// An item was released; loop and retry.
		}
	}
}

// Release marks an item as free again and wakes any waiters.
func (ra *RandAllocator[T]) Release(item T) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	if ra.inUse[item] {
		delete(ra.inUse, item)
	}

	// Wake all current waiters by closing waitCh,
	// then create a fresh channel for future waiters.
	close(ra.waitCh)
	ra.waitCh = make(chan struct{})
}

// Replace atomically swaps the candidate item set and wakes all waiters.
// Any items currently in use may remain absent from the new item set; they
// simply won't be handed out again once released.
func (ra *RandAllocator[T]) Replace(vals sets.Set[T]) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	ra.items = vals.UnsortedList()

	// Wake all current waiters so they can observe the new set.
	close(ra.waitCh)
	ra.waitCh = make(chan struct{})
}

// pickFreeLocked picks a currently-free item at random.
// caller must hold ra.mu.
func (ra *RandAllocator[T]) pickFreeLocked() (T, bool) {
	var zero T

	n := len(ra.items)
	if n == 0 {
		return zero, false
	}

	for _, idx := range rand.Perm(n) {
		item := ra.items[idx]
		if !ra.inUse[item] {
			return item, true
		}
	}
	return zero, false
}
