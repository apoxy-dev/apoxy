// SPDX-License-Identifier: AGPL-3.0-only

package agent

import "sync"

// mailbox is the input queue of one process. A send never waits, and the
// queue keeps the order of the messages of one sender. It has no bound: the
// inputs of each process limit its messages.
type mailbox struct {
	mu   sync.Mutex
	q    []any
	wake chan struct{}
}

func newMailbox() *mailbox { return &mailbox{wake: make(chan struct{}, 1)} }

// send appends m and wakes the process.
func (b *mailbox) send(m any) {
	b.mu.Lock()
	b.q = append(b.q, m)
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// take returns the queued messages in order and empties the queue.
func (b *mailbox) take() []any {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.q
	b.q = nil
	return q
}
