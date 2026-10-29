// SPDX-License-Identifier: AGPL-3.0-only

// Package proc has the messages between the processes of the VPC agent and relay.
//
// Each long-running process is one goroutine. It owns its state, and messages go only between a
// parent and its direct children. Events go in a mailbox; values go in watchable maps that the
// parent owns.
//
//   - A value is the newest state of its writer, an immutable pointer that compares by pointer. No
//     answer goes back, and the reader can skip versions. The parent makes both maps of a child: it
//     writes the down map, and the child writes the up map. A task of a process can read the down
//     map of that process. A value map is never closed; a subscription ends with its context.
//   - An event is all else: a request, an answer, a task result, an end, a packet, or a message
//     whose order with the other events of the same pair changes the result.
//   - A reader takes the events first and loads the values after, so it sees each value that was
//     stored before those events. The value can be newer than the event.
//   - A goroutine that blocks on I/O has no subscription. A subscription keeps each update until its
//     reader takes the snapshot, so Watch reads all the time and gives the keys to a process loop
//     that does not block.
package proc

import (
	"context"
	"sync"

	"github.com/telepresenceio/watchable"
)

// Mailbox is the event queue of one process: one queue under a small lock, in order. A send never
// blocks. After close, a send drops, so a stale reply to an ended process goes nowhere.
type Mailbox struct {
	mu     sync.Mutex
	q      []any
	closed bool
	max    int // The most events in the queue, or 0 for no limit.
	sig    chan struct{}
}

// NewMailbox returns a mailbox that keeps at most max events, or any number when max is 0.
func NewMailbox(max int) *Mailbox {
	return &Mailbox{max: max, sig: make(chan struct{}, 1)}
}

// Send adds e to the queue. It reports false when the mailbox is closed or full; then e drops.
func (m *Mailbox) Send(e any) bool {
	m.mu.Lock()
	if m.closed || (m.max > 0 && len(m.q) >= m.max) {
		m.mu.Unlock()
		return false
	}
	m.q = append(m.q, e)
	m.mu.Unlock()
	select {
	case m.sig <- struct{}{}:
	default:
	}
	return true
}

// Take returns the events in the queue, the first one first.
func (m *Mailbox) Take() []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.q
	m.q = nil
	return q
}

// Close drops each later send, and returns the events that the process did not take.
func (m *Mailbox) Close() []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.q
	m.closed, m.q = true, nil
	return q
}

// Wake returns the channel that gets a signal after a Send. The owner then calls Take.
func (m *Mailbox) Wake() <-chan struct{} { return m.sig }

// Val is a value in a watchable map. It is immutable and goes by pointer: its copy is the same
// pointer, and two values are equal only with the same pointer.
type Val struct{ p any }

func (v Val) DeepCopy() Val    { return v }
func (v Val) Equal(o Val) bool { return v.p == o.p }

// Values is the map of values that a parent owns for one child, in one direction.
type Values = watchable.Map[string, Val]

// Store sets key in m to the pointer p.
func Store(m *Values, key string, p any) { m.Store(key, Val{p: p}) }

// Load returns the value of key in m, or the zero T.
func Load[T any](m *Values, key string) T {
	v, _ := m.Load(key)
	return As[T](v)
}

// As returns the pointer of v as T, or the zero T.
func As[T any](v Val) T {
	t, _ := v.p.(T)
	return t
}

// Watch calls changed with the keys of each change of m, the first time with each key, until ctx
// ends. The changes merge, and the process loads the newest values itself.
func Watch(ctx context.Context, m *Values, changed func(keys []string)) {
	ch := m.Subscribe(ctx)
	go func() {
		first := true
		for snap := range ch {
			var keys []string
			if first {
				for k := range snap.State {
					keys = append(keys, k)
				}
				first = false
			}
			for _, u := range snap.Updates {
				keys = append(keys, u.Key)
			}
			changed(keys)
		}
	}()
}
