// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"sync"

	"github.com/telepresenceio/watchable"
)

// mailbox is the event queue of one process: one queue under a small lock, in order. A send never
// blocks. After close, a send drops, so a stale reply to an ended process goes nowhere.
type mailbox struct {
	mu     sync.Mutex
	q      []any
	closed bool
	max    int // The most events in the queue, or 0 for no limit.
	sig    chan struct{}
}

func newMailbox(max int) *mailbox {
	return &mailbox{max: max, sig: make(chan struct{}, 1)}
}

// send adds e to the queue. It reports false when the mailbox is closed or full.
func (m *mailbox) send(e any) bool {
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

// take returns the events in the queue, the first one first.
func (m *mailbox) take() []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.q
	m.q = nil
	return q
}

// close drops each later send, and returns the events that the process did not take.
func (m *mailbox) close() []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.q
	m.closed, m.q = true, nil
	return q
}

// val is a value in a watchable map. It is immutable and goes by pointer: its copy is the same
// pointer, and two values are equal only with the same pointer.
type val struct{ p any }

func (v val) DeepCopy() val    { return v }
func (v val) Equal(o val) bool { return v.p == o.p }

// valueMap is the map of values that a parent owns for one child, in one direction.
type valueMap = watchable.Map[string, val]

// store sets key in m to the pointer p.
func store(m *valueMap, key string, p any) { m.Store(key, val{p: p}) }

// load returns the value of key in m, or the zero T.
func load[T any](m *valueMap, key string) T {
	v, _ := m.Load(key)
	t, _ := v.p.(T)
	return t
}

// watch calls changed with the keys of each change of m, the first time with each key, until ctx
// ends. The changes merge, and the process loads the newest values itself.
func watch(ctx context.Context, m *valueMap, changed func(keys []string)) {
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
