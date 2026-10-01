// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"sync"
	"time"
)

// deadline is a read or write deadline. Its channel closes when the
// deadline passes, as in net.Pipe.
type deadline struct {
	mu    sync.Mutex
	timer *time.Timer
	c     chan struct{}
}

func newDeadline() *deadline { return &deadline{c: make(chan struct{})} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.c // The timer func runs now. Wait until it closes c.
	}
	d.timer = nil
	closed := isClosed(d.c)
	if t.IsZero() {
		if closed {
			d.c = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.c = make(chan struct{})
		}
		c := d.c
		d.timer = time.AfterFunc(dur, func() { close(c) })
		return
	}
	if !closed {
		close(d.c)
	}
}

// wait returns a channel that closes when the deadline passes.
func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.c
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
