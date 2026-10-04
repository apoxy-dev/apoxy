// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"sync/atomic"
	"time"
)

// maxQueue is the largest virtual queue of a limiter, in time at its rate. A
// short limit: the breaker drops the excess and adds no delay (RFC 8084).
const maxQueue = int64(2 * time.Millisecond)

// epoch is the start of the limiter clock.
var epoch = time.Now()

// nanotime returns the monotonic time since epoch in nanoseconds.
func nanotime() int64 { return int64(time.Since(epoch)) }

// limiter limits the bytes to one peer while its breaker is tripped. It is a GCRA
// policer: each packet that passes adds its time at the rate to a virtual queue,
// and a packet drops when that queue is longer than maxQueue. It does not hold
// packets, lock or allocate.
type limiter struct {
	rate atomic.Int64  // Bytes per second. Zero means no limit.
	tat  atomic.Int64  // End of the virtual queue, on the nanotime clock.
	sent atomic.Uint64 // Bytes that went through the limiter.
}

// admit reports whether a packet of n bytes can go now.
func (g *limiter) admit(n int) bool {
	if g.rate.Load() == 0 {
		g.sent.Add(uint64(n))
		return true
	}
	return g.admitAt(n, nanotime())
}

func (g *limiter) admitAt(n int, now int64) bool {
	r := g.rate.Load()
	if r == 0 {
		g.sent.Add(uint64(n))
		return true
	}
	cost := int64(n) * int64(time.Second) / r
	for {
		tat := g.tat.Load()
		at := max(tat, now)
		if at-now > maxQueue {
			return false
		}
		if g.tat.CompareAndSwap(tat, at+cost) {
			g.sent.Add(uint64(n))
			return true
		}
	}
}
