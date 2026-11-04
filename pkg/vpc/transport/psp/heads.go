// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// headSlots is the most destinations that keep a packet head.
	headSlots = 1024
	// headHold is the age at which a new packet replaces a head, and the
	// shortest time between two heads that TakeHead gives for one destination.
	headHold = time.Second
	// quoteLen is the most bytes of a packet that an ICMP error quotes.
	quoteLen = MaxICMPv6 - header.IPv6MinimumSize - header.ICMPv6DstUnreachableMinimumSize
)

type headKey struct {
	l   *Link
	dst netip.Addr
}

// head is the start of a packet to a destination of a link, and the time of
// the last head that TakeHead gave for it.
type head struct {
	pkt  []byte // Nil after TakeHead.
	at   time.Time
	last time.Time
}

// heads keeps the start of the first packet of a flow to each destination on a
// relay route, so that the agent can quote it in an ICMP error after a NoRoute.
type heads struct {
	mu sync.Mutex
	m  map[headKey]*head
	// fresh are the heads that capture kept since the last Tick, at most headSlots.
	fresh []Head
}

// Head is a packet head that the binding kept: the first packet in headHold of a flow to Dst on
// a relay route.
type Head struct {
	Src, Dst netip.Addr
}

// capture keeps the start of pkt for dst on l, unless the head of dst is younger than headHold
// or pkt is a channel packet. A full table drops its old entries once, else it keeps nothing.
func (h *heads) capture(l *Link, pkt []byte, dst netip.Addr) {
	if isChannel(pkt) {
		return
	}
	now := time.Now()
	key := headKey{l, dst}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.m[key]
	if e != nil && e.pkt != nil && now.Sub(e.at) < headHold {
		return
	}
	if e == nil {
		if len(h.m) >= headSlots && !h.dropOld(now) {
			return
		}
		if h.m == nil {
			h.m = map[headKey]*head{}
		}
		e = &head{}
		h.m[key] = e
	}
	e.pkt = append(e.pkt[:0], pkt[:min(len(pkt), quoteLen)]...)
	e.at = now
	if src, ok := innerSrc(pkt); ok && len(h.fresh) < headSlots {
		h.fresh = append(h.fresh, Head{Src: src, Dst: dst})
	}
}

// dropOld removes the entries whose head and last error are older than
// headHold, and reports whether the table has space. h.mu must be held.
func (h *heads) dropOld(now time.Time) bool {
	for k, e := range h.m {
		if (e.pkt == nil || now.Sub(e.at) >= headHold) && now.Sub(e.last) >= headHold {
			delete(h.m, k)
		}
	}
	return len(h.m) < headSlots
}

// take returns the head of dst on l and clears it, or nil when it has none, when skip reports
// true for it, or when the last head that it gave is younger than headHold.
func (h *heads) take(l *Link, dst netip.Addr, now time.Time, skip func(pkt []byte) bool) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.m[headKey{l, dst}]
	if e == nil || e.pkt == nil || now.Sub(e.last) < headHold || skip(e.pkt) {
		return nil
	}
	pkt := e.pkt
	e.pkt, e.last = nil, now
	return pkt
}

// sweep removes the entries with no head whose last error is older than headHold.
func (h *heads) sweep(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, e := range h.m {
		if e.pkt == nil && now.Sub(e.last) >= headHold {
			delete(h.m, k)
		}
	}
}

// takeFresh returns the heads that capture kept since the last call.
func (h *heads) takeFresh() []Head {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.fresh
	h.fresh = nil
	return out
}

// TakeHead returns the start of the first packet to dst on l since the last
// call that gave one, for an ICMP error after a NoRoute of the relay. It
// returns nil when it has none, or when it gave one less than headHold ago.
// It gives no head from the own list to a destination with a direct route: that
// flow goes direct now, so the NoRoute of the relay is not for it.
func (b *Binding) TakeHead(l *Link, dst netip.Addr, now time.Time) []byte {
	dst = dst.Unmap()
	return b.heads.take(l, dst, now, func(pkt []byte) bool {
		if b.directN.Load() == 0 {
			return false
		}
		_, direct := b.directPeer(pkt, dst)
		return direct
	})
}
