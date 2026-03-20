// Package conntrack provides a lightweight TCP connection tracker that
// implements connection.PacketObserver. It counts active TCP flows by
// watching SYN/FIN/RST flags, enabling early drain exit when all
// connections have closed.
package conntrack

import (
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// flowKey identifies a TCP flow by its 4-tuple.
type flowKey struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
}

// flowState tracks half-close state for a TCP connection.
type flowState struct {
	finSeen [2]bool // [0] = forward, [1] = reverse
}

// Tracker counts active TCP connections by observing packets via the
// PacketObserver interface. Safe for concurrent use.
type Tracker struct {
	mu    sync.Mutex
	flows map[flowKey]*flowState
	count atomic.Int64
}

var _ connection.PacketObserver = (*Tracker)(nil)

// NewTracker creates a new TCP connection tracker.
func NewTracker() *Tracker {
	return &Tracker{
		flows: make(map[flowKey]*flowState),
	}
}

// ActiveCount returns the number of currently tracked TCP connections.
func (t *Tracker) ActiveCount() int {
	return int(t.count.Load())
}

// OnPacket implements connection.PacketObserver. It inspects TCP flags to
// track connection lifecycle (SYN opens, FIN/RST closes).
func (t *Tracker) OnPacket(info connection.PacketInfo) {
	if info.Protocol != connection.ProtocolTCP {
		return
	}

	flags := info.TCPFlags
	srcIP := info.SrcIP.As16()
	dstIP := info.DstIP.As16()

	key := flowKey{srcIP: srcIP, dstIP: dstIP, srcPort: info.SrcPort, dstPort: info.DstPort}

	t.mu.Lock()
	defer t.mu.Unlock()

	if flags&connection.TCPFlagSYN != 0 && flags&connection.TCPFlagFIN == 0 {
		// New connection (SYN). Use forward direction as canonical key.
		if _, exists := t.flows[key]; !exists {
			t.flows[key] = &flowState{}
			t.count.Add(1)
		}
		return
	}

	// RST and FIN need to check both forward and reverse directions.
	reverseKey := flowKey{srcIP: dstIP, dstIP: srcIP, srcPort: info.DstPort, dstPort: info.SrcPort}

	if flags&connection.TCPFlagRST != 0 {
		// RST immediately kills the flow in either direction.
		if _, ok := t.flows[key]; ok {
			delete(t.flows, key)
			t.count.Add(-1)
		} else if _, ok := t.flows[reverseKey]; ok {
			delete(t.flows, reverseKey)
			t.count.Add(-1)
		}
		return
	}

	if flags&connection.TCPFlagFIN != 0 {
		// FIN: mark half-close. Remove when both directions have FIN'd.
		if fs, ok := t.flows[key]; ok {
			fs.finSeen[0] = true
			if fs.finSeen[1] {
				delete(t.flows, key)
				t.count.Add(-1)
			}
		} else if fs, ok := t.flows[reverseKey]; ok {
			fs.finSeen[1] = true
			if fs.finSeen[0] {
				delete(t.flows, reverseKey)
				t.count.Add(-1)
			}
		}
	}
}
