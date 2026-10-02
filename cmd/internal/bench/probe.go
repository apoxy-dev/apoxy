// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"context"
	"encoding/binary"
	"log/slog"
	"math"
	"net"
	"slices"
	"sync"
	"time"
)

// RTTStats are the RTT percentiles of the echoed probes, in milliseconds.
type RTTStats struct {
	Probes int     `json:"probes"`
	Lost   int     `json:"lost"`
	P50    float64 `json:"p50"`
	P90    float64 `json:"p90"`
	P99    float64 `json:"p99"`
	Max    float64 `json:"max"`
}

// NewRTTStats sorts rtts and returns their percentiles.
func NewRTTStats(rtts []time.Duration, lost int) RTTStats {
	st := RTTStats{Probes: len(rtts) + lost, Lost: lost}
	if len(rtts) == 0 {
		return st
	}
	slices.Sort(rtts)
	ms := func(q float64) float64 {
		i := int(math.Ceil(q*float64(len(rtts)))) - 1
		return float64(rtts[max(i, 0)]) / float64(time.Millisecond)
	}
	st.P50, st.P90, st.P99, st.Max = ms(0.5), ms(0.9), ms(0.99), ms(1)
	return st
}

// Prober sends numbered UDP probes to an echo server and records the RTT of each echo.
type Prober struct {
	conn  net.Conn
	start time.Time

	mu   sync.Mutex
	sent []time.Duration // Send time by sequence number.
	rtt  []time.Duration // RTT by sequence number, 0 until the echo arrives.
}

// NewProber returns a prober on conn. Its times are relative to start.
func NewProber(conn net.Conn, start time.Time, interval, run time.Duration) *Prober {
	n := int(run/interval) + 64
	return &Prober{conn: conn, start: start, sent: make([]time.Duration, 0, n), rtt: make([]time.Duration, 0, n)}
}

// Send sends a probe at each interval until ctx ends.
func (p *Prober) Send(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var b [16]byte
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Since(p.start)
		p.mu.Lock()
		seq := len(p.sent)
		p.sent = append(p.sent, now)
		p.rtt = append(p.rtt, 0)
		p.mu.Unlock()
		binary.BigEndian.PutUint64(b[:8], uint64(seq))
		binary.BigEndian.PutUint64(b[8:], uint64(now))
		if _, err := p.conn.Write(b[:]); err != nil && ctx.Err() == nil {
			slog.Warn("Failed to send RTT probe", "error", err)
		}
	}
}

// Receive records the echoes until the conn closes.
func (p *Prober) Receive() {
	var b [64]byte
	for {
		n, err := p.conn.Read(b[:])
		if err != nil {
			return
		}
		if n < 16 {
			continue
		}
		seq := binary.BigEndian.Uint64(b[:8])
		rtt := time.Since(p.start) - time.Duration(binary.BigEndian.Uint64(b[8:16]))
		p.mu.Lock()
		if seq < uint64(len(p.rtt)) {
			p.rtt[seq] = rtt
		}
		p.mu.Unlock()
	}
}

// Window returns the RTTs of the probes sent in [from, to) and the number of them with no echo.
func (p *Prober) Window(from, to time.Duration) ([]time.Duration, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var rtts []time.Duration
	lost := 0
	for i, s := range p.sent {
		if s < from || s >= to {
			continue
		}
		if p.rtt[i] > 0 {
			rtts = append(rtts, p.rtt[i])
		} else {
			lost++
		}
	}
	return rtts, lost
}
