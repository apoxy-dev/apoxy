// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"sync"
	"time"
)

// Circuit breaker values, with their reason from RFC 8084.
const (
	// Measure over a period much longer than an RTT, so that congestion control acts first.
	breakInterval = time.Second
	// An interval with fewer expected packets gives no stable loss rate, so it does not count.
	breakMinPackets = 100
	// Trip only on excessive loss, far above the loss that congestion control keeps.
	breakLossPercent = 20
	// Trip only on persistent congestion, not on one bad interval.
	breakIntervals = 3
	// The reduced rate keeps a minimum, so that the session and its control traffic continue.
	breakFloor = 1_000_000 / 8 // Bytes per second.
	// Restart only after a period much longer than the time to trip.
	breakReset = 30 * time.Second
)

// SACount is the receive counters of one SA, from a report of its receiver.
type SACount struct {
	SPI     uint32
	Packets uint64 // Accepted packets.
	Seq     uint32 // Highest accepted sequence number.
}

// Trip is a change of a breaker limit.
type Trip struct {
	Rate int64 // Limit in bytes per second. Zero means the limit was removed.
	Loss int   // Loss percent of the last interval.
}

// breaker trips when the loss to one peer stays high, and then limits the
// send rate with its limiter: half of the rate that arrived, and half again at
// each new trip. The send path reads only the limiter.
type breaker struct {
	limiter limiter

	mu       sync.Mutex
	sas      map[uint32]SACount // Last counters of each SA, from the reports.
	quicSent uint64             // Counters at the last QUIC report.
	quicLost uint64
	start    time.Time // Start of the interval. Zero before the first report.
	sent     uint64    // limiter.sent at start.
	expected uint64    // Packets in the interval.
	lost     int64     // Lost packets in the interval. Late packets subtract.
	run      int       // Lossy intervals in a row.
	tripped  time.Time // Last trip. Zero while there is no limit.
}

// sent returns the number of sequence numbers up to the highest one that
// arrived. Sequence numbers start at 0.
func (c SACount) sent() uint64 {
	if c.Packets == 0 {
		return 0
	}
	return uint64(c.Seq) + 1
}

// addSAs adds a PSP report. A new SA counts from zero.
func (br *breaker) addSAs(now time.Time, sas []SACount) (Trip, bool) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if br.sas == nil {
		br.sas = map[uint32]SACount{}
	}
	seen := len(br.sas)
	for _, sa := range sas {
		prev, ok := br.sas[sa.SPI]
		if ok {
			seen--
		}
		br.sas[sa.SPI] = sa
		if sa.sent() < prev.sent() || sa.Packets < prev.Packets {
			continue
		}
		ds := sa.sent() - prev.sent()
		br.expected += ds
		br.lost += int64(ds) - int64(sa.Packets-prev.Packets)
	}
	if seen > 0 {
		// Forget the SAs that the receiver removed.
		for spi := range br.sas {
			if !hasSPI(sas, spi) {
				delete(br.sas, spi)
			}
		}
	}
	return br.step(now)
}

func hasSPI(sas []SACount, spi uint32) bool {
	for _, sa := range sas {
		if sa.SPI == spi {
			return true
		}
	}
	return false
}

// addQUIC adds the total data frames sent and QUIC packets lost.
func (br *breaker) addQUIC(now time.Time, sent, lost uint64) (Trip, bool) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if !br.start.IsZero() && sent >= br.quicSent && lost >= br.quicLost {
		br.expected += sent - br.quicSent
		br.lost += int64(lost - br.quicLost)
	}
	br.quicSent, br.quicLost = sent, lost
	return br.step(now)
}

// step ends the interval when it is long enough. br.mu must be held.
func (br *breaker) step(now time.Time) (Trip, bool) {
	if br.start.IsZero() {
		br.begin(now)
		return Trip{}, false
	}
	dt := now.Sub(br.start)
	if dt < breakInterval {
		return Trip{}, false
	}
	exp := br.expected
	lost := uint64(min(max(br.lost, 0), int64(exp)))
	sent := br.limiter.sent.Load() - br.sent
	br.begin(now)
	if exp < breakMinPackets {
		return br.reset(now)
	}
	loss := int(lost * 100 / exp)
	if loss < breakLossPercent {
		br.run = 0
		return br.reset(now)
	}
	if br.run++; br.run < breakIntervals {
		return Trip{}, false
	}
	br.run = 0
	r := br.limiter.rate.Load() / 2
	if r == 0 {
		// Half of the bytes that arrived.
		r = int64(float64(sent) * float64(exp-lost) / float64(exp) / dt.Seconds() / 2)
	}
	r = max(r, breakFloor)
	br.limiter.rate.Store(r)
	br.tripped = now
	return Trip{Rate: r, Loss: loss}, true
}

func (br *breaker) begin(now time.Time) {
	br.start, br.sent, br.expected, br.lost = now, br.limiter.sent.Load(), 0, 0
}

// reset removes the limit breakReset after the last trip. br.mu must be held.
func (br *breaker) reset(now time.Time) (Trip, bool) {
	if br.tripped.IsZero() || now.Sub(br.tripped) < breakReset {
		return Trip{}, false
	}
	br.tripped = time.Time{}
	br.limiter.rate.Store(0)
	return Trip{}, true
}

// expire removes the limit if no trip came for breakReset, also when no reports come.
func (br *breaker) expire(now time.Time) (Trip, bool) {
	br.mu.Lock()
	defer br.mu.Unlock()
	return br.reset(now)
}

// limit returns the limit in bytes per second, or 0 when there is no limit.
func (br *breaker) limit() int64 { return br.limiter.rate.Load() }
