// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBreaker gives the breaker one QUIC report at the end of each interval and
// checks the gate rate after it.
func TestBreaker(t *testing.T) {
	type iv struct {
		pkts, lost uint64 // Packets sent and lost in the interval.
		bytes      uint64 // Bytes through the gate in the interval.
		wait       time.Duration
	}
	lossy := iv{pkts: 1000, lost: 500, bytes: 1_000_000} // 50% loss; 500 kB/s arrive.
	clean := iv{pkts: 1000, lost: 100, bytes: 1_000_000} // 10% loss.
	cases := []struct {
		name  string
		ivs   []iv
		rates []int64 // Gate rate after each interval.
	}{
		{"loss below 20% does not trip",
			[]iv{clean, clean, clean, {pkts: 1000, lost: 199, bytes: 1_000_000}},
			[]int64{0, 0, 0, 0}},
		{"three lossy intervals trip at half the rate that arrived",
			[]iv{lossy, lossy, lossy},
			[]int64{0, 0, 250_000}},
		{"loss of exactly 20% counts",
			[]iv{{pkts: 1000, lost: 200, bytes: 1_000_000}, {pkts: 1000, lost: 200, bytes: 1_000_000}, {pkts: 1000, lost: 200, bytes: 1_000_000}},
			[]int64{0, 0, 400_000}},
		{"a clean interval starts the count again",
			[]iv{lossy, lossy, clean, lossy, lossy, lossy},
			[]int64{0, 0, 0, 0, 0, 250_000}},
		{"an interval with few packets does not count",
			[]iv{lossy, lossy, {pkts: 99, lost: 99, bytes: 100_000}, lossy},
			[]int64{0, 0, 0, 250_000}},
		{"a trip while limited halves the limit, down to the floor",
			slices.Repeat([]iv{lossy}, 9),
			[]int64{0, 0, 250_000, 250_000, 250_000, 125_000, 125_000, 125_000, 125_000}},
		{"the limit is at least 1 Mbit/s",
			[]iv{{pkts: 1000, lost: 500, bytes: 100_000}, {pkts: 1000, lost: 500, bytes: 100_000}, {pkts: 1000, lost: 500, bytes: 100_000}},
			[]int64{0, 0, breakFloor}},
		{"the limit ends 30 s after the last trip",
			[]iv{lossy, lossy, lossy, {pkts: 1000, wait: 29 * time.Second}, {pkts: 1000}},
			[]int64{0, 0, 250_000, 250_000, 0}},
		{"a long interval is one interval",
			[]iv{{pkts: 1000, lost: 500, bytes: 2_000_000, wait: 2 * time.Second}, lossy, lossy},
			[]int64{0, 0, 250_000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Len(t, tc.rates, len(tc.ivs))
			var br breaker
			now := time.Unix(1000, 0)
			var sent, lost uint64
			_, changed := br.addQUIC(now, 0, 0)
			assert.False(t, changed)
			for i, x := range tc.ivs {
				now = now.Add(cmpOr(x.wait, time.Second))
				br.gate.sent.Add(x.bytes)
				sent, lost = sent+x.pkts, lost+x.lost
				before := br.limit()
				trip, changed := br.addQUIC(now, sent, lost)
				assert.Equal(t, tc.rates[i], br.limit(), "interval %d", i)
				if before != br.limit() {
					assert.True(t, changed, "interval %d", i)
				}
				if changed {
					assert.Equal(t, br.limit(), trip.Rate, "interval %d", i)
				}
			}
		})
	}
}

func cmpOr(d, def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return d
}

// TestBreakerExpire opens the gate 30 s after the last trip, also with no reports.
func TestBreakerExpire(t *testing.T) {
	var br breaker
	now := time.Unix(1000, 0)
	br.gate.rate.Store(250_000)
	br.tripped = now
	_, changed := br.expire(now.Add(breakReset - time.Millisecond))
	assert.False(t, changed)
	assert.Equal(t, int64(250_000), br.limit())
	_, changed = br.expire(now.Add(breakReset))
	assert.True(t, changed)
	assert.Zero(t, br.limit())
}

// TestBreakerSAs checks how a PSP report changes the counts of the interval.
func TestBreakerSAs(t *testing.T) {
	cases := []struct {
		name         string
		saved        []SACount
		report       []SACount
		wantExpected uint64
		wantLost     int64
		wantSPIs     []uint32
	}{
		{"the changes of seq and packets",
			[]SACount{{1, 100, 100}}, []SACount{{1, 600, 1100}}, 1000, 500, []uint32{1}},
		{"a new SA counts from zero",
			[]SACount{{1, 100, 100}}, []SACount{{1, 100, 100}, {2, 90, 99}}, 100, 10, []uint32{1, 2}},
		{"an SA with no packets before counts from zero",
			[]SACount{{1, 0, 0}}, []SACount{{1, 7, 9}}, 10, 3, []uint32{1}},
		{"late packets reduce the loss",
			[]SACount{{1, 90, 100}}, []SACount{{1, 95, 100}}, 0, -5, []uint32{1}},
		{"an SA that the receiver removed is forgotten",
			[]SACount{{1, 100, 100}, {2, 100, 100}}, []SACount{{2, 150, 200}}, 100, 50, []uint32{2}},
		{"a lower seq starts again",
			[]SACount{{1, 100, 100}}, []SACount{{1, 10, 10}}, 0, 0, []uint32{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			br := breaker{start: now, sas: map[uint32]SACount{}}
			for _, sa := range tc.saved {
				br.sas[sa.SPI] = sa
			}
			_, changed := br.addSAs(now.Add(100*time.Millisecond), tc.report)
			assert.False(t, changed)
			assert.Equal(t, tc.wantExpected, br.expected)
			assert.Equal(t, tc.wantLost, br.lost)
			assert.Equal(t, tc.wantSPIs, slices.Sorted(maps.Keys(br.sas)))
		})
	}
}

// TestRxReport checks the receive counters that a peer reports, and that the
// sender breaker trips on them.
func TestRxReport(t *testing.T) {
	a, b := newPair(t)
	now := time.Now()
	offer(t, now, a, b)
	spi := a.peer.tx.SA(0).SPI()
	pkt := packet(a.v4, b.v4, 17, 1, 2, 100)
	// a sends 10 packets. Packets 3, 5 and 7 do not arrive.
	for i := 1; i <= 10; i++ {
		phy := seal(a, pkt)
		require.NotNil(t, phy)
		if i != 3 && i != 5 && i != 7 {
			require.NotNil(t, open(b.b, phy[addrLen:]))
		}
	}
	got := b.peer.RxReport()
	require.Len(t, got, 1)
	assert.Equal(t, SACount{SPI: spi, Packets: 7, Seq: 9}, got[0], "sequence numbers start at 0")

	// After a rekey, the report has the old SA and the new one.
	_, err := rekey(now.Add(b.b.table.Lifetime()*3/4), b)
	require.NoError(t, err)
	assert.Len(t, b.peer.RxReport(), 2)

	// 50% loss in 3 intervals trips the breaker of a.
	var trips []Trip
	a.b.onTrip = func(p *Peer, tr Trip) {
		assert.Same(t, a.peer, p)
		trips = append(trips, tr)
	}
	sas := []SACount{{SPI: spi}}
	for i := range 4 {
		a.peer.Report(now.Add(time.Duration(i)*time.Second), sas)
		sas[0].Seq += 1000
		sas[0].Packets += 500
	}
	require.Len(t, trips, 1)
	assert.Equal(t, 50, trips[0].Loss)
	assert.Equal(t, int64(breakFloor), a.peer.Limit())

	// The peer removal clears the report.
	b.b.RemovePeer(b.peer)
	assert.Empty(t, b.peer.RxReport())
}
