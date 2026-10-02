// SPDX-License-Identifier: AGPL-3.0-only

package bench

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRTTStats(t *testing.T) {
	ms := func(v ...int) []time.Duration {
		d := make([]time.Duration, len(v))
		for i, x := range v {
			d[i] = time.Duration(x) * time.Millisecond
		}
		return d
	}
	cases := []struct {
		name string
		rtts []time.Duration
		lost int
		want RTTStats
	}{
		{name: "no probes", want: RTTStats{}},
		{name: "all lost", lost: 2, want: RTTStats{Probes: 2, Lost: 2}},
		{name: "one", rtts: ms(20), want: RTTStats{Probes: 1, P50: 20, P90: 20, P99: 20, Max: 20}},
		{
			name: "ten unsorted",
			rtts: ms(29, 20, 21, 22, 23, 24, 25, 26, 27, 28),
			lost: 1,
			want: RTTStats{Probes: 11, Lost: 1, P50: 24, P90: 28, P99: 29, Max: 29},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NewRTTStats(tc.rtts, tc.lost))
		})
	}
}

func TestProberWindow(t *testing.T) {
	p := &Prober{
		sent: []time.Duration{0, 10, 20, 30, 40},
		rtt:  []time.Duration{5, 0, 7, 8, 0},
	}
	cases := []struct {
		name     string
		from, to time.Duration
		want     []time.Duration
		lost     int
	}{
		{name: "middle", from: 10, to: 40, want: []time.Duration{7, 8}, lost: 1},
		{name: "all", from: 0, to: 50, want: []time.Duration{5, 7, 8}, lost: 2},
		{name: "end is not in the window", from: 0, to: 10, want: []time.Duration{5}},
		{name: "after the last probe", from: 50, to: 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rtts, lost := p.Window(tc.from, tc.to)
			assert.Equal(t, tc.want, rtts)
			assert.Equal(t, tc.lost, lost)
		})
	}
}

// TestProberEcho sends probes to a UDP echo on loopback.
func TestProberEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	go func() {
		b := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	require.NoError(t, err)
	defer conn.Close()

	start := time.Now()
	p := NewProber(conn, start, time.Millisecond, 100*time.Millisecond)
	go p.Receive()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	p.Send(ctx, time.Millisecond)
	require.Eventually(t, func() bool {
		_, lost := p.Window(0, time.Since(start))
		return lost == 0
	}, 5*time.Second, 10*time.Millisecond)

	rtts, _ := p.Window(0, time.Since(start))
	require.NotEmpty(t, rtts)
	for _, rtt := range rtts {
		assert.Positive(t, rtt)
		assert.Less(t, rtt, 5*time.Second)
	}
}

func TestSleep(t *testing.T) {
	flowErr := errors.New("write: broken pipe")
	cases := []struct {
		name    string
		cancel  bool
		done    func(chan error)
		wantErr error
		wantMsg string
	}{
		{name: "time ends"},
		{name: "context ends", cancel: true, wantErr: context.Canceled},
		{name: "flow fails", done: func(c chan error) { c <- flowErr }, wantErr: flowErr},
		{name: "flow stops", done: func(c chan error) { close(c) }, wantMsg: "a flow stopped before the end of the run"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			done := make(chan error, 1)
			if tc.done != nil {
				tc.done(done)
			}
			d := 10 * time.Millisecond
			if tc.cancel || tc.done != nil {
				d = time.Hour
			}
			err := Sleep(ctx, d, done)
			switch {
			case tc.wantErr != nil:
				assert.ErrorIs(t, err, tc.wantErr)
			case tc.wantMsg != "":
				assert.EqualError(t, err, tc.wantMsg)
			default:
				assert.NoError(t, err)
			}
		})
	}
}
