package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"
	"github.com/apoxy-dev/icx/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestParseRate(t *testing.T) {
	cases := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{in: "0", want: 0},
		{in: "2G", want: 2e9},
		{in: "800m", want: 800e6},
		{in: "10K", want: 10e3},
		{in: "1.5e9", want: 1.5e9},
		{in: "", wantErr: true},
		{in: "G", wantErr: true},
		{in: "fast", wantErr: true},
		{in: "-1G", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseRate(tc.in)
			if tc.wantErr {
				require.ErrorContains(t, err, "bad rate")
				return
			}
			require.NoError(t, err)
			assert.InDelta(t, tc.want, got, 1e-6)
		})
	}
}

func TestPacerWait(t *testing.T) {
	start := time.Unix(1000, 0)
	cases := []struct {
		name string
		rate float64
		sent uint64
		now  time.Time
		want time.Duration
	}{
		{name: "no rate", rate: 0, sent: 1e6, now: start, want: 0},
		// 1250 B at 1 Gbps is 10 us for each packet.
		{name: "ahead", rate: 1e9, sent: 100, now: start, want: time.Millisecond},
		{name: "on time", rate: 1e9, sent: 100, now: start.Add(time.Millisecond), want: 0},
		{name: "behind", rate: 1e9, sent: 100, now: start.Add(3 * time.Millisecond), want: -2 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newPacer(tc.rate, 1250, start).wait(tc.sent, tc.now))
		})
	}
}

func TestNewResult(t *testing.T) {
	const size = 1000
	at := func(packets uint64, seconds, cpu float64) mark {
		return mark{Packets: packets, Bytes: packets * size, Nanos: int64(seconds * 1e9), CPU: cpu}
	}
	cases := []struct {
		name         string
		agent, relay [2]mark
		want         result
	}{
		{
			name:  "loss",
			agent: [2]mark{at(100, 1, 1), at(1_000_100, 11, 21)},
			relay: [2]mark{at(0, 1, 5), at(900_000, 11, 15)},
			want: result{
				Seconds: 10, BitsPerSecond: 0.72e9, PacketsPerSecond: 90_000, LostPercent: 10,
				SentBitsPerSecond: 0.8e9, AgentCores: 2, RelayCores: 1,
				AgentCoresPerGbps: 2 / 0.72, RelayCoresPerGbps: 1 / 0.72,
			},
		},
		{
			// The relay window starts later than the agent window, so it can count more packets.
			name:  "no loss",
			agent: [2]mark{at(0, 0, 0), at(1000, 1, 0.5)},
			relay: [2]mark{at(0, 0, 0), at(1001, 1, 0.5)},
			want: result{
				Seconds: 1, BitsPerSecond: 8.008e6, PacketsPerSecond: 1001, SentBitsPerSecond: 8e6,
				AgentCores: 0.5, RelayCores: 0.5, AgentCoresPerGbps: 0.5 / 8.008e-3, RelayCoresPerGbps: 0.5 / 8.008e-3,
			},
		},
		{name: "empty window"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := newResult("softpsp", size, tc.agent, tc.relay)
			tc.want.Transport, tc.want.Size = "softpsp", size
			assert.InDelta(t, tc.want.AgentCoresPerGbps, got.AgentCoresPerGbps, 1e-9)
			assert.InDelta(t, tc.want.RelayCoresPerGbps, got.RelayCoresPerGbps, 1e-9)
			got.AgentCoresPerGbps, got.RelayCoresPerGbps = tc.want.AgentCoresPerGbps, tc.want.RelayCoresPerGbps
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValidate(t *testing.T) {
	ok := options{Transport: "softpsp", Size: 1392, Batch: 64}
	cases := []struct {
		name    string
		edit    func(*options)
		wantErr string
	}{
		{name: "ok", edit: func(*options) {}},
		{name: "quic", edit: func(o *options) { o.Transport = "quic" }},
		{name: "unknown transport", edit: func(o *options) { o.Transport = "tcp" }, wantErr: "unknown transport"},
		{name: "small packet", edit: func(o *options) { o.Size = 27 }, wantErr: "bad -size"},
		{name: "large packet", edit: func(o *options) { o.Size = 9001 }, wantErr: "bad -size"},
		{name: "no batch", edit: func(o *options) { o.Batch = 0 }, wantErr: "bad -batch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := ok
			tc.edit(&o)
			err := o.validate()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestQlogWriter(t *testing.T) {
	rs := string(rune(recordSeparator))
	cases := []struct {
		name   string
		max    int64
		writes []string
		want   string
	}{
		{
			name:   "keeps records under the limit",
			max:    100,
			writes: []string{rs + "{hdr}\n", rs, "{a}", "\n"},
			want:   rs + "{hdr}\n" + rs + "{a}\n",
		},
		{
			name:   "finishes the open record",
			max:    1,
			writes: []string{rs, "{a}", "\n"},
			want:   rs + "{a}\n",
		},
		{
			name:   "drops later records",
			max:    5,
			writes: []string{rs, "{a}\n", rs, "{b}\n", rs, "{c}"},
			want:   rs + "{a}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			q := &qlogWriter{w: bufio.NewWriter(&out), c: nopCloser{}, max: tc.max}
			for _, w := range tc.writes {
				n, err := q.Write([]byte(w))
				require.NoError(t, err)
				assert.Equal(t, len(w), n)
			}
			require.NoError(t, q.Close())
			assert.Equal(t, tc.want, out.String())
		})
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestSoftPSPRoundTrip(t *testing.T) {
	agentAddr := &net.UDPAddr{IP: net.IPv4(10, 200, 0, 1), Port: 40000}
	relayAddr := &net.UDPAddr{IP: net.IPv4(10, 200, 0, 2), Port: 4433}
	cases := []struct {
		name      string
		size      int
		relayRole psp.Role
		wantOK    bool
	}{
		{name: "tunnel MTU", size: icx.MTU(1500), relayRole: psp.Responder, wantOK: true},
		{name: "small packet", size: 64, relayRole: psp.Responder, wantOK: true},
		{name: "jumbo packet", size: 8000, relayRole: psp.Responder, wantOK: true},
		{name: "same role on both sides", size: 1000, relayRole: psp.Initiator, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent, err := newEngine(agentAddr, relayAddr, psp.Initiator)
			require.NoError(t, err)
			relay, err := newEngine(relayAddr, agentAddr, tc.relayRole)
			require.NoError(t, err)

			pkt := innerPacket(tc.size)
			ip := header.IPv4(pkt)
			require.True(t, ip.IsValid(tc.size))
			require.True(t, ip.IsChecksumValid())

			payload, err := seal(agent, pkt, make([]byte, tc.size+encapRoom))
			require.NoError(t, err)
			buf := make([]byte, tc.size+encapRoom+512)
			copy(buf[udp.PayloadOffsetIPv4:], payload)
			virt := make([]byte, len(buf))
			n := open(relay, buf, len(payload), agentAddr, virt)
			if !tc.wantOK {
				assert.Zero(t, n)
				return
			}
			require.Equal(t, tc.size, n)
			assert.Equal(t, pkt, virt[:n])
		})
	}
}

// TestLoopback runs the agent and the relay over the loopback interface.
func TestLoopback(t *testing.T) {
	cases := []struct {
		name string
		o    options
	}{
		{name: "quic with qlog", o: options{Transport: "quic", QlogDir: t.TempDir(), QlogMax: 64 << 10}},
		{name: "softpsp", o: options{Transport: "softpsp", Batch: 8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.o
			o.Size, o.Rate = icx.MTU(1500), 100e6
			o.Omit, o.Duration = 200*time.Millisecond, 500*time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			conn, err := listenUDP(fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port))
			require.NoError(t, err)
			type relayResult struct {
				total mark
				err   error
			}
			relayDone := make(chan relayResult, 1)
			go func() {
				total, err := runRelay(ctx, o, ln, conn)
				relayDone <- relayResult{total, err}
			}()

			res, err := runAgent(ctx, o, ln.Addr().String())
			require.NoError(t, err)
			assert.Equal(t, transportName(o.Transport), res.Transport)
			assert.Greater(t, res.BitsPerSecond, 0.0)
			assert.Greater(t, res.AgentCoresPerGbps, 0.0)

			rr := <-relayDone
			require.NoError(t, rr.err)
			assert.Greater(t, rr.total.Packets, uint64(0))

			if o.QlogDir != "" {
				for _, side := range []string{"agent", "relay"} {
					files, err := filepath.Glob(filepath.Join(o.QlogDir, "*_"+side+"_*.sqlog"))
					require.NoError(t, err)
					require.Len(t, files, 1, side)
					data, err := os.ReadFile(files[0])
					require.NoError(t, err)
					require.NotEmpty(t, data)
					assert.Equal(t, byte(recordSeparator), data[0])
					assert.Equal(t, byte('\n'), data[len(data)-1])
					assert.Less(t, int64(len(data)), o.QlogMax+4<<10)
				}
			}
		})
	}
}
