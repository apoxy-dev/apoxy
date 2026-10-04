// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"fmt"
	"hash/maphash"
	"net/netip"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

// joinSeg is one slot of TestJoin: a TCP segment with the bytes off to off+n of the data
// of a flow, or a slot of another kind.
type joinSeg struct {
	flow, off, n int
	ack          uint32 // Added to the ACK number.
	flags        header.TCPFlags
	kind         string       // "", "udp", "notip" or "fail" (Open failed).
	edit         func([]byte) // Changes the packet after it is made.
}

// TestJoin makes the packets of one set and checks which slots join, and that each
// joined packet has the right headers and the data of its slots in order.
func TestJoin(t *testing.T) {
	const mss = 100
	segs := func(n, size int) []joinSeg {
		s := make([]joinSeg, n)
		for i := range s {
			s[i] = joinSeg{off: i * size, n: size}
		}
		return s
	}
	// ipEdit changes byte i of an IPv4 header or byte i6 of an IPv6 header.
	ipEdit := func(i int, x byte, i6 int, x6 byte) func([]byte) {
		return func(p []byte) {
			if p[0]>>4 == 4 {
				p[i] ^= x
			} else {
				p[i6] ^= x6
			}
		}
	}
	// tcpEdit changes byte i of the TCP header.
	tcpEdit := func(i int, x byte) func([]byte) {
		return func(p []byte) { p[ipHdrLen(p)+i] ^= x }
	}
	cases := []struct {
		name string
		in   []joinSeg
		want [][2]int // The first slot and the number of slots of each packet.
	}{
		{name: "in order", in: segs(4, mss), want: [][2]int{{0, 4}}},
		{name: "one segment", in: segs(1, mss), want: [][2]int{{0, 1}}},
		{name: "small segments", in: segs(8, 10), want: [][2]int{{0, 8}}},
		{name: "run in the first view", in: segs(2, 10), want: [][2]int{{0, 2}}},
		{
			name: "short segment ends the run",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss}, {off: 200, n: 50}, {off: 250, n: mss}},
			want: [][2]int{{0, 3}, {3, 1}},
		},
		{
			name: "longer segment",
			in:   []joinSeg{{off: 0, n: 50}, {off: 50, n: mss}},
			want: [][2]int{{0, 1}, {1, 1}},
		},
		{
			name: "PSH ends the run",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, flags: header.TCPFlagPsh}, {off: 200, n: mss}},
			want: [][2]int{{0, 2}, {2, 1}},
		},
		{
			name: "FIN",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, flags: header.TCPFlagFin}},
			want: [][2]int{{0, 2}},
		},
		{
			name: "hole",
			in:   []joinSeg{{off: 0, n: mss}, {off: 200, n: mss}, {off: 300, n: mss}},
			want: [][2]int{{0, 1}, {1, 2}},
		},
		{
			name: "two flows",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss}, {flow: 1, off: 0, n: mss}, {flow: 1, off: 100, n: mss}, {off: 200, n: mss}},
			want: [][2]int{{0, 2}, {2, 2}, {4, 1}},
		},
		{
			name: "other ACK",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, ack: 1}, {off: 200, n: mss, ack: 1}},
			want: [][2]int{{0, 1}, {1, 2}},
		},
		{
			name: "ACK with no data",
			in:   []joinSeg{{off: 0}, {off: 0}, {off: 0, n: mss}},
			want: [][2]int{{0, 1}, {1, 1}, {2, 1}},
		},
		{
			name: "SYN",
			in:   []joinSeg{{off: 0, n: mss, flags: header.TCPFlagSyn}, {off: 100, n: mss}, {off: 200, n: mss}},
			want: [][2]int{{0, 1}, {1, 2}},
		},
		{
			name: "CWR",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, flags: header.TCPFlagCwr}},
			want: [][2]int{{0, 1}, {1, 1}},
		},
		{
			name: "other window",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, edit: tcpEdit(15, 1)}},
			want: [][2]int{{0, 1}, {1, 1}},
		},
		{
			name: "other TS value",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, edit: tcpEdit(25, 1)}},
			want: [][2]int{{0, 1}, {1, 1}},
		},
		{
			name: "other checksum",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, edit: tcpEdit(16, 1)}},
			want: [][2]int{{0, 2}},
		},
		{
			name: "ECN CE mark",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, edit: ipEdit(1, 0x03, 1, 0x30)}},
			want: [][2]int{{0, 1}, {1, 1}},
		},
		{
			name: "other hop limit",
			in:   []joinSeg{{off: 0, n: mss}, {off: 100, n: mss, edit: ipEdit(8, 1, 7, 1)}},
			want: [][2]int{{0, 1}, {1, 1}},
		},
		{
			name: "Open failed",
			in:   []joinSeg{{off: 0, n: mss}, {kind: "fail"}, {off: 100, n: mss}},
			want: [][2]int{{0, 1}, {2, 1}},
		},
		{
			name: "UDP",
			in:   []joinSeg{{off: 0, n: mss}, {kind: "udp"}, {off: 100, n: mss}},
			want: [][2]int{{0, 1}, {1, 1}, {2, 1}},
		},
		{
			name: "not IP",
			in:   []joinSeg{{off: 0, n: mss}, {kind: "notip"}, {off: 100, n: mss}},
			want: [][2]int{{0, 1}, {2, 1}},
		},
		{
			// A joined packet has at most 64 KiB.
			name: "most",
			in:   segs(60, 1200),
			want: [][2]int{{0, 54}, {54, 6}},
		},
	}
	for _, v6 := range []bool{false, true} {
		src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
		if v6 {
			src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("v6=%t/%s", v6, tc.name), func(t *testing.T) {
				data := pattern(64 * 1200)
				res := make([]openResult, len(tc.in))
				for i, s := range tc.in {
					var p []byte
					switch s.kind {
					case "fail":
						continue
					case "udp":
						p = packet(src, dst, 17, 1, 2, 64)
					case "notip":
						p = []byte{0}
					default:
						p = tcpPacket(src, dst, uint16(1000+s.flow), uint32(s.off), 7+s.ack,
							header.TCPFlagAck|s.flags, data[s.off:s.off+s.n])
					}
					if s.edit != nil {
						s.edit(p)
					}
					res[i] = openResult{inner: p, ok: true}
				}
				j := &injectBatch{in: make([]chan []injected, 1)}
				out := make([]rxPacket, len(res))
				n := j.join(res, out)
				var got [][2]int
				for _, r := range out[:n] {
					got = append(got, [2]int{r.first, r.n})
					checkJoined(t, r, tc.in[r.first:r.first+r.n], res[r.first].inner, data)
					r.pkb.DecRef()
				}
				assert.Equal(t, tc.want, got)
			})
		}
	}
}

// checkJoined checks the packet r of the slots segs, of which the first holds first.
func checkJoined(t *testing.T, r rxPacket, segs []joinSeg, first, data []byte) {
	t.Helper()
	assert.True(t, r.pkb.RXChecksumValidated)
	v := r.pkb.ToView()
	defer v.Release()
	p := v.AsSlice()
	if r.n == 1 {
		assert.Equal(t, first, p)
		return
	}
	ipLen := ipHdrLen(p)
	buf := r.pkb.ToBuffer()
	defer buf.Release()
	var views []int
	buf.Apply(func(v *buffer.View) { views = append(views, v.Size()) })
	want := []int{min(headLen, len(p))}
	if len(p) > headLen {
		want = append(want, len(p)-headLen)
	}
	assert.Equal(t, want, views, "view sizes")
	if p[0]>>4 == 4 {
		h := header.IPv4(p)
		assert.Equal(t, len(p), int(h.TotalLength()))
		assert.True(t, h.IsChecksumValid(), "IPv4 checksum")
		assert.Equal(t, first[:2], p[:2], "IPv4 version and TOS")
		assert.Equal(t, first[4:10], p[4:10], "IPv4 ID, fragment, TTL and protocol")
		assert.Equal(t, first[12:20], p[12:20], "IPv4 addresses")
	} else {
		assert.Equal(t, len(p)-header.IPv6MinimumSize, int(header.IPv6(p).PayloadLength()))
		assert.Equal(t, first[6:40], p[6:40], "IPv6 header after the length")
	}
	th := header.TCP(p[ipLen:])
	var flags header.TCPFlags
	size := 0
	for _, s := range segs {
		flags |= s.flags
		size += s.n
	}
	ft := header.TCP(first[ipLen:])
	assert.Equal(t, ft.SequenceNumber(), th.SequenceNumber())
	assert.Equal(t, ft.Flags()|flags, th.Flags())
	assert.Equal(t, ft[header.TCPMinimumSize:ft.DataOffset()], th[header.TCPMinimumSize:th.DataOffset()], "TCP options")
	off := segs[0].off
	assert.True(t, bytes.Equal(data[off:off+size], th.Payload()), "payload of %d slots", r.n)
}

// ipHdrLen returns the IP header length of a test packet.
func ipHdrLen(p []byte) int {
	if p[0]>>4 == 4 {
		return header.IPv4MinimumSize
	}
	return header.IPv6MinimumSize
}

// pspEvent is one PSP packet of TestPipeJoin: segment seg of a flow, or a copy of the
// PSP packet of an earlier event.
type pspEvent struct {
	flow, seg int
	forged    bool
	copyOf    int // The index of the event to copy, plus one.
	end       bool
}

// TestPipeJoin gives reads of TCP segments of two flows to the demux. The netstack must get
// the data of each flow in order, and a joined packet drops when one of its segments drops.
func TestPipeJoin(t *testing.T) {
	const mss = 1000
	run := func(flow, from, to int) []pspEvent {
		var e []pspEvent
		for i := from; i < to; i++ {
			e = append(e, pspEvent{flow: flow, seg: i})
		}
		return e
	}
	cat := func(parts ...[]pspEvent) []pspEvent {
		var e []pspEvent
		for _, p := range parts {
			e = append(e, p...)
		}
		return e
	}
	cases := []struct {
		name    string
		events  []pspEvent
		want    map[int][][2]int // The segment ranges that each flow gets.
		drops   uint64
		icv     uint64
		replays uint64
	}{
		{
			name:   "runs of two flows",
			events: cat(run(0, 0, 10), run(1, 0, 10), run(0, 10, 20), run(1, 10, 12)),
			want:   map[int][][2]int{0: {{0, 20}}, 1: {{0, 12}}},
		},
		{
			name:   "forged segment in a run",
			events: cat(run(0, 0, 4), []pspEvent{{flow: 0, seg: 4, forged: true}}, run(0, 5, 10)),
			want:   map[int][][2]int{0: {{0, 4}, {5, 10}}},
			drops:  1, icv: 1,
		},
		{
			name:   "copy in a run",
			events: cat(run(0, 0, 5), []pspEvent{{copyOf: 3}}, run(0, 5, 10)),
			want:   map[int][][2]int{0: {{0, 10}}},
			drops:  1, replays: 1,
		},
		{
			// The copy of segment 1 from the first read joins segment 0, so both drop.
			name:   "old copy joins a run",
			events: []pspEvent{{flow: 0, seg: 1, end: true}, {flow: 0, seg: 0}, {copyOf: 1}},
			want:   map[int][][2]int{0: {{1, 2}}},
			drops:  2, replays: 1,
		},
	}
	for _, opens := range []int{0, 1, 3} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("opens=%d/%s", opens, tc.name), func(t *testing.T) {
				a, b := newPair(t)
				offer(t, time.Now(), a, b)
				r := &pktRecorder{}
				ep := channel.New(16, MaxMTU, "")
				ep.Attach(r)
				t.Cleanup(ep.Close)
				useNetstack(t, b, ep, 2, opens)
				data := pattern(32 * mss)
				var pkts [][]byte
				for _, e := range tc.events {
					var pkt []byte
					if e.copyOf > 0 {
						pkt = bytes.Clone(pkts[e.copyOf-1])
					} else {
						off := e.seg * mss
						pkt = seal(a, tcpPacket(a.v4, b.v4, uint16(1000+e.flow), uint32(off), 7, header.TCPFlagAck, data[off:off+mss]))[addrLen:]
						if e.forged {
							pkt = bytes.Clone(pkt)
							pkt[len(pkt)-1] ^= 1
						}
					}
					pkts = append(pkts, pkt)
					b.b.demux.Handle(bytes.Clone(pkt), nil)
					if e.end {
						b.b.demux.BatchEnd()
					}
				}
				b.b.demux.BatchEnd()
				h, err := pspwire.ParseHeader(pkts[0])
				require.NoError(t, err)
				total := uint64(len(tc.events))
				require.Eventually(t, func() bool {
					st := b.b.Stats()
					return st.RxPackets+st.RxDrops == total
				}, 5*time.Second, time.Millisecond)
				assert.Equal(t, Stats{RxPackets: total - tc.drops, RxDrops: tc.drops}, b.b.Stats())
				sa, ok := b.b.table.Stats(h.SPI)
				require.True(t, ok)
				assert.Equal(t, tc.icv, sa.ICVFailures)
				assert.Equal(t, tc.replays, sa.Replays)

				r.mu.Lock()
				defer r.mu.Unlock()
				got := map[int][][2]int{}
				for _, p := range r.pkts {
					th := header.TCP(p[header.IPv4MinimumSize:])
					flow := int(th.SourcePort()) - 1000
					off, n := int(th.SequenceNumber()), len(th.Payload())
					require.Zero(t, off%mss)
					require.Zero(t, n%mss)
					assert.True(t, bytes.Equal(data[off:off+n], th.Payload()), "payload of flow %d at %d", flow, off)
					rs := got[flow]
					// Join the ranges that follow each other.
					if k := len(rs) - 1; k >= 0 && rs[k][1] == off/mss {
						rs[k][1] += n / mss
					} else {
						rs = append(rs, [2]int{off / mss, (off + n) / mss})
					}
					got[flow] = rs
				}
				assert.Equal(t, tc.want, got)
			})
		}
	}
}

// BenchmarkJoin makes the packets of a set of 64 TCP segments of 1208 B of payload, in
// runs of 16 segments of 4 flows.
func BenchmarkJoin(b *testing.B) {
	src, dst := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	const mss, perRun = 1208, 16
	data := pattern(pipeSlots * mss)
	res := make([]openResult, pipeSlots)
	for i := range res {
		flow, k := i/perRun%4, i%perRun
		off := k * mss
		res[i] = openResult{inner: tcpPacket(src, dst, uint16(1000+flow), uint32(off), 7, header.TCPFlagAck, data[off:off+mss]), ok: true}
	}
	j := &injectBatch{seed: maphash.MakeSeed(), in: make([]chan []injected, 4)}
	out := make([]rxPacket, pipeSlots)
	b.SetBytes(pipeSlots * mss)
	b.ReportAllocs()
	for b.Loop() {
		n := j.join(res, out)
		for i := range out[:n] {
			out[i].pkb.DecRef()
			out[i] = rxPacket{}
		}
	}
}
