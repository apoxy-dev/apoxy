// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	statsSnd = "192.0.2.1:1000"
	statsRcv = "192.0.2.2:2000"
	// innerLen is the inner packet size of the test packets, and pspLen is the
	// UDP payload of a PSP packet that carries one.
	innerLen = 100
	pspLen   = innerLen + pspwire.Overhead
)

// statsEnv is a router with XDP. The sender has attachment "snd" and SPI 1 to
// attachment "rcv" of the receiver.
type statsEnv struct {
	r        *Router
	f        *fakeXDP
	snd, rcv testSession
}

func newStatsEnv(t *testing.T, cfg Config) statsEnv {
	t.Helper()
	r := NewRouter(nil, cfg)
	f := newFakeXDP()
	r.setXDP(f, t0)
	e := statsEnv{r: r, f: f}
	e.snd = addSession(t, r, vpcA, "sender", statsSnd)
	e.rcv = addSession(t, r, vpcA, "receiver", statsRcv)
	require.NoError(t, r.attach(e.snd.Session, attachment("snd", "fd00:1::/96")))
	require.NoError(t, r.attach(e.rcv.Session, attachment("rcv", "fd00:2::/96")))
	e.register(t, "fd00:2::1", 1)
	return e
}

// attachment returns an attachment with the addresses.
func attachment(id string, addrs ...string) *Attachment {
	a := &Attachment{ID: id, VPC: vpcA, NetworkID: testVNI, Network: "net-a", Name: "name-" + id}
	for _, p := range addrs {
		a.Addresses = append(a.Addresses, netip.MustParsePrefix(p))
	}
	return a
}

// register gives the sender the SPIs to dst and installs their XDP rows.
func (e statsEnv) register(t *testing.T, dst string, spis ...uint32) {
	t.Helper()
	require.NoError(t, e.r.registerSPI(e.snd.Session, register(vpcA, dst, time.Hour, spis...), t0))
	flushXDP(e.r, t0)
}

// socket sends n PSP packets of the sender with spi on the socket path.
func (e statsEnv) socket(t *testing.T, spi uint32, n int) {
	t.Helper()
	for range n {
		_, v := e.r.Forward(netip.MustParseAddrPort(statsSnd), spi, pspLen, t0)
		require.Equal(t, Pass, v)
	}
}

// xdp adds n forwarded packets and drops lane meter drops to the XDP row of spi.
func (e statsEnv) xdp(t *testing.T, spi uint32, n, drops uint64) {
	t.Helper()
	k := key(statsSnd, spi)
	row, ok := e.f.rows[k]
	require.True(t, ok, "no XDP row for SPI %d", spi)
	row.c.packets += n
	row.c.bytes += n * pspLen
	row.c.drops += drops
	e.f.rows[k] = row
}

// flows returns the counters of each attachment by ID.
func flows(sts []AttachmentStats) map[string]counts {
	out := map[string]counts{}
	for _, st := range sts {
		out[st.ID] = countsOf(st)
	}
	return out
}

func countsOf(st AttachmentStats) counts {
	return counts{st.RXPackets, st.RXBytes, st.RXDrops, st.TXPackets, st.TXBytes}
}

// rx and tx return the counters of n test packets in one direction.
func rx(n uint64) counts { return counts{rxPackets: n, rxBytes: n * innerLen} }
func tx(n uint64) counts { return counts{txPackets: n, txBytes: n * innerLen} }

func TestAttachmentStats(t *testing.T) {
	// A packet above the burst of a meter drops at once.
	const tooLong = minBurst + 1
	cases := []struct {
		name string
		cfg  Config
		run  func(t *testing.T, e statsEnv)
		want map[string]counts
	}{
		{
			name: "no traffic",
			run:  func(*testing.T, statsEnv) {},
			want: map[string]counts{"snd": {}, "rcv": {}},
		},
		{
			name: "socket path",
			run:  func(t *testing.T, e statsEnv) { e.socket(t, 1, 3) },
			want: map[string]counts{"snd": rx(3), "rcv": tx(3)},
		},
		{
			name: "XDP path",
			run:  func(t *testing.T, e statsEnv) { e.xdp(t, 1, 5, 0) },
			want: map[string]counts{"snd": rx(5), "rcv": tx(5)},
		},
		{
			name: "both paths",
			run: func(t *testing.T, e statsEnv) {
				e.socket(t, 1, 3)
				e.xdp(t, 1, 5, 0)
			},
			want: map[string]counts{"snd": rx(8), "rcv": tx(8)},
		},
		{
			name: "row ends",
			run: func(t *testing.T, e statsEnv) {
				e.socket(t, 1, 3)
				e.xdp(t, 1, 5, 0)
				require.NoError(t, e.r.unregisterSPI(e.snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{1}}))
				// XDP forwards until the sync removes its row.
				e.xdp(t, 1, 2, 0)
				flushXDP(e.r, t0)
			},
			want: map[string]counts{"snd": rx(10), "rcv": tx(10)},
		},
		{
			name: "new row with the SPI of a row that ended",
			run: func(t *testing.T, e statsEnv) {
				e.xdp(t, 1, 5, 0)
				require.NoError(t, e.r.unregisterSPI(e.snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{1}}))
				e.register(t, "fd00:2::1", 1)
				e.socket(t, 1, 1)
				e.xdp(t, 1, 2, 0)
			},
			want: map[string]counts{"snd": rx(8), "rcv": tx(8)},
		},
		{
			name: "idle row expires",
			run: func(t *testing.T, e statsEnv) {
				e.socket(t, 1, 3)
				e.xdp(t, 1, 5, 0)
				e.r.Sweep(t0.Add(2 * time.Hour))
			},
			want: map[string]counts{"snd": rx(8), "rcv": tx(8)},
		},
		{
			name: "unknown SPI",
			run: func(_ *testing.T, e statsEnv) {
				e.r.Forward(netip.MustParseAddrPort(statsSnd), 9, pspLen, t0)
			},
			want: map[string]counts{"snd": {rxDrops: 1}, "rcv": {}},
		},
		{
			name: "lane meter",
			cfg:  Config{LaneRate: 1},
			run: func(t *testing.T, e statsEnv) {
				e.socket(t, 1, 2)
				e.r.Forward(netip.MustParseAddrPort(statsSnd), 1, tooLong, t0)
				e.xdp(t, 1, 0, 4)
			},
			want: map[string]counts{"snd": {rxPackets: 2, rxBytes: 2 * innerLen, rxDrops: 5}, "rcv": tx(2)},
		},
		{
			name: "lane meter drops of an XDP row that ended",
			cfg:  Config{LaneRate: 1},
			run: func(t *testing.T, e statsEnv) {
				e.xdp(t, 1, 0, 4)
				require.NoError(t, e.r.unregisterSPI(e.snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{1}}))
				flushXDP(e.r, t0)
			},
			want: map[string]counts{"snd": {rxDrops: 4}, "rcv": {}},
		},
		{
			name: "tunnel limit",
			cfg:  Config{TunnelRate: 1},
			run: func(t *testing.T, e statsEnv) {
				e.r.Forward(netip.MustParseAddrPort(statsSnd), 1, tooLong, t0)
				// The sender has the first XDP tunnel.
				require.Contains(t, e.f.tunnels, uint32(1))
				e.f.tunnels[1] = 3
			},
			want: map[string]counts{"snd": {rxDrops: 4}, "rcv": {}},
		},
		{
			name: "each attachment of the receiver has its own TX",
			run: func(t *testing.T, e statsEnv) {
				require.NoError(t, e.r.attach(e.rcv.Session, attachment("rcv2", "fd00:3::/96")))
				e.register(t, "fd00:3::1", 2)
				e.socket(t, 1, 2)
				e.xdp(t, 2, 3, 0)
			},
			want: map[string]counts{"snd": rx(5), "rcv": tx(2), "rcv2": tx(3)},
		},
		{
			name: "the oldest attachment of the sender has all RX",
			run: func(t *testing.T, e statsEnv) {
				require.NoError(t, e.r.attach(e.snd.Session, attachment("snd2", "fd00:4::/96")))
				e.socket(t, 1, 4)
				e.r.Forward(netip.MustParseAddrPort(statsSnd), 9, pspLen, t0)
			},
			want: map[string]counts{"snd": {rxPackets: 4, rxBytes: 4 * innerLen, rxDrops: 1}, "snd2": {}, "rcv": tx(4)},
		},
		{
			name: "the next attachment starts at zero when the oldest one ends",
			run: func(t *testing.T, e statsEnv) {
				require.NoError(t, e.r.attach(e.snd.Session, attachment("snd2", "fd00:4::/96")))
				e.socket(t, 1, 4)
				e.xdp(t, 1, 1, 0)
				_, last, err := e.r.detach(e.snd.Session, "snd")
				require.NoError(t, err)
				assert.Equal(t, rx(5), countsOf(last))
				e.socket(t, 1, 2)
			},
			want: map[string]counts{"snd2": rx(2), "rcv": tx(7)},
		},
		{
			name: "attachment that is not the oldest ends",
			run: func(t *testing.T, e statsEnv) {
				require.NoError(t, e.r.attach(e.rcv.Session, attachment("rcv2", "fd00:3::/96")))
				e.register(t, "fd00:3::1", 2)
				e.socket(t, 2, 2)
				e.xdp(t, 2, 3, 0)
				_, last, err := e.r.detach(e.rcv.Session, "rcv2")
				require.NoError(t, err)
				assert.Equal(t, tx(5), countsOf(last))
				assert.Empty(t, e.f.rows[key(statsSnd, 2)], "the XDP row of the detached attachment stays")
			},
			want: map[string]counts{"snd": rx(5), "rcv": {}},
		},
		{
			name: "route moves to a newer attachment of the session",
			run: func(t *testing.T, e statsEnv) {
				route := netip.MustParsePrefix("10.0.0.0/24")
				first, second := attachment("first"), attachment("second")
				first.Routes, second.Routes = []netip.Prefix{route}, []netip.Prefix{route}
				require.NoError(t, e.r.attach(e.rcv.Session, first))
				e.register(t, "10.0.0.5", 2)
				e.socket(t, 2, 2)
				e.xdp(t, 2, 1, 0)
				require.NoError(t, e.r.attach(e.rcv.Session, second))
				e.socket(t, 2, 4)
			},
			want: map[string]counts{"snd": rx(7), "rcv": {}, "first": tx(3), "second": tx(4)},
		},
		{
			name: "route moves to another session",
			run: func(t *testing.T, e statsEnv) {
				// The two sessions are of one agent, so the newer attachment takes the route.
				other := addSession(t, e.r, vpcA, "receiver", "192.0.2.3:3000")
				route := netip.MustParsePrefix("10.0.0.0/24")
				first, second := attachment("first"), attachment("second")
				first.Routes, second.Routes = []netip.Prefix{route}, []netip.Prefix{route}
				require.NoError(t, e.r.attach(e.rcv.Session, first))
				e.register(t, "10.0.0.5", 2)
				e.xdp(t, 2, 2, 0)
				require.NoError(t, e.r.attach(other.Session, second))
				flushXDP(e.r, t0)
				e.xdp(t, 2, 4, 0)
			},
			want: map[string]counts{"snd": rx(6), "rcv": {}, "first": tx(2), "second": tx(4)},
		},
		{
			name: "a low read does not decrease a counter",
			run: func(t *testing.T, e statsEnv) {
				e.socket(t, 1, 3)
				e.xdp(t, 1, 5, 0)
				require.Equal(t, rx(8), flows(e.r.AttachmentStats())["snd"])
				// The packet count of the XDP row is ahead of its byte count.
				k := key(statsSnd, 1)
				row := e.f.rows[k]
				row.c.packets++
				e.f.rows[k] = row
			},
			want: map[string]counts{
				"snd": {rxPackets: 9, rxBytes: 8 * innerLen},
				"rcv": {txPackets: 9, txBytes: 8 * innerLen},
			},
		},
		{
			name: "the first attachment does not get the RX from before it",
			run: func(t *testing.T, e statsEnv) {
				e.socket(t, 1, 3)
				_, last, err := e.r.detach(e.snd.Session, "snd")
				require.NoError(t, err)
				assert.Equal(t, rx(3), countsOf(last))
				e.socket(t, 1, 2)
				require.NoError(t, e.r.attach(e.snd.Session, attachment("snd2", "fd00:4::/96")))
				e.socket(t, 1, 1)
			},
			want: map[string]counts{"snd2": rx(1), "rcv": tx(6)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newStatsEnv(t, tc.cfg)
			tc.run(t, e)
			assert.Equal(t, tc.want, flows(e.r.AttachmentStats()))
			// A second read gives the same counters.
			assert.Equal(t, tc.want, flows(e.r.AttachmentStats()))
		})
	}
}

// TestAttachmentStatsSessionEnd checks the last counters of the attachments
// of a session that closes, with XDP counts that come after the close.
func TestAttachmentStatsSessionEnd(t *testing.T) {
	cases := []struct {
		name  string
		close func(e statsEnv) *Session
		want  map[string]counts // Last counters of the closed session.
		live  map[string]counts // Counters of the other session.
	}{
		{
			name:  "sender closes",
			close: func(e statsEnv) *Session { return e.snd.Session },
			want:  map[string]counts{"snd": rx(10), "snd2": {}},
			live:  map[string]counts{"rcv": tx(10)},
		},
		{
			name:  "receiver closes",
			close: func(e statsEnv) *Session { return e.rcv.Session },
			want:  map[string]counts{"rcv": tx(10)},
			live:  map[string]counts{"snd": rx(10), "snd2": {}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newStatsEnv(t, Config{})
			require.NoError(t, e.r.attach(e.snd.Session, attachment("snd2", "fd00:4::/96")))
			e.socket(t, 1, 3)
			e.xdp(t, 1, 5, 0)
			s := tc.close(e)
			e.r.removeSession(s)
			// XDP forwards until the sync removes its row.
			e.xdp(t, 1, 2, 0)
			atts, last := e.r.endAttachments(s)
			require.Len(t, last, len(atts))
			assert.Equal(t, tc.want, flows(last))
			assert.Empty(t, e.f.rows, "XDP rows after the sync")
			assert.Equal(t, tc.live, flows(e.r.AttachmentStats()))
			again, _ := e.r.endAttachments(s)
			assert.Empty(t, again, "the attachments end one time")
		})
	}
}

// dataSession adds a session in mode at addr with one attachment. Its
// datagrams go nowhere.
func dataSession(t *testing.T, r *Router, id, addr, prefix string, mode dp.Mode) *Session {
	t.Helper()
	ap := netip.MustParseAddrPort(addr)
	s := newSession(Identity{VPC: vpcA, ID: id}, func() netip.AddrPort { return ap })
	s.sendDatagram = func([]byte) error { return nil }
	r.addSession(s, t0)
	require.NoError(t, r.attach(s, attachment(id, prefix)))
	require.NoError(t, r.openSync(s, mode, ref(vpcA), nil))
	return s
}

// TestAttachmentStatsData checks the counters of the data frames of sessions
// in QUIC mode.
func TestAttachmentStatsData(t *testing.T) {
	frame := func(dst string) []byte {
		inner := ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr(dst), make([]byte, innerLen-40))
		return peerconn.EncodeData(nil, testVNI, inner)
	}
	cases := []struct {
		name string
		// send sends the frames of src, or of its shard.
		send func(t *testing.T, r *Router, src, shard *Session, buf []byte)
		want map[string]counts
	}{
		{
			name: "data frames",
			send: func(t *testing.T, r *Router, src, _ *Session, buf []byte) {
				for range 3 {
					require.True(t, r.forwardData(src, frame("fd00:2::1"), buf, t0))
				}
			},
			want: map[string]counts{"src": rx(3), "dst": tx(3)},
		},
		{
			name: "data frames on a shard count for its owner",
			send: func(t *testing.T, r *Router, src, shard *Session, buf []byte) {
				require.True(t, r.forwardData(src, frame("fd00:2::1"), buf, t0))
				require.True(t, r.forwardData(shard, frame("fd00:2::1"), buf, t0))
			},
			want: map[string]counts{"src": rx(2), "dst": tx(2)},
		},
		{
			name: "no route",
			send: func(t *testing.T, r *Router, src, _ *Session, buf []byte) {
				require.False(t, r.forwardData(src, frame("fd00:9::1"), buf, t0))
			},
			want: map[string]counts{"src": {rxDrops: 1}, "dst": {}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := localRouter(t)
			src := dataSession(t, r, "src", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_QUIC)
			dataSession(t, r, "dst", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_QUIC)
			shard := newSession(src.id, func() netip.AddrPort { return netip.AddrPort{} })
			r.addSession(shard, t0)
			_, _, err := r.joinShard(shard, "src", 1)
			require.NoError(t, err)
			tc.send(t, r, src, shard, make([]byte, maxUDP))
			assert.Equal(t, tc.want, flows(r.AttachmentStats()))
		})
	}
}

// TestAttachmentStatsBridge checks the counters of the packets that the relay
// opens or seals itself. Each packet must count one time for each end.
func TestAttachmentStatsBridge(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	ends := map[string]*end{
		"q1": newEnd(t, h, ca, "q1", dp.Mode_MODE_QUIC),
		"q2": newEnd(t, h, ca, "q2", dp.Mode_MODE_QUIC),
		"p1": newEnd(t, h, ca, "p1", dp.Mode_MODE_PSP),
	}
	ends["p1"].giveSAs(t)
	byName := func() map[string]counts {
		out := map[string]counts{}
		for _, st := range h.r.AttachmentStats() {
			out[st.Name] = countsOf(st)
		}
		return out
	}

	cases := []struct {
		name     string
		from, to string
	}{
		{"QUIC to QUIC", "q1", "q2"},
		{"QUIC to PSP", "q1", "p1"},
		{"PSP to QUIC", "p1", "q2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from, to := ends[tc.from], ends[tc.to]
			inner := ipPacket(from.addr, to.addr, []byte(tc.name))
			size := uint64(len(inner))
			want := byName()
			f, r := want[tc.from], want[tc.to]
			f.rxPackets, f.rxBytes = f.rxPackets+1, f.rxBytes+size
			r.txPackets, r.txBytes = r.txPackets+1, r.txBytes+size
			want[tc.from], want[tc.to] = f, r

			from.send(t, inner)
			got, _ := to.recv(t)
			require.Equal(t, inner, got)
			// The relay counts the packet after the send returns.
			assert.Eventually(t, func() bool { return assert.ObjectsAreEqual(want, byName()) },
				5*time.Second, time.Millisecond)
			assert.Equal(t, want, byName())
		})
	}
}

// TestAttachmentStatsIdentity checks the identity fields, the RTT and the order.
func TestAttachmentStatsIdentity(t *testing.T) {
	r := NewRouter(nil, Config{})
	before := time.Now()
	b := addSession(t, r, vpcA, "agent-b", "192.0.2.2:2000")
	a := addSession(t, r, vpcA, "agent-a", "192.0.2.1:1000")
	require.NoError(t, r.attach(b.Session, attachment("b", "fd00:2::/96")))
	require.NoError(t, r.attach(a.Session, attachment("a", "fd00:1::/96")))
	require.NoError(t, r.checkRevision(a.Session, dp.LocalVersion("v1.2.3")))
	a.rtt = new(atomic.Int64)
	a.rtt.Store(int64(5 * time.Millisecond))

	sts := r.AttachmentStats()
	require.Len(t, sts, 2)
	for _, st := range sts {
		assert.False(t, st.Since.Before(before), "attach time of %s", st.ID)
		assert.False(t, st.Since.After(time.Now()), "attach time of %s", st.ID)
	}
	sts[0].Since, sts[1].Since = time.Time{}, time.Time{}
	assert.Equal(t, []AttachmentStats{
		{ID: "a", Instance: 2, VPC: vpcA, Network: "net-a", Name: "name-a", Build: "v1.2.3", RTT: 5 * time.Millisecond},
		{ID: "b", Instance: 1, VPC: vpcA, Network: "net-a", Name: "name-b"},
	}, sts)
}

// TestAttachmentEnd checks that the relay gives the last counters of an
// attachment one time: at its Detach, or when its session ends.
func TestAttachmentEnd(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T, a agent, id string)
	}{
		{"detach", func(t *testing.T, a agent, id string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := a.c.Detach(ctx, &dp.DetachRequest{AttachmentId: id})
			require.NoError(t, err)
		}},
		{"session ends", func(t *testing.T, a agent, _ string) {
			require.NoError(t, a.qc.CloseWithError(0, ""))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newCA(t)
			var mu sync.Mutex
			var ended []AttachmentStats
			h := newHarness(t, ca, func(r *Router) {
				r.OnAttachmentEnd(func(st AttachmentStats) {
					mu.Lock()
					defer mu.Unlock()
					ended = append(ended, st)
				})
			})
			a := h.mustDial(t, ca.agentCert(t, vpcA, "agent"))
			open(t, a)
			id := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}).AttachmentId

			var live AttachmentStats
			require.Eventually(t, func() bool {
				sts := h.r.AttachmentStats()
				if len(sts) != 1 {
					return false
				}
				live = sts[0]
				return live.RTT > 0
			}, 5*time.Second, 5*time.Millisecond, "the attachment has no RTT")
			assert.Equal(t, id, live.ID)
			assert.Equal(t, "laptop", live.Name)
			assert.Equal(t, "net-a", live.Network)

			tc.end(t, a, id)
			require.Eventually(t, func() bool { return h.addrs.count() == 0 }, 5*time.Second, 5*time.Millisecond)
			_ = a.qc.CloseWithError(0, "")
			require.Eventually(t, func() bool {
				h.r.mu.RLock()
				defer h.r.mu.RUnlock()
				return len(h.r.sessions) == 0
			}, 5*time.Second, 5*time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			require.Len(t, ended, 1)
			assert.Equal(t, id, ended[0].ID)
			assert.Equal(t, live.Instance, ended[0].Instance)
			assert.Equal(t, live.Since, ended[0].Since)
			assert.Equal(t, "net-a", ended[0].Network)
			assert.Empty(t, h.r.AttachmentStats())
		})
	}
}
