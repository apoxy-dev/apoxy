// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// fakeXDP is the row map of an XDP program in memory.
type fakeXDP struct {
	rows    map[xdpKey]fakeXDPRow
	tunnels map[uint32]uint64 // Drops of each tunnel.
	st      xdpStats
	putErr  error
	puts    int // Calls of putRow.
}

type fakeXDPRow struct {
	xdpRow
	c xdpCounters
}

func newFakeXDP() *fakeXDP {
	return &fakeXDP{rows: map[xdpKey]fakeXDPRow{}, tunnels: map[uint32]uint64{}}
}

var errNoKey = errors.New("no key")

func (f *fakeXDP) putRow(k xdpKey, w xdpRow) error {
	f.puts++
	if f.putErr != nil {
		return f.putErr
	}
	if w.tunnel != 0 {
		if _, ok := f.tunnels[w.tunnel]; !ok {
			return fmt.Errorf("no tunnel %d", w.tunnel)
		}
	}
	row := f.rows[k]
	row.xdpRow = w
	f.rows[k] = row
	return nil
}

func (f *fakeXDP) deleteRow(k xdpKey) (xdpCounters, error) {
	row, ok := f.rows[k]
	if !ok {
		return xdpCounters{}, errNoKey
	}
	delete(f.rows, k)
	return row.c, nil
}

func (f *fakeXDP) counters(k xdpKey) (xdpCounters, error) {
	row, ok := f.rows[k]
	if !ok {
		return xdpCounters{}, errNoKey
	}
	return row.c, nil
}

func (f *fakeXDP) putTunnel(id uint32) error {
	f.tunnels[id] = 0
	return nil
}

func (f *fakeXDP) deleteTunnel(id uint32) (uint64, error) {
	d, ok := f.tunnels[id]
	if !ok {
		return 0, errNoKey
	}
	delete(f.tunnels, id)
	return d, nil
}

func (f *fakeXDP) tunnelDrops(id uint32) (uint64, error) {
	d, ok := f.tunnels[id]
	if !ok {
		return 0, errNoKey
	}
	return d, nil
}

func (f *fakeXDP) stats() (xdpStats, error) { return f.st, nil }

// installed returns the rows of f as "source/SPI" -> "next hop".
func (f *fakeXDP) installed() map[string]string {
	out := map[string]string{}
	for k, w := range f.rows {
		out[fmt.Sprintf("%s/%d", k.src, k.spi)] = w.next.String()
	}
	return out
}

func key(src string, spi uint32) xdpKey {
	return xdpKey{netip.MustParseAddrPort(src), spi}
}

// flushXDP runs the XDP sync as Run does after a mark.
func flushXDP(r *Router, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncXDP(now)
}

// checkForward checks that Forward sends the packets of each XDP row to
// the next hop of the row.
func checkForward(t *testing.T, r *Router, f *fakeXDP, now time.Time) {
	t.Helper()
	for k, w := range f.rows {
		dst, v := r.Forward(k.src, k.spi, 100, now)
		assert.Equal(t, Pass, v, "row %s/%d", k.src, k.spi)
		assert.Equal(t, w.next, dst, "row %s/%d", k.src, k.spi)
		assert.False(t, now.After(w.expires), "row %s/%d expired", k.src, k.spi)
	}
}

func TestXDPSync(t *testing.T) {
	const (
		snd   = "192.0.2.1:1000"
		rcv   = "192.0.2.2:2000"
		moved = "198.51.100.1:3000"
	)
	type env struct {
		r        *Router
		f        *fakeXDP
		snd, rcv testSession
	}
	cases := []struct {
		name string
		// run changes the router after SPI 1 and 2 of snd go to rcv.
		run  func(t *testing.T, e env)
		at   time.Duration // Time of the sync after t0.
		want map[string]string
	}{
		{
			name: "register",
			run:  func(*testing.T, env) {},
			want: map[string]string{snd + "/1": rcv, snd + "/2": rcv},
		},
		{
			name: "unregister",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.unregisterSPI(e.snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{1}}))
			},
			want: map[string]string{snd + "/2": rcv},
		},
		{
			name: "expire",
			run:  func(_ *testing.T, e env) { e.r.Sweep(t0.Add(2 * time.Minute)) },
			at:   2 * time.Minute,
			want: map[string]string{},
		},
		{
			name: "re-register keeps the row",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.registerSPI(e.snd.Session, register(vpcA, "fd00::2", time.Hour, 1), t0.Add(time.Minute)))
				e.r.Sweep(t0.Add(90 * time.Second))
			},
			at:   90 * time.Second,
			want: map[string]string{snd + "/1": rcv},
		},
		{
			name: "sender closes",
			run:  func(_ *testing.T, e env) { e.r.removeSession(e.snd.Session) },
			want: map[string]string{},
		},
		{
			name: "receiver closes",
			run:  func(_ *testing.T, e env) { e.r.removeSession(e.rcv.Session) },
			want: map[string]string{},
		},
		{
			name: "permit denies",
			run: func(_ *testing.T, e env) {
				e.r.SetPermit(func(VPCKey, string, VPCKey, netip.Addr) bool { return false })
			},
			want: map[string]string{},
		},
		{
			name: "route removed",
			run:  func(_ *testing.T, e env) { e.r.RemoveRoute(e.rcv.Session, netip.MustParsePrefix("fd00::2/128")) },
			want: map[string]string{},
		},
		{
			name: "sender migrates",
			run: func(_ *testing.T, e env) {
				e.snd.addr.set(moved)
				e.r.Sweep(t0)
			},
			want: map[string]string{snd + "/1": rcv, snd + "/2": rcv, moved + "/1": rcv, moved + "/2": rcv},
		},
		{
			name: "old sender address ends",
			run: func(_ *testing.T, e env) {
				e.snd.addr.set(moved)
				e.r.Sweep(t0)
				e.r.Sweep(t0.Add(rebindOverlap + time.Second))
			},
			at:   rebindOverlap + time.Second,
			want: map[string]string{moved + "/1": rcv, moved + "/2": rcv},
		},
		{
			name: "receiver migrates",
			run: func(_ *testing.T, e env) {
				e.rcv.addr.set(moved)
				e.r.Sweep(t0)
			},
			want: map[string]string{snd + "/1": moved, snd + "/2": moved},
		},
		{
			name: "receiver of the other family",
			run: func(_ *testing.T, e env) {
				e.rcv.addr.set("[2001:db8::2]:2000")
				e.r.Sweep(t0)
			},
			want: map[string]string{},
		},
		{
			name: "row to the relay",
			run: func(_ *testing.T, e env) {
				local := newSession(Identity{}, func() netip.AddrPort { return netip.AddrPort{} })
				e.r.mu.Lock()
				e.snd.rows[3] = &row{sender: e.snd.Session, receiver: local, spi: 3, expires: t0.Add(time.Minute)}
				e.r.markXDP(e.snd.Session)
				e.r.mu.Unlock()
			},
			want: map[string]string{snd + "/1": rcv, snd + "/2": rcv},
		},
		{
			name: "map full",
			run: func(_ *testing.T, e env) {
				e.r.clearXDP()
				e.f.putErr = errors.New("map full")
				e.r.setXDP(e.f, t0)
			},
			want: map[string]string{},
		},
		{
			name: "map has room again",
			run: func(_ *testing.T, e env) {
				e.r.clearXDP()
				e.f.putErr = errors.New("map full")
				e.r.setXDP(e.f, t0)
				e.f.putErr = nil
				e.r.Sweep(t0)
			},
			want: map[string]string{snd + "/1": rcv, snd + "/2": rcv},
		},
		{
			name: "failed update leaves no row",
			run: func(_ *testing.T, e env) {
				e.f.putErr = errors.New("update failed")
				e.rcv.addr.set(moved)
				e.r.Sweep(t0)
			},
			want: map[string]string{},
		},
		{
			name: "update works again",
			run: func(_ *testing.T, e env) {
				e.f.putErr = errors.New("update failed")
				e.rcv.addr.set(moved)
				e.r.Sweep(t0)
				e.f.putErr = nil
				e.r.Sweep(t0)
			},
			want: map[string]string{snd + "/1": moved, snd + "/2": moved},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			f := newFakeXDP()
			r.setXDP(f, t0)
			e := env{r: r, f: f}
			e.snd = addSession(t, r, vpcA, "sender", snd, "fd00::1/128")
			e.rcv = addSession(t, r, vpcA, "receiver", rcv, "fd00::2/128")
			require.NoError(t, r.registerSPI(e.snd.Session, register(vpcA, "fd00::2", time.Minute, 1, 2), t0))
			now := t0.Add(tc.at)
			tc.run(t, e)
			flushXDP(r, now)
			assert.Equal(t, tc.want, f.installed())
			checkForward(t, r, f, now)
		})
	}
}

// TestXDPSyncTwin checks the rows of two sessions of one agent socket.
func TestXDPSyncTwin(t *testing.T) {
	const addr = "192.0.2.1:1000"
	cases := []struct {
		name  string
		close string // "old", "new" or "".
		local bool   // The new session has a row to the relay with SPI 1.
		want  map[string]string
	}{
		{"both sessions open", "", false, map[string]string{addr + "/1": "192.0.2.2:2000", addr + "/2": "192.0.2.2:2000"}},
		{"old session closes", "old", false, map[string]string{addr + "/2": "192.0.2.2:2000"}},
		{"new session closes", "new", false, map[string]string{addr + "/1": "192.0.2.2:2000"}},
		{"row to the relay hides the old row", "", true, map[string]string{addr + "/2": "192.0.2.2:2000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			f := newFakeXDP()
			r.setXDP(f, t0)
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			old := addSession(t, r, vpcA, "agent", addr).Session
			require.NoError(t, r.openSync(old, dp.Mode_MODE_PSP, ref(vpcA), nil))
			require.NoError(t, r.registerSPI(old, register(vpcA, "fd00::2", time.Minute, 1), t0))
			next := addSession(t, r, vpcA, "agent", addr).Session
			require.NoError(t, r.openSync(next, dp.Mode_MODE_PSP, ref(vpcA), nil))
			require.NoError(t, r.registerSPI(next, register(vpcA, "fd00::2", time.Minute, 2), t0))
			if tc.local {
				local := newSession(Identity{}, func() netip.AddrPort { return netip.AddrPort{} })
				r.mu.Lock()
				next.rows[1] = &row{sender: next, receiver: local, spi: 1, expires: t0.Add(time.Minute)}
				r.markXDP(next)
				r.mu.Unlock()
			}
			switch tc.close {
			case "old":
				r.removeSession(old)
			case "new":
				r.removeSession(next)
			}
			flushXDP(r, t0)
			assert.Equal(t, tc.want, f.installed())
			checkForward(t, r, f, t0)
		})
	}
}

// TestXDPSyncNoChange checks that a sync with no change writes no row.
func TestXDPSyncNoChange(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no meters", Config{}},
		{"tunnel meter", Config{TunnelRate: 1e6}},
		{"lane and tunnel meters", Config{LaneRate: 1e6, TunnelRate: 1e6}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, tc.cfg)
			f := newFakeXDP()
			r.setXDP(f, t0)
			snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Hour, 1, 2), t0))
			flushXDP(r, t0)
			require.Len(t, f.rows, 2)
			puts := f.puts
			r.Sweep(t0.Add(time.Second))
			r.Sweep(t0.Add(2 * time.Second))
			assert.Equal(t, puts, f.puts)
		})
	}
}

// TestXDPExpiry checks the expiry of the XDP rows.
func TestXDPExpiry(t *testing.T) {
	r := NewRouter(nil, Config{})
	f := newFakeXDP()
	r.setXDP(f, t0)
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))
	flushXDP(r, t0)
	assert.Equal(t, t0.Add(time.Minute), f.rows[key("192.0.2.1:1000", 1)].expires)

	// The old address of a sender ends at the end of the overlap.
	snd.addr.set("198.51.100.1:3000")
	r.Sweep(t0)
	assert.Equal(t, t0.Add(rebindOverlap), f.rows[key("192.0.2.1:1000", 1)].expires)
	assert.Equal(t, t0.Add(time.Minute), f.rows[key("198.51.100.1:3000", 1)].expires)
}

// TestXDPIdle checks that XDP traffic keeps a row.
func TestXDPIdle(t *testing.T) {
	cases := []struct {
		name string
		used time.Duration // Last XDP forward after t0, or 0 for none.
		want bool
	}{
		{"XDP traffic keeps the row", 9 * time.Minute, true},
		{"idle row goes", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			f := newFakeXDP()
			r.setXDP(f, t0)
			snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Hour, 1), t0))
			flushXDP(r, t0)
			k := key("192.0.2.1:1000", 1)
			if tc.used != 0 {
				w := f.rows[k]
				w.c.used = t0.Add(tc.used)
				f.rows[k] = w
			}
			r.Sweep(t0.Add(rowIdle + 5*time.Minute))
			_, ok := f.rows[k]
			assert.Equal(t, tc.want, ok)
			assert.Equal(t, tc.want, len(r.SenderStats(snd.Session).Lanes) == 1)
		})
	}
}

// TestXDPCounters checks that the sender counters and the metrics have the
// XDP counters, also after the XDP rows go.
func TestXDPCounters(t *testing.T) {
	r := NewRouter(nil, Config{LaneRate: 1e6, TunnelRate: 1e6})
	f := newFakeXDP()
	r.setXDP(f, t0)
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	other := addSession(t, r, vpcA, "other", "192.0.2.3:1000", "fd00::3/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1, 2), t0))
	require.NoError(t, r.registerSPI(other.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))
	flushXDP(r, t0)

	// The rows of one sender share a tunnel limit.
	k1, k2, k3 := key("192.0.2.1:1000", 1), key("192.0.2.1:1000", 2), key("192.0.2.3:1000", 1)
	require.NotZero(t, f.rows[k1].tunnel)
	assert.Equal(t, f.rows[k1].tunnel, f.rows[k2].tunnel)
	assert.NotEqual(t, f.rows[k1].tunnel, f.rows[k3].tunnel)
	assert.Len(t, f.tunnels, 2)

	w := f.rows[k1]
	w.c = xdpCounters{packets: 5, bytes: 500, drops: 2, used: t0}
	f.rows[k1] = w
	f.tunnels[w.tunnel] = 3
	f.st = xdpStats{packets: 5, bytes: 500, laneDrops: 2, tunnelDrops: 3, noRow: 7, tooLong: 1}
	r.Forward(netip.MustParseAddrPort("192.0.2.1:1000"), 1, 100, t0)

	want := SenderStats{
		DropMeter:       2,
		DropTunnelLimit: 3,
		Lanes: []LaneStats{
			{SPI: 1, Destination: netip.MustParseAddr("fd00::2"), Packets: 6, Bytes: 600, DropMeter: 2},
			{SPI: 2, Destination: netip.MustParseAddr("fd00::2")},
		},
	}
	assert.Equal(t, want, r.SenderStats(snd.Session))

	// The counters stay after the rows go.
	require.NoError(t, r.unregisterSPI(snd.Session, &dp.UnregisterSPIRequest{Vpc: ref(vpcA), Spis: []uint32{2}}))
	flushXDP(r, t0)
	assert.Equal(t, want.Lanes[:1], r.SenderStats(snd.Session).Lanes)
	r.removeSession(snd.Session)
	flushXDP(r, t0)
	st := r.SenderStats(snd.Session)
	assert.Equal(t, uint64(2), st.DropMeter)
	assert.Equal(t, uint64(3), st.DropTunnelLimit)
	assert.Len(t, f.tunnels, 1)
	assert.Equal(t, map[string]string{"192.0.2.3:1000/1": "192.0.2.2:2000"}, f.installed())

	const metrics = `
# HELP apoxy_vpc_relay_dropped_packets_total Packets that the relay dropped before it forwarded them, by reason.
# TYPE apoxy_vpc_relay_dropped_packets_total counter
apoxy_vpc_relay_dropped_packets_total{reason="closed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="lane_meter"} 2
apoxy_vpc_relay_dropped_packets_total{reason="malformed"} 0
apoxy_vpc_relay_dropped_packets_total{reason="send_queue"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_keys"} 0
apoxy_vpc_relay_dropped_packets_total{reason="trunk_mtu"} 0
apoxy_vpc_relay_dropped_packets_total{reason="tunnel_limit"} 3
apoxy_vpc_relay_dropped_packets_total{reason="unknown_source"} 0
apoxy_vpc_relay_dropped_packets_total{reason="unknown_spi"} 0
# HELP apoxy_vpc_relay_xdp_forwarded_bytes_total UDP payload bytes that the XDP program forwarded.
# TYPE apoxy_vpc_relay_xdp_forwarded_bytes_total counter
apoxy_vpc_relay_xdp_forwarded_bytes_total 500
# HELP apoxy_vpc_relay_xdp_packets_total PSP packets that the XDP program forwarded, or gave to the socket path, by result.
# TYPE apoxy_vpc_relay_xdp_packets_total counter
apoxy_vpc_relay_xdp_packets_total{result="expired"} 0
apoxy_vpc_relay_xdp_packets_total{result="forwarded"} 5
apoxy_vpc_relay_xdp_packets_total{result="malformed"} 0
apoxy_vpc_relay_xdp_packets_total{result="no_route"} 0
apoxy_vpc_relay_xdp_packets_total{result="no_row"} 7
apoxy_vpc_relay_xdp_packets_total{result="too_long"} 1
`
	assert.NoError(t, testutil.CollectAndCompare(r, strings.NewReader(metrics)))
	// The counters stay after the program stops.
	r.clearXDP()
	assert.Empty(t, f.rows)
	assert.Empty(t, f.tunnels)
	assert.NoError(t, testutil.CollectAndCompare(r, strings.NewReader(metrics)))
}

// TestXDPWake checks that Run syncs the rows after a change.
func TestXDPWake(t *testing.T) {
	r := NewRouter(nil, Config{})
	f := newFakeXDP()
	r.setXDP(f, t0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	now := time.Now()
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), now))
	installed := func() map[string]string {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return f.installed()
	}
	require.Eventually(t, func() bool { return len(installed()) == 1 }, 5*time.Second, time.Millisecond)
	r.removeSession(snd.Session)
	require.Eventually(t, func() bool { return len(installed()) == 0 }, 5*time.Second, time.Millisecond)
}
