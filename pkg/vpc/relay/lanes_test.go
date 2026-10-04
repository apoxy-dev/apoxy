// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// registerLanes returns a RegisterSPI request for SPIs with their lanes.
func registerLanes(k VPCKey, dst string, spis, lanes []uint32) *dp.RegisterSPIRequest {
	req := register(k, dst, time.Minute, spis...)
	req.Lanes = lanes
	return req
}

// lanePorts returns the lane ports of s.
func lanePorts(r *Router, s *Session) []uint16 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []uint16
	for _, a := range s.lanes {
		out = append(out, a.Port())
	}
	return out
}

func TestRegisterLanes(t *testing.T) {
	const ip = "192.0.2.1"
	many := make([]uint32, MaxLaneSources+1)
	for i := range many {
		many[i] = uint32(3001 + i)
	}
	cases := []struct {
		name  string
		limit int
		ports []uint32
		code  rpc.Code
		want  []uint16
	}{
		{name: "two ports", limit: MaxLaneSources, ports: []uint32{2001, 2002}, want: []uint16{2001, 2002}},
		{name: "new ports", limit: MaxLaneSources, ports: []uint32{2003}, want: []uint16{2003}},
		{name: "no ports", limit: MaxLaneSources, want: nil},
		{name: "above the limit", limit: MaxLaneSources, ports: many, code: rpc.InvalidArgument, want: []uint16{2001}},
		{name: "above a lower limit", limit: 1, ports: []uint32{2001, 2002}, code: rpc.InvalidArgument, want: []uint16{2001}},
		{name: "port 0", limit: MaxLaneSources, ports: []uint32{0}, code: rpc.InvalidArgument, want: []uint16{2001}},
		{name: "port above 65535", limit: MaxLaneSources, ports: []uint32{70000}, code: rpc.InvalidArgument, want: []uint16{2001}},
		{name: "session port", limit: MaxLaneSources, ports: []uint32{1000}, code: rpc.InvalidArgument, want: []uint16{2001}},
		{name: "repeated port", limit: MaxLaneSources, ports: []uint32{2002, 2002}, code: rpc.InvalidArgument, want: []uint16{2001}},
		{name: "address of another agent", limit: MaxLaneSources, ports: []uint32{2002, 3000}, code: rpc.AlreadyExists, want: []uint16{2001}},
		{name: "lane port of another agent", limit: MaxLaneSources, ports: []uint32{4000}, code: rpc.AlreadyExists, want: []uint16{2001}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{LaneSources: tc.limit})
			snd := addSession(t, r, vpcA, "sender", ip+":1000", "fd00::1/128")
			rcv := addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			// Another agent behind the same IP address.
			other := addSession(t, r, vpcA, "other", ip+":3000", "fd00::3/128")
			require.NoError(t, r.registerLanes(other.Session, []uint32{4000}))
			require.NoError(t, r.registerLanes(snd.Session, []uint32{2001}))
			require.NoError(t, r.registerSPI(snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))

			err := r.registerLanes(snd.Session, tc.ports)
			require.Equal(t, tc.code, codeOf(err), "error: %v", err)
			assert.Equal(t, tc.want, lanePorts(r, snd.Session))
			for _, p := range []uint16{2001, 2002, 2003} {
				dst, v := r.Forward(netip.AddrPortFrom(netip.MustParseAddr(ip), p), 1, 100, t0)
				if slices.Contains(tc.want, p) {
					assert.Equal(t, Pass, v, "port %d", p)
					assert.Equal(t, rcv.addr.get(), dst, "port %d", p)
				} else {
					assert.Equal(t, DropUnknownSource, v, "port %d", p)
				}
			}
			// The other agent keeps its sources.
			r.mu.RLock()
			defer r.mu.RUnlock()
			assert.Same(t, other.Session, r.bySource[netip.MustParseAddrPort(ip+":3000")])
			assert.Same(t, other.Session, r.bySource[netip.MustParseAddrPort(ip+":4000")])
		})
	}
}

// TestLanePortsEnd checks that the lane ports of a session go away with the
// session, its address and its shard join.
func TestLanePortsEnd(t *testing.T) {
	const (
		snd   = "192.0.2.1:1000"
		moved = "198.51.100.1:1000"
	)
	type env struct {
		r   *Router
		snd testSession
	}
	cases := []struct {
		name string
		// run returns the session and the lane port that must go.
		run func(t *testing.T, e env) (*Session, string)
	}{
		{
			name: "session closes",
			run: func(_ *testing.T, e env) (*Session, string) {
				e.r.removeSession(e.snd.Session)
				return e.snd.Session, "192.0.2.1:2001"
			},
		},
		{
			name: "session moves",
			run: func(_ *testing.T, e env) (*Session, string) {
				e.snd.addr.set(moved)
				e.r.Sweep(t0)
				return e.snd.Session, "192.0.2.1:2001"
			},
		},
		{
			name: "new lane ports",
			run: func(t *testing.T, e env) (*Session, string) {
				require.NoError(t, e.r.registerLanes(e.snd.Session, []uint32{2003}))
				return e.snd.Session, "192.0.2.1:2001"
			},
		},
		{
			name: "session joins as a shard",
			run: func(t *testing.T, e env) (*Session, string) {
				require.NoError(t, e.r.openSync(e.snd.Session, dp.Mode_MODE_QUIC, ref(vpcA)))
				require.NoError(t, e.r.attach(e.snd.Session, &Attachment{ID: "att-sender"}))
				sh := newSession(e.snd.id, e.snd.remote)
				e.r.addSession(sh, t0)
				require.NoError(t, e.r.registerLanes(sh, []uint32{2002}))
				_, _, err := e.r.joinShard(sh, "att-sender", 1)
				require.NoError(t, err)
				return sh, "192.0.2.1:2002"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{LaneSources: MaxLaneSources})
			e := env{r: r, snd: addSession(t, r, vpcA, "sender", snd, "fd00::1/128")}
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			require.NoError(t, r.registerLanes(e.snd.Session, []uint32{2001}))
			require.NoError(t, r.registerSPI(e.snd.Session, register(vpcA, "fd00::2", time.Minute, 1), t0))
			_, v := r.Forward(netip.MustParseAddrPort("192.0.2.1:2001"), 1, 100, t0)
			require.Equal(t, Pass, v)

			s, lane := tc.run(t, e)
			assert.NotContains(t, lanePorts(r, s), netip.MustParseAddrPort(lane).Port())
			r.mu.RLock()
			_, ok := r.bySource[netip.MustParseAddrPort(lane)]
			r.mu.RUnlock()
			assert.False(t, ok)
			_, v = r.Forward(netip.MustParseAddrPort(lane), 1, 100, t0)
			assert.Equal(t, DropUnknownSource, v)
		})
	}
}

// TestLaneTwin checks a new session of the agent socket that takes the lane
// ports of the older one, as after a reconnect.
func TestLaneTwin(t *testing.T) {
	const addr, lane = "192.0.2.1:1000", "192.0.2.1:2001"
	r := NewRouter(nil, Config{LaneSources: MaxLaneSources})
	old := addSession(t, r, vpcA, "sender", addr, "fd00::1/128")
	require.NoError(t, r.openSync(old.Session, dp.Mode_MODE_PSP, ref(vpcA)))
	rcv := addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerLanes(old.Session, []uint32{2001}))
	require.NoError(t, r.registerSPI(old.Session, registerLanes(vpcA, "fd00::2", []uint32{1}, []uint32{1}), t0))

	next := addSession(t, r, vpcA, "sender", addr)
	require.NoError(t, r.openSync(next.Session, dp.Mode_MODE_PSP, ref(vpcA)))
	require.NoError(t, r.registerLanes(next.Session, []uint32{2001}))
	owner := func() *Session {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.bySource[netip.MustParseAddrPort(lane)]
	}
	assert.Same(t, next.Session, owner())
	// The new session has no row for SPI 1, so Forward uses the row of the older one.
	dst, v := r.Forward(netip.MustParseAddrPort(lane), 1, 100, t0)
	assert.Equal(t, Pass, v)
	assert.Equal(t, rcv.addr.get(), dst)

	r.removeSession(next.Session)
	assert.Same(t, old.Session, owner(), "the older session gets the lane port back")
	_, v = r.Forward(netip.MustParseAddrPort(lane), 1, 100, t0)
	assert.Equal(t, Pass, v)
	r.removeSession(old.Session)
	assert.Nil(t, owner())
}

// TestXDPLanes checks that each SPI has one XDP row, at the port of its lane.
func TestXDPLanes(t *testing.T) {
	const (
		snd   = "192.0.2.1:1000"
		lane1 = "192.0.2.1:2001"
		lane2 = "192.0.2.1:2002"
		rcv   = "192.0.2.2:2000"
		moved = "198.51.100.1:3000"
	)
	type env struct {
		r   *Router
		f   *fakeXDP
		snd testSession
	}
	cases := []struct {
		name string
		run  func(t *testing.T, e env)
		want map[string]string
	}{
		{
			name: "register",
			run:  func(*testing.T, env) {},
			want: map[string]string{snd + "/1": rcv, lane1 + "/2": rcv, lane2 + "/3": rcv},
		},
		{
			name: "lane of an SPI changes",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.registerSPI(e.snd.Session, registerLanes(vpcA, "fd00::2", []uint32{2}, []uint32{2}), t0))
			},
			want: map[string]string{snd + "/1": rcv, lane2 + "/2": rcv, lane2 + "/3": rcv},
		},
		{
			name: "SPI with no lanes",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.registerSPI(e.snd.Session, register(vpcA, "fd00::2", time.Minute, 3), t0))
			},
			want: map[string]string{snd + "/1": rcv, lane1 + "/2": rcv, snd + "/3": rcv},
		},
		{
			name: "lane with no port",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.registerSPI(e.snd.Session, registerLanes(vpcA, "fd00::2", []uint32{4}, []uint32{5}), t0))
			},
			want: map[string]string{snd + "/1": rcv, lane1 + "/2": rcv, lane2 + "/3": rcv, snd + "/4": rcv},
		},
		{
			name: "one lane port",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.registerLanes(e.snd.Session, []uint32{2001}))
			},
			want: map[string]string{snd + "/1": rcv, lane1 + "/2": rcv, snd + "/3": rcv},
		},
		{
			name: "no lane ports",
			run: func(t *testing.T, e env) {
				require.NoError(t, e.r.registerLanes(e.snd.Session, nil))
			},
			want: map[string]string{snd + "/1": rcv, snd + "/2": rcv, snd + "/3": rcv},
		},
		{
			name: "sender migrates",
			run: func(_ *testing.T, e env) {
				e.snd.addr.set(moved)
				e.r.Sweep(t0)
			},
			want: map[string]string{
				snd + "/1": rcv, snd + "/2": rcv, snd + "/3": rcv,
				moved + "/1": rcv, moved + "/2": rcv, moved + "/3": rcv,
			},
		},
		{
			name: "sender closes",
			run:  func(_ *testing.T, e env) { e.r.removeSession(e.snd.Session) },
			want: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{LaneSources: MaxLaneSources})
			f := newFakeXDP()
			r.setXDP(f, t0)
			e := env{r: r, f: f, snd: addSession(t, r, vpcA, "sender", snd, "fd00::1/128")}
			addSession(t, r, vpcA, "receiver", rcv, "fd00::2/128")
			require.NoError(t, r.registerLanes(e.snd.Session, []uint32{2001, 2002}))
			require.NoError(t, r.registerSPI(e.snd.Session, registerLanes(vpcA, "fd00::2", []uint32{1, 2, 3}, []uint32{0, 1, 2}), t0))
			tc.run(t, e)
			flushXDP(r, t0)
			assert.Equal(t, tc.want, f.installed())
			checkForward(t, r, f, t0)
		})
	}
}

// TestLaneCounters checks that the counters of an XDP row at a lane port go to
// its SPI, and that Forward takes an SPI from each source of the sender.
func TestLaneCounters(t *testing.T) {
	r := NewRouter(nil, Config{LaneSources: MaxLaneSources})
	f := newFakeXDP()
	r.setXDP(f, t0)
	snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
	addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
	require.NoError(t, r.registerLanes(snd.Session, []uint32{2001}))
	require.NoError(t, r.registerSPI(snd.Session, registerLanes(vpcA, "fd00::2", []uint32{1}, []uint32{1}), t0))
	flushXDP(r, t0)
	k := key("192.0.2.1:2001", 1)
	require.Contains(t, f.rows, k)
	row := f.rows[k]
	row.c = xdpCounters{packets: 7, bytes: 700}
	f.rows[k] = row

	// The socket path also takes SPI 1 from the session address.
	_, v := r.Forward(netip.MustParseAddrPort("192.0.2.1:1000"), 1, 100, t0)
	require.Equal(t, Pass, v)
	st := r.SenderStats(snd.Session)
	require.Len(t, st.Lanes, 1)
	assert.Equal(t, uint64(8), st.Lanes[0].Packets)
	assert.Equal(t, uint64(800), st.Lanes[0].Bytes)
}

func TestRegisterSPILanes(t *testing.T) {
	cases := []struct {
		name  string
		spis  []uint32
		lanes []uint32
		code  rpc.Code
	}{
		{"no lanes", []uint32{1, 2}, nil, rpc.OK},
		{"a lane for each SPI", []uint32{1, 2}, []uint32{0, MaxLaneSources}, rpc.OK},
		{"fewer lanes than SPIs", []uint32{1, 2}, []uint32{1}, rpc.InvalidArgument},
		{"lane above the limit", []uint32{1}, []uint32{MaxLaneSources + 1}, rpc.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			snd := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128")
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			err := r.registerSPI(snd.Session, registerLanes(vpcA, "fd00::2", tc.spis, tc.lanes), t0)
			require.Equal(t, tc.code, codeOf(err), "error: %v", err)
			r.mu.RLock()
			defer r.mu.RUnlock()
			for i, spi := range tc.spis {
				w := snd.rows[spi]
				if tc.code != rpc.OK {
					assert.Nil(t, w, "SPI %d", spi)
					continue
				}
				want := 0
				if tc.lanes != nil {
					want = int(tc.lanes[i])
				}
				assert.Equal(t, want, w.lane, "SPI %d", spi)
			}
		})
	}
}
