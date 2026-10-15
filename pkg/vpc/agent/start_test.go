// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// closed reports whether ch is closed.
func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestStarts(t *testing.T) {
	const lo, hi = time.Second, 4 * time.Second
	type op int
	const (
		begin op = iota // want: a start begins.
		end             // err is the result of the start.
		icmp            // want: an ICMP error goes.
		sweep           // want: the address stays.
	)
	type step struct {
		at   time.Duration
		op   op
		err  error
		want bool
	}
	failed := errors.New("open failed")
	cases := []struct {
		name  string
		fill  int  // Other addresses before the steps.
		rx    bool // The packets come to the address: no ICMP error is for them.
		steps []step
	}{
		{name: "one start runs", steps: []step{
			{op: begin, want: true}, {op: begin}, {at: time.Millisecond, op: end}, {at: time.Millisecond, op: begin, want: true},
		}},
		{name: "failed start waits", steps: []step{
			{op: begin, want: true}, {op: end, err: failed},
			{at: lo - time.Nanosecond, op: begin}, {at: lo, op: begin, want: true}, {at: lo, op: end, err: failed},
			{at: 3*lo - time.Nanosecond, op: begin}, {at: 3 * lo, op: begin, want: true}, {at: 3 * lo, op: end},
			{at: 3 * lo, op: begin, want: true},
		}},
		{name: "wait to the limit", steps: []step{
			{op: begin, want: true}, {op: end, err: failed},
			{at: lo, op: begin, want: true}, {at: lo, op: end, err: failed},
			{at: 3 * lo, op: begin, want: true}, {at: 3 * lo, op: end, err: failed},
			{at: 7 * lo, op: begin, want: true}, {at: 7 * lo, op: end, err: failed},
			{at: 7*lo + hi - time.Nanosecond, op: begin}, {at: 7*lo + hi, op: begin, want: true},
		}},
		{name: "one ICMP error each interval", steps: []step{
			{op: begin, want: true}, {op: icmp, want: true}, {at: icmpInterval / 2, op: icmp},
			{at: icmpInterval / 2, op: begin}, {at: icmpInterval - time.Nanosecond, op: icmp},
			{at: icmpInterval, op: icmp, want: true}, {at: icmpInterval, op: icmp},
		}},
		{name: "no ICMP error for received packets", rx: true, steps: []step{
			{op: begin, want: true}, {at: icmpInterval, op: icmp},
		}},
		{name: "sweep after one wait more", steps: []step{
			{op: begin, want: true}, {op: end, err: failed},
			{at: 2 * lo, op: sweep, want: true}, {at: 2*lo + time.Nanosecond, op: sweep},
		}},
		{name: "sweep keeps a start that runs", steps: []step{
			{op: begin, want: true}, {at: time.Hour, op: sweep, want: true},
		}},
		{name: "address limit", fill: startEntries, steps: []step{{op: begin}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s starts
			start := time.Unix(1000, 0)
			ctx := context.Background()
			for i := range tc.fill {
				s.begin(ctx, startKey{addr: netip.AddrFrom16([16]byte{0xfd, 1, 14: byte(i >> 8), 15: byte(i)})}, nil, start)
			}
			key := startKey{addr: netip.MustParseAddr("fd00::1")}
			pkt := make([]byte, 100)
			if tc.rx {
				pkt = nil
			}
			var last attempt
			for i, st := range tc.steps {
				now := start.Add(st.at)
				switch st.op {
				case begin:
					at, ok := s.begin(ctx, key, pkt, now)
					assert.Equal(t, st.want, ok, "step %d: begin at %v", i, st.at)
					if ok {
						last = at
					}
				case end:
					s.end(key, last, st.err, now, lo, hi)
				case icmp:
					assert.Equal(t, st.want, s.icmp(key, now) != nil, "step %d: ICMP error at %v", i, st.at)
				case sweep:
					s.sweep(now)
					assert.Equal(t, st.want, s.addrs[key] != nil, "step %d: address after the sweep at %v", i, st.at)
				}
			}
		})
	}
}

// TestOnce checks that the opens for one key run once, and that other keys
// do not wait.
func TestOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var s starts
		k1, k2 := startKey{addr: netip.MustParseAddr("fd00::1")}, startKey{addr: netip.MustParseAddr("fd00::2")}
		release, want := make(chan struct{}), errors.New("dial failed")
		var runs atomic.Int32
		open := func() error {
			runs.Add(1)
			<-release
			return want
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Go(func() { errs[i] = s.once(t.Context(), k1, open) })
		}
		synctest.Wait()
		assert.Equal(t, int32(1), runs.Load())
		assert.NoError(t, s.once(t.Context(), k2, func() error { return nil }))
		close(release)
		wg.Wait()
		assert.Equal(t, int32(1), runs.Load())
		for _, err := range errs {
			assert.Equal(t, want, err)
		}
		assert.Empty(t, s.opening)
	})
}

// sendOnce sends msg once from src to dst:port and waits for the echo.
func sendOnce(s *stack.Stack, src, dst netip.Addr, port uint16, msg string) error {
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != msg {
		return errors.New("wrong echo")
	}
	return nil
}

// send sends msg once from src to dst:port.
func send(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, msg string) {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte(msg))
	require.NoError(t, err)
}

// unreachableIn returns the ICMPv6 destination unreachable errors that the
// netstack of ta got.
func unreachableIn(ta *testAgent) uint64 {
	return ta.stack.Stats().ICMP.V6.PacketsReceived.DstUnreachable.Value()
}

// burst sends n packets from src to dst:port at once, and returns the number
// of different echoes in 5 s.
func burst(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, n int) int {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	for i := range n {
		_, err := c.Write(fmt.Appendf(nil, "packet %d", i))
		require.NoError(t, err)
	}
	got := map[string]bool{}
	buf := make([]byte, 1500)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(got) < n {
		k, err := c.Read(buf)
		if err != nil {
			break
		}
		got[string(buf[:k])] = true
	}
	return len(got)
}

// steady sends a packet from src to dst:port each interval until stop, and
// returns the number of packets and of echoes, 2 s after stop.
func steady(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, interval time.Duration, stop <-chan struct{}) (sent, echoes int) {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	var got atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for loop := true; loop; {
		_, err := c.Write(fmt.Appendf(nil, "packet %d", sent))
		require.NoError(t, err)
		sent++
		select {
		case <-stop:
			loop = false
		case <-tick.C:
		}
	}
	require.Eventually(t, func() bool { return int(got.Load()) >= sent }, 2*time.Second, 10*time.Millisecond, "echoes: %d of %d", got.Load(), sent)
	_ = c.Close()
	<-done
	return sent, int(got.Load())
}

// routeTo returns the route of a to the peer with the address addr, from
// Routes, or no route.
func routeTo(a *Agent, addr netip.Addr) Route {
	for _, r := range a.Routes() {
		if r.Proto != "bfd" {
			continue
		}
		if pfx, err := netip.ParsePrefix(r.Dst); (err == nil && pfx.Contains(addr)) || r.Dst == addr.String() {
			return r
		}
	}
	return Route{}
}

// routeUp waits until the routes of a and b to each other are up.
func routeUp(t *testing.T, a, b *testAgent, ea, eb attachEvent) {
	t.Helper()
	require.Eventually(t, func() bool {
		return routeTo(a.a, eb.addr).State == "up" && routeTo(b.a, ea.addr).State == "up"
	}, 10*time.Second, time.Millisecond, "routes of the peer session after BFD Up")
}

// sourceTo returns the source address that the netstack selects for a new
// connection to dst.
func sourceTo(t *testing.T, s *stack.Stack, dst netip.Addr) netip.Addr {
	t.Helper()
	c, err := gonet.DialUDP(s, nil, fullAddr(dst, 9), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}

// TestPeerRoutes checks the route table of the agent: the packets with no up
// route to a peer go on the default route through the relay at once, and a
// route to a peer is up only between BFD Up and BFD Down.
func TestPeerRoutes(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "first packets go at once with no loss",
			run: func(t *testing.T) {
				w := newWorld(t)
				r := w.relay(t, "relay-1")
				a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
				ea, eb := a.attached(t), b.attached(t)
				echo(t, b.stack, eb.addr, 9000)
				const n = 160
				assert.Equal(t, n, burst(t, a.stack, ea.addr, eb.addr, 9000, n), "echoes of the first packets")
				routeUp(t, a, b, ea, eb)
				assert.Equal(t, 1, peerCount(a.a), "the packets started one peer session")
				assert.Zero(t, unreachableIn(a), "ICMP errors")
			},
		},
		{
			name: "failed open keeps the default route",
			run: func(t *testing.T) {
				// The waits of the two starts must last for the second ping.
				defer func(d time.Duration) { pspRetryMin = d }(pspRetryMin)
				pspRetryMin = 2 * time.Second
				w := newWorld(t)
				r := w.relay(t, "relay-1")
				a := w.agent(t, "a", r, agentOptions{refuseOpen: true})
				b := w.agent(t, "b", r, agentOptions{refuseOpen: true})
				ea, eb := a.attached(t), b.attached(t)
				echo(t, b.stack, eb.addr, 9000)
				ping(t, a.stack, ea.addr, eb.addr, 9000, "with no peer session")
				waits := func(ta *testAgent, dst netip.Addr) func() bool {
					key := startKey{ta.current().link, dst}
					return func() bool {
						ta.a.starts.mu.Lock()
						defer ta.a.starts.mu.Unlock()
						st := ta.a.starts.addrs[key]
						return st != nil && !st.running && st.until.After(time.Now())
					}
				}
				// The packets of a start b too. Its session to a closes after its start.
				aWaits, bWaits := waits(a, eb.addr), waits(b, ea.addr)
				require.Eventually(t, func() bool { return aWaits() && bWaits() && peerCount(a.a) == 0 },
					10*time.Second, 10*time.Millisecond, "the next starts wait")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "while the next start waits")
				assert.Zero(t, peerCount(a.a))
				assert.Zero(t, routeTo(a.a, eb.addr), "route to b")
				assert.Zero(t, unreachableIn(a), "ICMP errors")
			},
		},
		{
			name: "BFD Down through the relay removes the route at once",
			run: func(t *testing.T) {
				w := newWorld(t)
				r := w.relay(t, "relay-1")
				a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
				ea, eb := a.attached(t), b.attached(t)
				echo(t, b.stack, eb.addr, 9000)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				require.NoError(t, a.a.Connect(ctx, eb.addr))
				routeUp(t, a, b, ea, eb)
				pa, viaRelay := onlyPeer(t, a.a), rxCountOf(a.current().relay).packets

				// b changes to QUIC mode, so a BFD packet of a starts no new check in b.
				b.current().mode.Store(int32(dp.Mode_MODE_QUIC))
				b.a.pathsDown(b.current())
				// The detect time of BFD is 6 s, so only the AdminDown packet can do this.
				require.Eventually(t, func() bool { return routeTo(a.a, eb.addr).State == "down" }, 2*time.Second, time.Millisecond)
				assert.Greater(t, rxCountOf(a.current().relay).packets, viaRelay, "the Down packet came through the relay")
				before := rxCountOf(b.current().relay).packets
				require.NoError(t, sendOnce(a.stack, ea.addr, eb.addr, 9000, "on the default route"))
				assert.Greater(t, rxCountOf(b.current().relay).packets, before, "the packet went through the relay")
				assert.Same(t, pa, onlyPeer(t, a.a), "the peer session stays")
				assert.NoError(t, pa.qc.Context().Err())
				// b changes back to PSP mode, and the next try of a starts the check of b again.
				b.current().mode.Store(int32(dp.Mode_MODE_PSP))
				routeUp(t, a, b, ea, eb)
			},
		},
		{
			name: "peer path that drops large packets goes Down",
			run: func(t *testing.T) {
				w := newWorld(t)
				r := w.relay(t, "relay-1")
				conn := &lossyConn{}
				a, b := w.agent(t, "a", r, agentOptions{conn: conn}), w.agent(t, "b", r, agentOptions{})
				ea, eb := a.attached(t), b.attached(t)
				echo(t, b.stack, eb.addr, 9000)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				require.NoError(t, a.a.Connect(ctx, eb.addr))
				routeUp(t, a, b, ea, eb)

				// The path of a drops the PSP packets of the full size, but not the
				// path probes, so only the BFD check of the peer path can find it.
				conn.bigProbes.Store(true)
				conn.max.Store(int32(a.a.checkSize() - 1))
				const detect = bfdl.DefaultDetectMult * peerCheckTx
				require.Eventually(t, func() bool {
					return routeTo(a.a, eb.addr).State == "down" && routeTo(b.a, ea.addr).State == "down"
				}, detect+2*peerCheckTx, 10*time.Millisecond, "BFD stayed Up on a peer path that drops large packets")
				assert.Equal(t, dp.Mode_MODE_PSP, a.modeOf(ea.addr), "the relay session stays in PSP mode")
				ping(t, a.stack, ea.addr, eb.addr, 9000, "on the default route")
			},
		},
		{
			name: "mode change during an open loses no packet",
			run: func(t *testing.T) {
				w := newWorld(t)
				r := w.relay(t, "relay-1")
				conn := &lossyConn{}
				conn.limitProbes.Store(true)
				a, b := w.agent(t, "a", r, agentOptions{conn: conn}), w.agent(t, "b", r, agentOptions{})
				ea, eb := a.attached(t), b.attached(t)
				require.Equal(t, dp.Mode_MODE_QUIC, a.modeOf(ea.addr))
				echo(t, b.stack, eb.addr, 9000)
				stop := make(chan struct{})
				var sent, echoes int
				var wg sync.WaitGroup
				wg.Go(func() { sent, echoes = steady(t, a.stack, ea.addr, eb.addr, 9000, 10*time.Millisecond, stop) })
				var p *peer
				require.Eventually(t, func() bool {
					a.a.mu.Lock()
					defer a.a.mu.Unlock()
					for _, q := range a.a.peers {
						p = q
					}
					return p != nil
				}, 5*time.Second, time.Millisecond, "the first packet opens a peer session")
				// The probes pass now, so the session changes to PSP mode while the peer session opens.
				conn.limitProbes.Store(false)
				require.Eventually(t, func() bool { return a.modeOf(ea.addr) == dp.Mode_MODE_PSP }, 10*time.Second, 5*time.Millisecond)
				routeUp(t, a, b, ea, eb)
				time.AfterFunc(200*time.Millisecond, func() { close(stop) })
				wg.Wait()
				assert.Equal(t, sent, echoes, "echoes")
				assert.Same(t, p, onlyPeer(t, a.a), "the mode change kept the peer session")
				assert.NoError(t, p.qc.Context().Err())
			},
		},
		{
			name: "advertised network uses the next relay when the first is down",
			run: func(t *testing.T) {
				w, r1, r2 := meshRelays(t)
				own, src := netip.MustParsePrefix("fd98::/64"), netip.MustParseAddr("fd98::5")
				b := w.agent(t, "b", r2, agentOptions{})
				eb := b.attached(t)
				echo(t, b.stack, eb.addr, 9000)
				a, rcs := w.agentOn(t, "a", agentOptions{routes: []netip.Prefix{own}}, 2, r1, r2)
				require.Len(t, rcs, 2)
				a.netstack(t, a.binding(), src, false)
				metric := func(m uint32) *uint32 { return &m }
				defaults := func() []Route {
					return slices.DeleteFunc(a.a.Routes(), func(r Route) bool { return r.Dst != "default" })
				}
				assert.Equal(t, []Route{
					{Dst: "default", Via: rcs[0].name, Dev: rcs[0].name, Src: rcs[0].self.String(), Metric: metric(0)},
					{Dst: "default", Via: rcs[1].name, Dev: rcs[1].name, Src: rcs[1].self.String(), Metric: metric(1)},
				}, defaults())
				ping(t, a.stack, src, eb.addr, 9000, "from the network of a")

				r1.stopAccept()
				_ = rcs[0].qc.CloseWithError(0, "relay is down")
				require.Eventually(t, func() bool { return a.current() == rcs[1] }, 5*time.Second, 10*time.Millisecond)
				assert.Equal(t, []Route{
					{Dst: "default", Via: rcs[1].name, Dev: rcs[1].name, Src: rcs[1].self.String(), Metric: metric(1)},
				}, defaults())
				ping(t, a.stack, src, eb.addr, 9000, "on the next relay")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// bfdFrom returns a BFD packet of c with the state s.
func bfdFrom(t *testing.T, c *p2p.Check, s bfdl.State) []byte {
	var pkt bfdl.Packet
	require.NoError(t, bfdl.UnmarshalInto(&pkt, c.Packet()))
	pkt.State = s
	return bfdl.Marshal(&pkt)
}

// TestPeerCheck gives the BFD check of a peer session the packets of the
// peer, and checks that the route to the peer is up only from BFD Up to Down.
func TestPeerCheck(t *testing.T) {
	w := newWorld(t)
	a := w.stubAgent(t, "a")
	rc := a.primary()
	rc.mode.Store(int32(dp.Mode_MODE_PSP))
	rc.self = netip.MustParseAddr("fd00:a::1")
	p, _ := stubPeer(a, "b", true)
	require.NoError(t, a.admit(p, nil, signGrant(t, w.relayCA.relayCert(t, "relay-1"), "b", "fd00:b::/96"), 7, dp.Mode_MODE_PSP, 1))
	peerBFD := p2p.NewCheck(p2p.RoleAgent, peerCheckTx)
	t.Cleanup(peerBFD.Close)
	dst := netip.MustParseAddr("fd00:b::1")
	from := func(s bfdl.State) func() { return func() { a.takeBFD(p, bfdFrom(t, peerBFD, s)) } }
	runs := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return p.check != nil && !p.check.ended()
	}
	steps := []struct {
		name    string
		do      func()
		want    string // State of the route to the peer.
		stays   bool   // The route keeps the state for a time.
		settled bool
		idle    bool // No try of the check runs, so this agent sends no BFD packet.
	}{
		{name: "open", do: func() {}, want: "down", stays: true},
		{name: "peer is Down", do: from(bfdl.StateDown), want: "down", stays: true},
		{name: "peer is Init", do: from(bfdl.StateInit), want: "up", settled: true},
		{name: "peer is Up", do: from(bfdl.StateUp), want: "up", stays: true, settled: true},
		{name: "peer says Down", do: from(bfdl.StateDown), want: "down", settled: true},
		{name: "packet of the peer starts the next try at once", do: from(bfdl.StateInit), want: "up", settled: true},
		{name: "peer says AdminDown", do: from(bfdl.StateAdminDown), want: "down", settled: true, idle: true},
		{name: "AdminDown with no try starts none", do: from(bfdl.StateAdminDown), want: "down", stays: true, settled: true, idle: true},
		{name: "next packet of the peer starts a try at once", do: from(bfdl.StateInit), want: "up", settled: true},
		{name: "this agent changes to QUIC mode", do: func() {
			rc.mode.Store(int32(dp.Mode_MODE_QUIC))
			a.pathsDown(rc)
		}, want: "down", settled: true},
		{name: "packet of the peer in QUIC mode", do: from(bfdl.StateInit), want: "down", stays: true, settled: true},
	}
	for _, st := range steps {
		st.do()
		require.Eventually(t, func() bool { return routeTo(a, dst).State == st.want }, 2*time.Second, time.Millisecond, st.name)
		if st.stays {
			require.Never(t, func() bool { return routeTo(a, dst).State != st.want }, 100*time.Millisecond, 5*time.Millisecond, st.name)
		}
		assert.Equal(t, st.settled, closed(p.settled), "%s: settled", st.name)
		if st.idle {
			assert.False(t, runs(), "%s: a try runs", st.name)
		}
	}
	assert.Nil(t, a.tryCheck(p), "no check in QUIC mode")
}

// TestBackupAddress checks that the address of a relay session that is not the
// primary is deprecated while the primary is up, and not after it goes.
func TestBackupAddress(t *testing.T) {
	w := newWorld(t)
	r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
	a, rcs := w.agentOn(t, "a", agentOptions{}, 2, r1, r2)
	require.Len(t, rcs, 2)
	primary, backup := rcs[0].self, rcs[1].self
	dst := netip.MustParseAddr("fd61:706f:7879:12:3400:99::1")
	require.Eventually(t, func() bool { return slices.Contains(a.events("a"), "deprecate a "+backup.String()) },
		5*time.Second, 10*time.Millisecond, "the backup address is deprecated")
	assert.NotContains(t, a.events("a"), "deprecate a "+primary.String())
	assert.Equal(t, primary, sourceTo(t, a.stack, dst), "source of a new connection")

	r1.stopAccept()
	_ = rcs[0].qc.CloseWithError(0, "relay is down")
	require.Eventually(t, func() bool { return slices.Contains(a.events("a"), "prefer a "+backup.String()) },
		5*time.Second, 10*time.Millisecond, "the backup address is preferred again")
	assert.Equal(t, backup, sourceTo(t, a.stack, dst), "source of a new connection")
}

// TestFirstPacket checks that the first packets to an address of a peer and
// to a route of the peer open one peer session, and that they arrive.
func TestFirstPacket(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode
	}{{"PSP", TransportAuto}, {"QUIC", TransportQUIC}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
			a := w.agent(t, "a", r, agentOptions{mode: tc.mode})
			b := w.agent(t, "b", r, agentOptions{mode: tc.mode, routes: []netip.Prefix{route}})
			ea, eb := a.attached(t), b.attached(t)
			b.netstack(t, b.binding(), far, false)
			echo(t, b.stack, eb.addr, 9000)
			echo(t, b.stack, far, 9001)
			require.Eventually(t, func() bool { return slices.Contains(a.routeSet(), route) },
				5*time.Second, 10*time.Millisecond)

			var wg sync.WaitGroup
			var errB, errFar error
			wg.Go(func() { errB = sendOnce(a.stack, ea.addr, eb.addr, 9000, "to b") })
			wg.Go(func() { errFar = sendOnce(a.stack, ea.addr, far, 9001, "to a route of b") })
			wg.Wait()
			require.NoError(t, errB)
			require.NoError(t, errFar)
			require.Eventually(t, func() bool { return peerCount(a.a) == 1 }, 5*time.Second, 10*time.Millisecond, "one peer session")
		})
	}
}

// TestNoPeer checks that packets to a destination with no peer session get an
// ICMP error after the NoRoute of the relay: code 3 is no route, code 1
// permission denied.
func TestNoPeer(t *testing.T) {
	absent := func(attachEvent) netip.Addr { return netip.MustParseAddr("fd61:706f:7879:12:3400:99::1") }
	peer := func(eb attachEvent) netip.Addr { return eb.addr }
	cases := []struct {
		name    string
		dst     func(eb attachEvent) netip.Addr
		deny    bool   // The relay denies the destination.
		dialErr string // Not empty: a TCP dial in place of a UDP packet fails with this error.
		// vpcStack uses the netstack of vpc connect, which must let the ICMPv6 error in.
		vpcStack bool
	}{
		{name: "not found", dst: absent},
		{name: "TCP dial to an absent peer", dst: absent, dialErr: (&tcpip.ErrHostUnreachable{}).String()},
		{name: "outside the VPC", dst: func(attachEvent) netip.Addr { return netip.MustParseAddr("fd97::1") }},
		{name: "denied", dst: peer, deny: true},
		{name: "TCP dial denied", dst: peer, deny: true, dialErr: (&tcpip.ErrPermissionDenied{}).String()},
		{name: "TCP dial denied, vpc connect stack", dst: peer, deny: true, vpcStack: true, dialErr: (&tcpip.ErrPermissionDenied{}).String()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a, b := w.agent(t, "a", r, agentOptions{tcp: tc.dialErr != "", vpcStack: tc.vpcStack}), w.agent(t, "b", r, agentOptions{})
			ea, eb := a.attached(t), b.attached(t)
			if tc.deny {
				// A rule that denies each address also removes the row of a to the
				// relay, which has no address, so the rule denies only dst.
				dst := tc.dst(eb)
				r.r.SetPermit(func(_ relay.VPCKey, _ string, _ relay.VPCKey, a netip.Addr) bool { return a != dst })
			}
			if tc.dialErr != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				start := time.Now()
				_, err := gonet.DialContextTCP(ctx, a.stack, *fullAddr(tc.dst(eb), 9000), ipv6.ProtocolNumber)
				require.ErrorContains(t, err, tc.dialErr)
				assert.Less(t, time.Since(start), time.Second, "the dial stops at the ICMP error")
			} else {
				send(t, a.stack, ea.addr, tc.dst(eb), 9000, "no peer")
			}
			require.Eventually(t, func() bool { return unreachableIn(a) == 1 }, 5*time.Second, 10*time.Millisecond)
			assert.Zero(t, peerCount(a.a))
		})
	}
}

// TestLateRoutes checks that a route that comes after the peer session opens
// gets packets, and that its remove stops them.
func TestLateRoutes(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
	ea, eb := a.attached(t), b.attached(t)
	late := netip.MustParseAddr("fd98::5")
	b.netstack(t, b.binding(), late, false)
	echo(t, b.stack, late, 9000)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.a.Connect(ctx, eb.addr))

	a.a.mu.Lock()
	rc := a.a.primaryLocked()
	a.a.mu.Unlock()
	a.a.routeMu.Lock()
	id := rc.routes.origins[eb.prefixes[0]]
	a.a.routeMu.Unlock()
	require.NotEmpty(t, id)
	routes := []*dp.Route{
		{Prefix: "fd98::/64", Origin: id},
		{Prefix: "::/0", Origin: id},
		{Prefix: "fd61:706f:7879:12:3400:99::/96", Origin: id},
	}
	a.a.applyRoutes(rc, &dp.RouteDelta{Add: routes})
	ping(t, a.stack, ea.addr, late, 9000, "late route")
	a.a.mu.Lock()
	for _, p := range a.a.peers {
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("fd98::/64")}, p.advertised)
	}
	a.a.mu.Unlock()

	a.a.applyRoutes(rc, &dp.RouteDelta{Remove: routes[:1]})
	send(t, a.stack, ea.addr, late, 9000, "removed route")
	require.Eventually(t, func() bool { return unreachableIn(a) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, peerCount(a.a))
}
