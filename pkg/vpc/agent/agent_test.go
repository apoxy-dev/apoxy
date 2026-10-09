// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func fullAddr(a netip.Addr, port uint16) *tcpip.FullAddress {
	return &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}
}

// echo answers each UDP packet to addr:port with the same bytes.
func echo(t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(addr, port), nil, netProto(addr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(buf[:n], from)
		}
	}()
}

// ping sends msg from src to dst:port and waits for the echo, with retries.
func ping(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16, msg string) {
	t.Helper()
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer c.Close()
	buf := make([]byte, 1500)
	for range 10 {
		_, err := c.Write([]byte(msg))
		require.NoError(t, err)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err == nil {
			assert.Equal(t, msg, string(buf[:n]))
			return
		}
	}
	t.Fatalf("no answer from %s", dst)
}

func peerCount(a *Agent) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.peers)
}

// TestConnect sends UDP both ways in PSP after Connect.
func TestConnect(t *testing.T) {
	cases := []struct {
		name string
		both bool // Both agents dial at the same time.
	}{
		{name: "one agent dials"},
		{name: "both agents dial", both: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			// New agents each round. With both, some rounds have crossed dials.
			for round := range 5 {
				a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
				ea, eb := a.attached(t), b.attached(t)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				var errA, errB error
				if tc.both {
					var wg sync.WaitGroup
					wg.Go(func() { errA = a.a.Connect(ctx, eb.addr) })
					wg.Go(func() { errB = b.a.Connect(ctx, ea.addr) })
					wg.Wait()
				} else {
					errA = a.a.Connect(ctx, eb.addr)
					errB = b.a.Connect(ctx, ea.addr)
				}
				require.NoError(t, errA, "round %d", round)
				require.NoError(t, errB, "round %d", round)
				echo(t, b.stack, eb.addr, 9000)
				echo(t, a.stack, ea.addr, 9001)
				ping(t, a.stack, ea.addr, eb.addr, 9000, "from a")
				ping(t, b.stack, eb.addr, ea.addr, 9001, "from b")
				require.Eventually(t, func() bool { return peerCount(a.a) == 1 && peerCount(b.a) == 1 },
					5*time.Second, 10*time.Millisecond, "one session stays")

				// When b leaves, a closes its peer session.
				b.stop()
				require.Eventually(t, func() bool { return peerCount(a.a) == 0 }, 5*time.Second, 10*time.Millisecond)
				// The relay can remove the session of b after that. Until it does, a dial
				// to b waits 5 s.
				require.Eventually(t, func() bool {
					_, err := a.current().resolve(ctx, eb.addr)
					return err != nil
				}, 5*time.Second, 10*time.Millisecond)
				assert.Error(t, a.a.Connect(ctx, eb.addr))
				a.stop()
			}
		})
	}
}

// TestSharedIdentity runs agents a1 and a2 with one cert name and their own
// attachment names. Agent c, a1 and a2 keep a peer session for each agent.
func TestSharedIdentity(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode // Mode of a2.
	}{
		{name: "PSP"},
		{name: "one agent in QUIC mode", mode: TransportQUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a1 := w.agent(t, "a1", r, agentOptions{identity: "shared"})
			a2 := w.agent(t, "a2", r, agentOptions{identity: "shared", mode: tc.mode})
			c := w.agent(t, "c", r, agentOptions{})
			e1, e2, ec := a1.attached(t), a2.attached(t), c.attached(t)
			echo(t, a1.stack, e1.addr, 9001)
			echo(t, a2.stack, e2.addr, 9002)
			echo(t, c.stack, ec.addr, 9000)

			// a1 dials c, then a2 dials c. The session of a2 does not replace
			// the session of a1.
			ping(t, a1.stack, e1.addr, ec.addr, 9000, "a1 to c")
			p1 := onlyPeer(t, a1.a)
			ping(t, a2.stack, e2.addr, ec.addr, 9000, "a2 to c")
			for range 2 {
				ping(t, c.stack, ec.addr, e1.addr, 9001, "c to a1")
				ping(t, c.stack, ec.addr, e2.addr, 9002, "c to a2")
			}
			assert.Equal(t, 2, c.a.Status().Peers, "c has a peer session for each agent")
			assert.Same(t, p1, onlyPeer(t, a1.a), "a1 keeps its peer session")
			assert.NoError(t, p1.qc.Context().Err(), "the peer session of a1 is open")

			// d dials a1, then a2. The address of a2 is not a second attachment
			// of a1, so d does not wait for a grant from a1.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			d := w.agent(t, "d", r, agentOptions{})
			d.attached(t)
			require.NoError(t, d.a.Connect(ctx, e1.addr))
			start := time.Now()
			require.NoError(t, d.a.Connect(ctx, e2.addr))
			assert.Less(t, time.Since(start), duplicateWait/2, "first connect to a second agent of the subject")
			assert.Equal(t, 2, d.a.Status().Peers, "d has a peer session for each agent")

			// Each agent of the subject gets the address route of the other.
			require.Eventually(t, func() bool {
				return slices.Contains(a1.routeSet(), e2.prefixes[0]) && slices.Contains(a2.routeSet(), e1.prefixes[0])
			}, 5*time.Second, 10*time.Millisecond, "a1 and a2 get the address route of each other")

			// a1 and a2 dial each other at the same time.
			n1, n2 := peerCount(a1.a), peerCount(a2.a)
			var err1, err2 error
			var wg sync.WaitGroup
			wg.Go(func() { err1 = a1.a.Connect(ctx, e2.addr) })
			wg.Go(func() { err2 = a2.a.Connect(ctx, e1.addr) })
			wg.Wait()
			require.NoError(t, err1)
			require.NoError(t, err2)
			ping(t, a1.stack, e1.addr, e2.addr, 9002, "a1 to a2")
			ping(t, a2.stack, e2.addr, e1.addr, 9001, "a2 to a1")
			if tc.mode == TransportQUIC {
				// A QUIC pair keeps the two sessions of crossed dials.
				return
			}
			require.Eventually(t, func() bool { return peerCount(a1.a) == n1+1 && peerCount(a2.a) == n2+1 },
				5*time.Second, 10*time.Millisecond, "one session between a1 and a2 stays")
		})
	}
}

// TestTransportModes sends UDP both ways between agents where one or both
// send QUIC data frames. The relay bridges a PSP agent and a QUIC agent.
func TestTransportModes(t *testing.T) {
	inPSP := Status{Mode: dp.Mode_MODE_PSP}
	quicConfig := Status{Mode: dp.Mode_MODE_QUIC, Reason: dp.FallbackReason_FALLBACK_REASON_CONFIG}
	quicTimeout := Status{Mode: dp.Mode_MODE_QUIC, Reason: dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT}
	cases := []struct {
		name         string
		a, b         TransportMode
		noProbes     bool // The PSP probes of a get no reply.
		wantA, wantB Status
	}{
		{name: "PSP to QUIC", a: TransportPSP, b: TransportQUIC, wantA: inPSP, wantB: quicConfig},
		{name: "QUIC to PSP", a: TransportQUIC, b: TransportPSP, wantA: quicConfig, wantB: inPSP},
		{name: "QUIC to QUIC", a: TransportQUIC, b: TransportQUIC, wantA: quicConfig, wantB: quicConfig},
		{name: "auto to QUIC", b: TransportQUIC, wantA: inPSP, wantB: quicConfig},
		{name: "auto with no PSP path to auto", noProbes: true, wantA: quicTimeout, wantB: inPSP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			optsA := agentOptions{mode: tc.a}
			if tc.noProbes {
				optsA.conn = &lossyConn{}
				optsA.conn.limitProbes.Store(true)
			}
			a, b := w.agent(t, "a", r, optsA), w.agent(t, "b", r, agentOptions{mode: tc.b})
			ea, eb := a.attached(t), b.attached(t)
			for _, x := range []struct {
				ta   *testAgent
				want Status
			}{{a, tc.wantA}, {b, tc.wantB}} {
				st := x.ta.a.Status()
				assert.Equal(t, x.want.Mode, st.Mode)
				assert.Equal(t, x.want.Reason, st.Reason)
				assert.Positive(t, st.Connect)
				assert.Less(t, st.Connect, openTimeout)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			require.NoError(t, b.a.Connect(ctx, ea.addr))
			echo(t, b.stack, eb.addr, 9000)
			echo(t, a.stack, ea.addr, 9001)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "from a")
			ping(t, b.stack, eb.addr, ea.addr, 9001, "from b")
			assert.Equal(t, 1, peerCount(a.a))
			assert.Equal(t, 1, peerCount(b.a))

			// When b leaves, a closes its peer session.
			b.stop()
			require.Eventually(t, func() bool { return peerCount(a.a) == 0 }, 5*time.Second, 10*time.Millisecond)
		})
	}
}

// TestDualStackSocket sends UDP both ways when one agent has a dual-stack
// socket and the relay is on IPv4.
func TestDualStackSocket(t *testing.T) {
	cases := []struct {
		name string
		mode TransportMode
		want dp.Mode
	}{
		{name: "PSP", mode: TransportPSP, want: dp.Mode_MODE_PSP},
		{name: "QUIC", mode: TransportQUIC, want: dp.Mode_MODE_QUIC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
			if err != nil {
				t.Skipf("no dual-stack socket: %v", err)
			}
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a, b := w.agent(t, "a", r, agentOptions{mode: tc.mode, udp: udp}), w.agent(t, "b", r, agentOptions{mode: TransportPSP})
			ea, eb := a.attached(t), b.attached(t)
			assert.Equal(t, tc.want, a.a.Status().Mode)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			require.NoError(t, b.a.Connect(ctx, ea.addr))
			echo(t, b.stack, eb.addr, 9000)
			echo(t, a.stack, ea.addr, 9001)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "from a")
			ping(t, b.stack, eb.addr, ea.addr, 9001, "from b")
			assert.Zero(t, a.binding().Stats().TxDrops)
		})
	}
}

// TestStatusRTT checks that Status gives the RTT of the attached relay
// session, and no RTT after that session ends.
func TestStatusRTT(t *testing.T) {
	cases := []struct {
		name   string
		attach bool
		mode   TransportMode
		end    bool // The relay session ends and the relay takes no new one.
	}{
		{name: "no session"},
		{name: "PSP session", attach: true, mode: TransportPSP},
		{name: "QUIC session", attach: true, mode: TransportQUIC},
		{name: "ended session", attach: true, mode: TransportQUIC, end: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.attach {
				assert.Zero(t, New(Config{}).Status().RTT)
				return
			}
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{mode: tc.mode})
			a.attached(t)
			require.Eventually(t, func() bool { return a.a.Status().RTT > 0 }, 5*time.Second, 10*time.Millisecond)
			assert.Less(t, a.a.Status().RTT, openTimeout)
			if !tc.end {
				return
			}
			r.stopAccept()
			_ = a.a.current().qc.CloseWithError(0, "test ends the session")
			require.Eventually(t, func() bool { return a.a.Status().RTT == 0 }, 5*time.Second, 10*time.Millisecond)
		})
	}
}

// TestPSPRetry checks that an agent in QUIC mode after a failed probe moves
// back to PSP only after two probes in a row pass.
func TestPSPRetry(t *testing.T) {
	oldMin, oldMax, oldNext := pspRetryMin, pspRetryMax, pspRetryNext
	pspRetryMin, pspRetryMax, pspRetryNext = 100*time.Millisecond, 400*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { pspRetryMin, pspRetryMax, pspRetryNext = oldMin, oldMax, oldNext })
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	conn := &lossyConn{}
	conn.limitProbes.Store(true)
	a := w.agent(t, "a", r, agentOptions{conn: conn})
	a.attached(t)
	st := a.a.Status()
	assert.Equal(t, dp.Mode_MODE_QUIC, st.Mode)
	assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT, st.Reason)

	// Two retry probes pass, then the probe of the new session gets no reply.
	// One pass would open the new session before the budget ends.
	sent := conn.probes.Load()
	conn.probeBudget.Store(2)
	// Each failed probe sends 3 probes. The probe after them is the next retry.
	require.Eventually(t, func() bool { return conn.probes.Load() >= sent+2+3+1 }, 10*time.Second, 5*time.Millisecond)
	select {
	case <-a.attach:
		t.Fatal("agent moved to PSP after one probe passed")
	default:
	}
	assert.Equal(t, dp.Mode_MODE_QUIC, a.a.Status().Mode)

	conn.limitProbes.Store(false)
	a.attached(t)
	st = a.a.Status()
	assert.Equal(t, dp.Mode_MODE_PSP, st.Mode)
	assert.Equal(t, dp.FallbackReason_FALLBACK_REASON_UNSPECIFIED, st.Reason)
}

// TestPSPAfterQUIC sends UDP in a PSP session that follows a QUIC session.
// The shards of the QUIC session must not dial again while the PSP session opens.
func TestPSPAfterQUIC(t *testing.T) {
	w := newWorld(t)
	w.mtu = 1372
	r := w.relay(t, "relay-1")
	conn := &lossyConn{}
	conn.limitProbes.Store(true)
	a, b := w.agent(t, "a", r, agentOptions{conn: conn}), w.agent(t, "b", r, agentOptions{})
	a.attached(t)
	require.Equal(t, dp.Mode_MODE_QUIC, a.a.Status().Mode)
	shards := func() bool {
		a.a.mu.Lock()
		defer a.a.mu.Unlock()
		return a.a.rc.pc.Shards() == quicShards
	}
	require.Eventually(t, shards, 10*time.Second, 10*time.Millisecond)

	// The path probe of the PSP session fails, so the open takes more than 1 s.
	conn.limitProbes.Store(false)
	conn.max.Store(1400)
	a.reconnect()
	ea, eb := a.attached(t), b.attached(t)
	require.Equal(t, dp.Mode_MODE_PSP, a.a.Status().Mode)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.a.Connect(ctx, eb.addr))
	echo(t, b.stack, eb.addr, 9000)
	echo(t, a.stack, ea.addr, 9001)
	ping(t, a.stack, ea.addr, eb.addr, 9000, "from a")
	ping(t, b.stack, eb.addr, ea.addr, 9001, "from b")
}

// stream sends from src to dst:port until stop or the cleanup runs. stop logs
// the echoes and the longest time with no echo.
func stream(t *testing.T, s *stack.Stack, src, dst netip.Addr, port uint16) (stop func()) {
	c, err := gonet.DialUDP(s, fullAddr(src, 0), fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	done := make(chan struct{})
	var sent, got int
	var longest time.Duration
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 64)
		last := time.Now()
		defer func() { longest = max(longest, time.Since(last)) }()
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := c.Write([]byte("stream")); err == nil {
				sent++
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			if _, err := c.Read(buf); err == nil {
				got++
				longest, last = max(longest, time.Since(last)), time.Now()
			}
		}
	})
	stop = sync.OnceFunc(func() {
		close(done)
		wg.Wait()
		_ = c.Close()
		t.Logf("Data to %s: %d sent, %d echoes, longest time with no echo %v", dst, sent, got, longest)
	})
	t.Cleanup(stop)
	return stop
}

// TestRenew checks that the agent opens a session with the renewed cert before
// it closes the old one, and that the route moves with no remove at peers. An
// agent with an identity file does the same when the file has a new cert, and
// it does not enroll.
func TestRenew(t *testing.T) {
	cases := []struct {
		name  string
		spare bool // The agent keeps a spare on a second relay.
		route bool // The agent advertises a route, and agent b sends to it.
		file  bool // The agent has an identity file. The test replaces the file.
	}{
		{name: "one relay"},
		{name: "spare on a second relay", spare: true},
		{name: "one relay with a route", route: true},
		{name: "identity file", file: true},
		{name: "identity file, spare on a second relay", file: true, spare: true},
		{name: "identity file, one relay with a route", file: true, route: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			opts := agentOptions{life: 3 * time.Second}
			if tc.file {
				opts = agentOptions{identityFile: true}
			}
			if tc.spare {
				opts.relays = []identity.Relay{r.ref(), w.relay(t, "relay-2").ref()}
			}
			route, far := netip.MustParsePrefix("fd99::/64"), netip.MustParseAddr("fd99::5")
			if tc.route {
				opts.routes = []netip.Prefix{route}
			}
			a := w.agent(t, "a", r, opts)
			first := a.attached(t)
			var b *testAgent
			var stop func()
			if tc.route {
				b = w.agent(t, "b", r, agentOptions{})
				eb := b.attached(t)
				a.netstack(t, a.binding(), far, false)
				echo(t, a.stack, far, 9000)
				require.Eventually(t, func() bool { return slices.Contains(b.routeSet(), route) },
					5*time.Second, 10*time.Millisecond)
				stop = stream(t, b.stack, eb.addr, far, 9000)
			}
			old := a.current().cred
			if tc.file {
				if tc.spare {
					require.Eventually(t, func() bool { return a.spare() != nil }, 10*time.Second, 10*time.Millisecond)
				}
				// The new cert must expire later than the cert in use.
				a.writeIdentity(25 * time.Hour)
			}
			second := a.attached(t)
			assert.NotEqual(t, first.addr, second.addr, "each relay session has its own addresses")
			assert.NotSame(t, old, a.current().cred, "the new session has the new cert")
			if tc.file {
				assert.Zero(t, a.enrolls.Load(), "an agent with an identity file does not enroll")
			} else {
				assert.GreaterOrEqual(t, a.enrolls.Load(), int32(2))
			}
			id := identity.ID{Project: testProject, VPC: testVPC, Agent: "a"}.String()
			if tc.route {
				require.Eventually(t, func() bool { return w.addrs.LiveOf(id) == 1 },
					5*time.Second, 10*time.Millisecond, "the old session closes")
				stop()
				assert.Equal(t, []string{"+" + route.String()}, b.routeEvents(route), "b keeps the route")
				assert.Empty(t, a.routeEvents(route), "a never gets its own route")
			}
			assert.Equal(t, 2, w.addrs.Overlap(id), "the new session attaches before the old one closes")
			if tc.spare {
				require.Eventually(t, func() bool {
					s := a.spare()
					return s != nil && s.cred == a.a.cfg.Identity.Current()
				}, 10*time.Second, 10*time.Millisecond, "the spare gets the new cert")
			}
		})
	}
}

// TestSharedIdentityFile runs two agents with one identity file: one cert and
// one key, and a name for each agent. A new file moves the two agents.
func TestSharedIdentityFile(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	opts := agentOptions{identity: "shared", identityFile: true, identityPath: filepath.Join(t.TempDir(), "identity.json")}
	a1 := w.agent(t, "a1", r, opts)
	a2 := w.agent(t, "a2", r, opts)
	c := w.agent(t, "c", r, agentOptions{})
	ec := c.attached(t)
	echo(t, c.stack, ec.addr, 9000)

	// traffic waits for the next attach of a1 and a2, and sends data between
	// each two of the three agents.
	traffic := func() {
		t.Helper()
		e1, e2 := a1.attached(t), a2.attached(t)
		echo(t, a1.stack, e1.addr, 9001)
		echo(t, a2.stack, e2.addr, 9002)
		ping(t, a1.stack, e1.addr, e2.addr, 9002, "a1 to a2")
		ping(t, a2.stack, e2.addr, e1.addr, 9001, "a2 to a1")
		ping(t, a1.stack, e1.addr, ec.addr, 9000, "a1 to c")
		ping(t, a2.stack, e2.addr, ec.addr, 9000, "a2 to c")
		ping(t, c.stack, ec.addr, e1.addr, 9001, "c to a1")
		ping(t, c.stack, ec.addr, e2.addr, 9002, "c to a2")
	}
	traffic()
	first := a1.current().cred.Cert
	require.True(t, first.Equal(a2.current().cred.Cert), "a1 and a2 have one cert")

	a1.writeIdentity(25 * time.Hour)
	traffic()
	second := a1.current().cred.Cert
	assert.False(t, first.Equal(second), "a1 has the cert of the new file")
	assert.True(t, second.Equal(a2.current().cred.Cert), "a2 has the cert of the new file")
	assert.Zero(t, a1.enrolls.Load()+a2.enrolls.Load(), "an agent with an identity file does not enroll")
}

// TestIdentityFileExpires checks that an agent with an identity file stops
// with an error when the cert of the file expires and the file has no new cert.
func TestIdentityFileExpires(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	runErr := make(chan error, 1)
	a := w.agent(t, "a", r, agentOptions{identityFile: true, life: 2 * time.Second, runErr: runErr})
	a.attached(t)
	want := a.a.cfg.Identity.Current().Cert.NotAfter
	select {
	case err := <-runErr:
		var expired *identity.ExpiredError
		require.ErrorAs(t, err, &expired)
		assert.True(t, expired.At.Equal(want), "the error has the expiry time of the cert")
		assert.False(t, time.Now().Before(want), "Run stops at the expiry time, not before it")
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop after the cert of the identity file expired")
	}
	assert.Zero(t, a.enrolls.Load(), "an agent with an identity file does not enroll")
}

// closeOf waits for the end of the session rc and returns its close.
func closeOf(t *testing.T, rc *relayConn) *quic.ApplicationError {
	t.Helper()
	select {
	case <-rc.qc.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the session did not end in 10 s")
	}
	var ae *quic.ApplicationError
	require.ErrorAs(t, context.Cause(rc.qc.Context()), &ae)
	return ae
}

// closedByAgent checks that the agent closed the session rc, and that the
// relay did not close it.
func closedByAgent(t *testing.T, rc *relayConn) {
	t.Helper()
	ae := closeOf(t, rc)
	assert.False(t, ae.Remote, "the relay closed the old session: %v", ae)
}

// TestDrain checks that the agent moves to an alternate relay before the
// draining relay closes its session.
func TestDrain(t *testing.T) {
	cases := []struct {
		name  string
		spare bool // The agent knows both relays, so it has a spare on the alternate.
		one   bool // The agent knows both relays and has one session, so no spare.
		// first comes before the alternate that takes the agent: "drains" (a relay
		// that drains too), "no address", or "wrong address" (of another relay).
		first string
	}{
		{name: "new session on the alternate"},
		{name: "spare on the alternate", spare: true},
		{name: "one session", one: true},
		{name: "first alternate drains too", first: "drains"},
		{name: "first alternate has no address", first: "no address"},
		{name: "first address of the alternate is of another relay", first: "wrong address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1, r2, r3 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3")
			opts := agentOptions{}
			if tc.spare || tc.one {
				opts.relays = []identity.Relay{r1.ref(), r2.ref()}
			}
			if tc.one {
				opts.sessions = 1
			}
			a := w.agent(t, "a", r1, opts)
			a.attached(t)
			from, to := r1, r2
			if a.current().addr == r2.addr {
				from, to = r2, r1
			}
			var spare *relayConn
			if tc.spare {
				require.Eventually(t, func() bool { return a.spare() != nil }, 10*time.Second, 10*time.Millisecond)
				spare = a.spare()
			}
			good := &dp.RelayRef{Id: to.id, Addresses: []string{to.addr}}
			alts := []*dp.RelayRef{good}
			switch tc.first {
			case "drains":
				// A relay that drains refuses a new session at once.
				r3.srv.Drain(context.Background(), nil)
				alts = []*dp.RelayRef{{Id: r3.id, Addresses: []string{r3.addr}}, good}
			case "no address":
				alts = []*dp.RelayRef{{Id: r3.id}, good}
			case "wrong address":
				alts = []*dp.RelayRef{{Id: to.id, Addresses: []string{r3.addr, to.addr}}}
			}
			prev := a.current()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				from.srv.Drain(ctx, alts)
			}()
			a.attached(t)
			assert.Equal(t, to.addr, a.current().addr)
			if tc.spare {
				assert.Same(t, spare, a.current(), "the spare takes the attachment")
			} else {
				assert.Nil(t, a.spare(), "the agent has no spare")
			}
			select {
			case <-done:
				assert.NoError(t, ctx.Err(), "the agent closed its session before the drain time ended")
			case <-time.After(10 * time.Second):
				t.Fatal("drain did not end")
			}
			closedByAgent(t, prev)
			id := identity.ID{Project: testProject, VPC: testVPC, Agent: "a"}.String()
			assert.Equal(t, 2, w.addrs.Overlap(id), "the new session attaches before the old one closes")
		})
	}
}

// TestDrainNoAlternate drains the relay of an agent that gets no alternate and
// has no spare. The agent keeps its session until the relay closes it.
func TestDrainNoAlternate(t *testing.T) {
	w := newWorld(t)
	r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
	a := w.agent(t, "a", r1, agentOptions{relays: []identity.Relay{r1.ref(), r2.ref()}, sessions: 1})
	a.attached(t)
	from, to := r1, r2
	if a.current().addr == r2.addr {
		from, to = r2, r1
	}
	prev := a.current()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	from.srv.Drain(ctx, nil)
	ae := closeOf(t, prev)
	assert.True(t, ae.Remote, "the agent closed its session before the end of the drain time")
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), ae.ErrorCode)
	// Then the agent dials the relays that it knows.
	a.attached(t)
	assert.Equal(t, to.addr, a.current().addr)
}

// TestDrainLocalRoutesOnly drains the relay of an agent that has one agent for
// each relay. The relay gives it no alternate, so it does not move.
func TestDrainLocalRoutesOnly(t *testing.T) {
	w := newWorld(t)
	r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
	a := w.agent(t, "a", r1, agentOptions{localRoutesOnly: true, sessions: 1})
	a.attached(t)
	prev := a.current()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	r1.srv.Drain(ctx, []*dp.RelayRef{{Id: r2.id, Addresses: []string{r2.addr}}})
	// The relay closed the session at the end of the drain time.
	ae := closeOf(t, prev)
	assert.True(t, ae.Remote)
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), ae.ErrorCode)
	assert.Empty(t, r2.r.AttachmentStats(), "the agent has no attachment on the other relay")
}

// TestDrainMesh drains a relay with the alternates that its mesh gives. An
// agent that knows only that relay moves to the first of the other relays.
func TestDrainMesh(t *testing.T) {
	w := newWorld(t)
	w.mesh = true
	r1, r2, r3 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3")
	joinMesh(t, r1, r2, r3)
	a := w.agent(t, "a", r1, agentOptions{sessions: 1})
	a.attached(t)
	prev := a.current()
	alts := r1.mesh.Alternates()
	want := []*dp.RelayRef{{Id: r2.id, Addresses: []string{r2.addr}}, {Id: r3.id, Addresses: []string{r3.addr}}}
	require.Empty(t, cmp.Diff(want, alts, protocmp.Transform()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r1.srv.Drain(ctx, alts)
	}()
	a.attached(t)
	assert.Equal(t, r2.addr, a.current().addr, "the agent moves to the first alternate")
	select {
	case <-done:
		assert.NoError(t, ctx.Err(), "the agent closed its session before the drain time ended")
	case <-time.After(10 * time.Second):
		t.Fatal("drain did not end")
	}
	closedByAgent(t, prev)
	id := identity.ID{Project: testProject, VPC: testVPC, Agent: "a"}.String()
	assert.Equal(t, 2, w.addrs.Overlap(id), "the new session attaches before the old one closes")
}

// TestFirstPacketAfterMove checks that after a spare takes the attachment, the
// first packet to a peer opens a peer session on the new relay session.
func TestFirstPacketAfterMove(t *testing.T) {
	cases := []struct {
		name  string
		drain bool // The relay drains, in place of the session end.
	}{
		{name: "attached session ends"},
		{name: "relay drains", drain: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
			a := w.agent(t, "a", nil, agentOptions{relays: []identity.Relay{r1.ref(), r2.ref()}, sessions: 2})
			a.attached(t)
			require.Eventually(t, func() bool { return a.spare() != nil }, 10*time.Second, 10*time.Millisecond)
			from, to := r1, r2
			if a.current().addr == r2.addr {
				from, to = r2, r1
			}
			spare := a.spare()
			b := w.agent(t, "b", to, agentOptions{})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 9000)

			if tc.drain {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				var wg sync.WaitGroup
				t.Cleanup(func() { cancel(); wg.Wait() })
				wg.Go(func() { from.srv.Drain(ctx, []*dp.RelayRef{{Id: to.id, Addresses: []string{to.addr}}}) })
			} else {
				a.reconnect()
			}
			ea := a.attached(t)
			require.Same(t, spare, a.current(), "the spare takes the attachment")
			require.NoError(t, sendOnce(a.stack, ea.addr, eb.addr, 9000, "after the move"))
			assert.Equal(t, 1, peerCount(a.a))
			assert.Zero(t, a.a.Stats().HoldDrops)
			assert.Zero(t, unreachableIn(a))
		})
	}
}

// TestMoveAfterPromote checks that after a spare takes the attachment, the
// agent tells its relay when the local address changes.
func TestMoveAfterPromote(t *testing.T) {
	cases := []struct {
		name      string
		moveFirst bool // The socket moves while the session is a spare.
	}{
		{name: "move after the promote"},
		{name: "move before the promote", moveFirst: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := loopback(t)
			t.Cleanup(func() { _ = next.Close() })
			w := newWorld(t)
			r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
			runRouter(t, r1)
			runRouter(t, r2)
			mc := &moveConn{next: next}
			a := w.agent(t, "a", nil, agentOptions{mode: TransportPSP, move: mc, relays: []identity.Relay{r1.ref(), r2.ref()}, sessions: 2})
			a.attached(t)
			require.Eventually(t, func() bool { return a.spare() != nil }, 10*time.Second, 10*time.Millisecond)
			to := r2
			if a.current().addr == r2.addr {
				to = r1
			}
			spare := a.spare()
			b := w.agent(t, "b", to, agentOptions{mode: TransportPSP})
			eb := b.attached(t)
			echo(t, b.stack, eb.addr, 7)
			if tc.moveFirst {
				mc.move()
			}
			a.reconnect()
			ea := a.attached(t)
			require.Same(t, spare, a.current(), "the spare takes the attachment")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			if !tc.moveFirst {
				ping(t, a.stack, ea.addr, eb.addr, 7, "before the move")
				// With no QUIC packet in flight, quic-go does not move the connection by itself.
				time.Sleep(1500 * time.Millisecond)
				mc.move()
			}
			t0 := time.Now()
			at := firstEcho(t, a.stack, ea.addr, eb.addr, 7, 20*time.Millisecond, 1500*time.Millisecond)
			require.False(t, at.IsZero(), "no data in 1.5 s after the move")
			t.Logf("Data works after %v", at.Sub(t0))
		})
	}
}

// TestSpares checks that the agent keeps Sessions-1 spares on other relays,
// moves to a spare when the attached session ends, and replaces spares.
func TestSpares(t *testing.T) {
	cases := []struct {
		name     string
		sessions int
		endSpare bool // A spare ends, in place of the attached session.
	}{
		{name: "one session", sessions: 1},
		{name: "attached session ends", sessions: 2},
		{name: "spare ends", sessions: 2, endSpare: true},
		{name: "attached session ends with two spares", sessions: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			var relays []identity.Relay
			for i := range 3 {
				relays = append(relays, w.relay(t, fmt.Sprintf("relay-%d", i+1)).ref())
			}
			a := w.agent(t, "a", nil, agentOptions{relays: relays, sessions: tc.sessions})
			a.attached(t)
			spares := func() []*relayConn {
				a.a.mu.Lock()
				defer a.a.mu.Unlock()
				return slices.Clone(a.a.spares)
			}
			full := func() bool { return len(spares()) == tc.sessions-1 }
			require.Eventually(t, full, 10*time.Second, 10*time.Millisecond)
			if tc.sessions == 1 {
				require.Never(t, func() bool { return len(spares()) > 0 }, 500*time.Millisecond, 10*time.Millisecond)
			}
			used := map[string]bool{a.current().ep.key(): true}
			for _, s := range spares() {
				used[s.ep.key()] = true
			}
			assert.Len(t, used, tc.sessions, "each session is on its own relay")

			old, cur := spares(), a.current()
			if tc.endSpare {
				_ = old[0].qc.CloseWithError(0, "spare ends")
				require.Eventually(t, func() bool { return full() && !slices.Contains(spares(), old[0]) }, 10*time.Second, 10*time.Millisecond)
				assert.Same(t, cur, a.current())
				return
			}
			a.reconnect()
			a.attached(t)
			if tc.sessions > 1 {
				assert.True(t, slices.Contains(old, a.current()), "a spare takes the attachment")
			}
			t.Logf("Setup after the attached session ended: %v", a.a.Status().Setup)
			require.Eventually(t, full, 10*time.Second, 10*time.Millisecond)
		})
	}
}

// TestRelist checks that the agent enrolls again for a new relay list when
// all relays fail, and keeps the cached list while the enroll fails.
func TestRelist(t *testing.T) {
	oldMin, oldMax := relistMin, relistMax
	relistMin, relistMax = 100*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { relistMin, relistMax = oldMin, oldMax })
	cases := []struct {
		name  string
		fails int32 // Enrolls that fail after the first.
	}{
		{name: "new list"},
		{name: "enroll fails", fails: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", nil, agentOptions{enrolled: func(n int32) ([]identity.Relay, []byte, error) {
				switch {
				case n == 1:
					return []identity.Relay{{ID: "relay-0", Addresses: []string{"no-port"}}}, nil, nil
				case n <= 1+tc.fails:
					return nil, nil, errors.New("apiserver is down")
				}
				return []identity.Relay{r.ref()}, nil, nil
			}})
			a.attached(t)
			assert.Equal(t, r.addr, a.current().addr)
			assert.Equal(t, 2+tc.fails, a.enrolls.Load())
		})
	}
}

// TestRelayDial checks how the agent picks and trusts relays.
func TestRelayDial(t *testing.T) {
	cases := []struct {
		name      string
		first     string // Address of a relay before the live relay. "dead" drops all packets.
		noRoots   bool   // No Config.RelayRoots.
		certRoots bool   // Enroll gives the relay roots.
		attaches  bool
	}{
		{name: "next relay after a failed dial", first: "no-port", attaches: true},
		{name: "next relay while the first relay does not answer", first: "dead", attaches: true},
		{name: "unknown relay CA", noRoots: true},
		{name: "relay roots from enroll", noRoots: true, certRoots: true, attaches: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			relays := []identity.Relay{r.ref()}
			if tc.first != "" {
				addr := tc.first
				if addr == "dead" {
					addr = deadRelay(t)
				}
				relays = append([]identity.Relay{{ID: "relay-0", Addresses: []string{addr}}}, relays...)
			}
			opts := agentOptions{relays: relays, noRoots: tc.noRoots}
			if tc.certRoots {
				roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.relayCA.Cert.Raw})
				opts.relays = nil
				opts.enrolled = func(int32) ([]identity.Relay, []byte, error) { return relays, roots, nil }
			}
			a := w.agent(t, "a", r, opts)
			if !tc.attaches {
				select {
				case <-a.attach:
					t.Fatal("agent attached to a relay that it cannot verify")
				case <-time.After(time.Second):
				}
				return
			}
			a.attached(t)
			assert.Equal(t, r.addr, a.current().addr)
			setup := a.a.Status().Setup
			t.Logf("Setup with %d relays: %v", len(relays), setup)
			assert.Less(t, setup, 2*time.Second)
		})
	}
}

// TestCertRefused checks that the agent gets a new cert and dials again
// when the relay closes its session after a CA change.
func TestCertRefused(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	a.attached(t)
	require.Equal(t, int32(1), a.enrolls.Load())

	w.rotateAgentCA(t)
	r.r.Recheck()
	a.attached(t)
	assert.Equal(t, int32(2), a.enrolls.Load())
}

func TestRelayPacketSize(t *testing.T) {
	assert.GreaterOrEqual(t, int(relayQUIC.InitialPacketSize), relay.MinPacketSize)
	// The QUIC path of the binding carries psp.QUICMTU, as MinPacketSize carries 1280.
	assert.Equal(t, psp.QUICMTU, int(relayQUIC.InitialPacketSize)-(relay.MinPacketSize-psp.DefaultMTU))
}
