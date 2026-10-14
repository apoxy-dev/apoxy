// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/pem"
	"errors"
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
		{name: "PSP to QUIC", a: TransportAuto, b: TransportQUIC, wantA: inPSP, wantB: quicConfig},
		{name: "QUIC to PSP", a: TransportQUIC, b: TransportAuto, wantA: quicConfig, wantB: inPSP},
		{name: "QUIC to QUIC", a: TransportQUIC, b: TransportQUIC, wantA: quicConfig, wantB: quicConfig},
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
				// The reason of a probe that failed comes after the wait for its reply.
				require.Eventually(t, func() bool { return x.ta.a.Status().Reason == x.want.Reason }, 5*time.Second, 5*time.Millisecond)
				st := x.ta.a.Status()
				assert.Equal(t, x.want.Mode, st.Mode)
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
		{name: "PSP", mode: TransportAuto, want: dp.Mode_MODE_PSP},
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
			a, b := w.agent(t, "a", r, agentOptions{mode: tc.mode, udp: udp}), w.agent(t, "b", r, agentOptions{mode: TransportAuto})
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
		{name: "PSP session", attach: true, mode: TransportAuto},
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
			_ = a.a.primary().qc.CloseWithError(0, "test ends the session")
			require.Eventually(t, func() bool { return a.a.Status().RTT == 0 }, 5*time.Second, 10*time.Millisecond)
		})
	}
}

// TestPSPAfterQUIC sends UDP in a PSP session that follows a QUIC session.
// The shards of the QUIC session must not dial again while the PSP session opens.
func TestPSPAfterQUIC(t *testing.T) {
	w := newWorld(t)
	w.mtu = 1400
	r := w.relay(t, "relay-1")
	conn := &lossyConn{}
	conn.limitProbes.Store(true)
	a, b := w.agent(t, "a", r, agentOptions{conn: conn}), w.agent(t, "b", r, agentOptions{})
	a.attached(t)
	require.Equal(t, dp.Mode_MODE_QUIC, a.a.Status().Mode)
	shards := func() bool {
		a.a.mu.Lock()
		defer a.a.mu.Unlock()
		return a.a.primaryLocked().pc.Shards() == quicShards
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

// dialTCP opens a TCP connection from ta to dst:port, which serveTCP answers.
func dialTCP(t *testing.T, ta *testAgent, dst netip.Addr, port uint16) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, ta.stack, *fullAddr(dst, port), ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// newCert waits until the agent uses another cert than old.
func (ta *testAgent) newCert(t *testing.T, old *identity.Credential) {
	t.Helper()
	require.Eventually(t, func() bool { return ta.a.cfg.Identity.Current() != old }, 10*time.Second, 10*time.Millisecond,
		"the agent did not get a new cert")
}

// TestRenew checks that a new agent cert changes nothing on an open relay
// session: the connection, the address and a TCP stream stay, and the agent
// runs no callback. An agent with an identity file does not enroll.
func TestRenew(t *testing.T) {
	cases := []struct {
		name string
		file bool // The agent has an identity file. The test replaces the file.
	}{
		{name: "enroll"},
		{name: "identity file", file: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			opts := agentOptions{tcp: true, life: 3 * time.Second}
			if tc.file {
				opts = agentOptions{tcp: true, identityFile: true}
			}
			a := w.agent(t, "a", r, opts)
			b := w.agent(t, "b", r, agentOptions{tcp: true})
			ea, eb := a.attached(t), b.attached(t)
			serveTCP(t, b.stack, eb.addr, 9000)
			c := dialTCP(t, a, eb.addr, 9000)
			roundTrip(t, c, "before the renew")

			old, cred := a.current(), a.a.cfg.Identity.Current()
			if tc.file {
				// The new cert must expire later than the cert in use.
				a.writeIdentity(25 * time.Hour)
			}
			a.newCert(t, cred)
			require.Never(t, func() bool { return len(a.attach) > 0 }, 500*time.Millisecond, 20*time.Millisecond,
				"the agent attached again after the renew")
			roundTrip(t, c, "after the renew")
			assert.Same(t, old, a.current(), "the agent has the same relay session")
			assert.NoError(t, old.qc.Context().Err(), "the relay connection is open")
			assert.Equal(t, ea.addr, a.current().self)
			assert.Equal(t, []string{"attach a " + ea.addr.String()}, a.events("a"), "no callback after the first attach")
			if tc.file {
				assert.Zero(t, a.enrolls.Load(), "an agent with an identity file does not enroll")
			} else {
				assert.GreaterOrEqual(t, a.enrolls.Load(), int32(2))
			}
		})
	}
}

// TestSessionAfterCertExpiry checks a relay session after the cert of its
// handshake expired: it carries data, and the agent opens a peer session and
// starts a visit on it.
func TestSessionAfterCertExpiry(t *testing.T) {
	cases := []struct {
		name  string
		visit bool // The relays of a and b have no path, so a visits the relay of b.
	}{
		{name: "new peer session"},
		{name: "visit", visit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r1, r2 := meshRelays(t)
			a := w.agent(t, "a", r1, agentOptions{tcp: true, life: 3 * time.Second, visitCheck: time.Hour})
			near := w.agent(t, "near", r1, agentOptions{tcp: true})
			b := w.agent(t, "b", r2, agentOptions{visitCheck: time.Hour, visitWait: time.Hour})
			ea, en, eb := a.attached(t), near.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			a.hasRoutes(t, eb.prefixes[0])
			serveTCP(t, near.stack, en.addr, 9000)
			c := dialTCP(t, a, en.addr, 9000)
			roundTrip(t, c, "before the expiry")

			old := a.current()
			first := a.a.cfg.Identity.Current().Cert.NotAfter
			require.Eventually(t, func() bool { return time.Now().After(first) }, 10*time.Second, 50*time.Millisecond)
			roundTrip(t, c, "after the expiry")
			if tc.visit {
				t.Cleanup(cutMesh(r1, r2))
				waitReach(t, a, eb.addr, dp.Reach_REACH_VISIT)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_, err := dialOnVisit(t, ctx, a, r2, eb.addr)
				require.NoError(t, err)
			}
			ping(t, a.stack, ea.addr, eb.addr, 9000, "to a new peer")
			assert.Same(t, old, a.current(), "the agent has the same relay session")
			assert.Equal(t, []string{"attach a " + ea.addr.String()}, a.events("a"))
		})
	}
}

// TestSharedIdentityFile runs two agents with one identity file: one cert and
// one key, and a name for each agent. A new file gives the two agents the new
// cert, and their relay sessions stay.
func TestSharedIdentityFile(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	opts := agentOptions{identity: "shared", identityFile: true, identityPath: filepath.Join(t.TempDir(), "identity.json")}
	a1 := w.agent(t, "a1", r, opts)
	a2 := w.agent(t, "a2", r, opts)
	c := w.agent(t, "c", r, agentOptions{})
	e1, e2, ec := a1.attached(t), a2.attached(t), c.attached(t)
	echo(t, a1.stack, e1.addr, 9001)
	echo(t, a2.stack, e2.addr, 9002)
	echo(t, c.stack, ec.addr, 9000)

	// traffic sends data between each two of the three agents.
	traffic := func() {
		t.Helper()
		ping(t, a1.stack, e1.addr, e2.addr, 9002, "a1 to a2")
		ping(t, a2.stack, e2.addr, e1.addr, 9001, "a2 to a1")
		ping(t, a1.stack, e1.addr, ec.addr, 9000, "a1 to c")
		ping(t, a2.stack, e2.addr, ec.addr, 9000, "a2 to c")
		ping(t, c.stack, ec.addr, e1.addr, 9001, "c to a1")
		ping(t, c.stack, ec.addr, e2.addr, 9002, "c to a2")
	}
	traffic()
	first := a1.a.cfg.Identity.Current()
	require.True(t, first.Cert.Equal(a2.a.cfg.Identity.Current().Cert), "a1 and a2 have one cert")

	a1.writeIdentity(25 * time.Hour)
	a1.newCert(t, first)
	require.Eventually(t, func() bool {
		return a1.a.cfg.Identity.Current().Cert.Equal(a2.a.cfg.Identity.Current().Cert)
	}, 10*time.Second, 10*time.Millisecond, "a2 has the cert of the new file")
	traffic()
	assert.Zero(t, len(a1.attach)+len(a2.attach), "the relay sessions stay")
	assert.Zero(t, a1.enrolls.Load()+a2.enrolls.Load(), "an agent with an identity file does not enroll")
}

// TestIdentityFileExpires checks that an agent with an identity file keeps
// its relay session after the cert of the file expired, and that Run returns
// an error when the agent then has no session.
func TestIdentityFileExpires(t *testing.T) {
	cases := []struct {
		name string
		lose bool // The relay session ends after the expiry.
	}{
		{name: "attached session"},
		{name: "no session", lose: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			runErr := make(chan error, 1)
			a := w.agent(t, "a", r, agentOptions{identityFile: true, life: 2 * time.Second, runErr: runErr})
			b := w.agent(t, "b", r, agentOptions{})
			ea, eb := a.attached(t), b.attached(t)
			echo(t, b.stack, eb.addr, 9000)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "before the expiry")
			old, want := a.current(), a.a.cfg.Identity.Current().Cert.NotAfter
			require.Eventually(t, func() bool { return time.Now().After(want) }, 10*time.Second, 50*time.Millisecond)
			require.Never(t, func() bool { return len(runErr) > 0 }, 500*time.Millisecond, 20*time.Millisecond,
				"Run stopped while the agent has a relay session")
			ping(t, a.stack, ea.addr, eb.addr, 9000, "after the expiry")
			assert.Same(t, old, a.current())
			assert.Zero(t, a.enrolls.Load(), "an agent with an identity file does not enroll")
			if !tc.lose {
				return
			}
			a.reconnect()
			select {
			case err := <-runErr:
				var expired *identity.ExpiredError
				require.ErrorAs(t, err, &expired)
				assert.True(t, expired.At.Equal(want), "the error has the expiry time of the cert")
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not stop after the last session of an expired identity file ended")
			}
		})
	}
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

// closedByDrain checks that the relay closed the session rc at the end of its
// drain, and that the agent did not close it.
func closedByDrain(t *testing.T, rc *relayConn) {
	t.Helper()
	ae := closeOf(t, rc)
	assert.True(t, ae.Remote, "the agent closed the session of a draining relay: %v", ae)
	assert.Equal(t, quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), ae.ErrorCode)
}

// drain starts the drain of r with alts. The drain ends, and r closes the
// sessions that stay, when the test calls end or ends.
func drain(t *testing.T, r *testRelay, alts []*dp.RelayRef) (end func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { r.srv.Drain(ctx, alts) })
	end = func() {
		cancel()
		wg.Wait()
	}
	t.Cleanup(end)
	return end
}

// stateOf returns the state of the session rc of a.
func stateOf(a *testAgent, rc *relayConn) connState {
	a.a.mu.Lock()
	defer a.a.mu.Unlock()
	return rc.state
}

// TestDrain checks that the agent opens a session on an alternate relay when its
// relay drains, and keeps the old session until the draining relay closes it.
func TestDrain(t *testing.T) {
	cases := []struct {
		name  string
		known bool // The agent knows both relays.
		// first comes before the alternate that takes the agent: "drains" (a relay
		// that drains too), "no address", or "wrong address" (of another relay).
		first string
		dead  bool // The alternate does not answer, so the agent gets no new session.
	}{
		{name: "alternate that the agent does not know"},
		{name: "alternate that the agent knows", known: true},
		{name: "first alternate drains too", first: "drains"},
		{name: "first alternate has no address", first: "no address"},
		{name: "first address of the alternate is of another relay", first: "wrong address"},
		{name: "alternate does not answer", dead: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r1, r2, r3 := w.relay(t, "relay-1"), w.relay(t, "relay-2"), w.relay(t, "relay-3")
			opts := agentOptions{}
			if tc.known {
				opts.relays = []identity.Relay{r1.ref(), r2.ref()}
			}
			a := w.agent(t, "a", r1, opts)
			first := a.attached(t)
			from, to := r1, r2
			if a.current().addr == r2.addr {
				from, to = r2, r1
			}
			good := &dp.RelayRef{Id: to.id, Addresses: []string{to.addr}}
			alts := []*dp.RelayRef{good}
			switch {
			case tc.first == "drains":
				// A relay that drains refuses a new session at once.
				r3.srv.Drain(context.Background(), nil)
				alts = []*dp.RelayRef{{Id: r3.id, Addresses: []string{r3.addr}}, good}
			case tc.first == "no address":
				alts = []*dp.RelayRef{{Id: r3.id}, good}
			case tc.first == "wrong address":
				alts = []*dp.RelayRef{{Id: to.id, Addresses: []string{r3.addr, to.addr}}}
			case tc.dead:
				alts = []*dp.RelayRef{{Id: to.id, Addresses: []string{deadRelay(t)}}}
			}
			prev := a.current()
			require.Equal(t, connAttached, stateOf(a, prev))
			end := drain(t, from, alts)

			if tc.dead {
				require.Eventually(t, func() bool { return stateOf(a, prev) == connDraining }, 5*time.Second, 10*time.Millisecond)
				assert.Same(t, prev, a.current(), "the draining session keeps the default address")
				assert.NoError(t, prev.qc.Context().Err(), "the draining session stays open")
				end()
				closedByDrain(t, prev)
				require.Eventually(t, func() bool { return stateOf(a, prev) == connEnded }, 5*time.Second, 10*time.Millisecond)
				return
			}
			second := a.attached(t)
			next := a.current()
			assert.Equal(t, to.addr, next.addr, "the new session has the default address")
			assert.Equal(t, connAttached, stateOf(a, next))
			assert.Equal(t, connDraining, stateOf(a, prev))
			assert.NoError(t, prev.qc.Context().Err(), "the draining session stays open")
			want := []ConnStatus{
				{Relay: from.addr, Address: first.addr, Rank: 0, Draining: true, Mode: dp.Mode_MODE_PSP},
				{Relay: to.addr, Address: second.addr, Rank: 1, Mode: dp.Mode_MODE_PSP},
			}
			got := a.a.Status().Connections
			for i := range got {
				got[i].RTT = 0
			}
			assert.Equal(t, want, got)
			assert.Equal(t, []string{"attach a " + first.addr.String(), "deprecate a " + first.addr.String(), "attach a " + second.addr.String()}, a.events("a"))

			end()
			closedByDrain(t, prev)
			require.Eventually(t, func() bool { return stateOf(a, prev) == connEnded }, 5*time.Second, 10*time.Millisecond)
			require.Eventually(t, func() bool { return len(a.events("a")) == 4 }, 5*time.Second, 10*time.Millisecond)
			assert.Equal(t, "detach a "+first.addr.String(), a.events("a")[3])
			a.a.mu.Lock()
			defer a.a.mu.Unlock()
			assert.Equal(t, []*relayConn{next}, a.a.conns, "only the old session ended")
		})
	}
}

// TestDrainNoAlternate drains the only relay of an agent, which gets no
// alternate. The agent keeps its session until the relay closes it, and dials
// no relay before.
func TestDrainNoAlternate(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{})
	a.attached(t)
	prev := a.current()
	sessions := func() int {
		a.a.mu.Lock()
		defer a.a.mu.Unlock()
		return len(a.a.conns)
	}

	end := drain(t, r, nil)
	require.Eventually(t, func() bool { return stateOf(a, prev) == connDraining }, 5*time.Second, 10*time.Millisecond)
	require.Never(t, func() bool { return sessions() != 1 || prev.qc.Context().Err() != nil },
		time.Second, 20*time.Millisecond, "the agent opened or closed a session while its relay drains")
	end()
	closedByDrain(t, prev)
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
// agent that knows only that relay attaches to the first of the other relays.
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

	end := drain(t, r1, alts)
	a.attached(t)
	assert.Equal(t, r2.addr, a.current().addr, "the agent attaches to the first alternate")
	assert.NoError(t, prev.qc.Context().Err(), "the draining session stays open")
	end()
	closedByDrain(t, prev)
}

// TestRelist checks that the agent enrolls again for a new relay list when
// all relays fail or the list is empty, and keeps the cached list while the
// enroll fails.
func TestRelist(t *testing.T) {
	oldMin, oldMax := relistMin, relistMax
	relistMin, relistMax = 100*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { relistMin, relistMax = oldMin, oldMax })
	noPort := []identity.Relay{{ID: "relay-0", Addresses: []string{"no-port"}}}
	cases := []struct {
		name  string
		first []identity.Relay // List of the first enroll.
		fails int32            // Enrolls that fail after the first.
	}{
		{name: "new list", first: noPort},
		{name: "enroll fails", first: noPort, fails: 1},
		{name: "no relay in the list, no session"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", nil, agentOptions{enrolled: func(n int32) ([]identity.Relay, []byte, error) {
				switch {
				case n == 1:
					return tc.first, nil, nil
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
