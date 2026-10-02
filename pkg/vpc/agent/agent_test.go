// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	c, err := gonet.DialUDP(s, fullAddr(addr, port), nil, ipv6.ProtocolNumber)
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
				assert.Error(t, a.a.Connect(ctx, eb.addr))
				a.stop()
			}
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

// TestRenew checks that the agent opens a relay session with the renewed
// cert before it closes the old one.
func TestRenew(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{life: 3 * time.Second})
	first := a.attached(t)
	second := a.attached(t)
	assert.NotEqual(t, first.addr, second.addr, "each relay session has its own addresses")
	assert.GreaterOrEqual(t, a.enrolls.Load(), int32(2))
	id := identity.ID{Project: testProject, VPC: testVPC, Agent: "a"}.String()
	assert.Equal(t, 2, w.addrs.overlap(id), "the new session attaches before the old one closes")
}

// TestDrain checks that the agent moves to an alternate relay before the
// draining relay closes its session.
func TestDrain(t *testing.T) {
	w := newWorld(t)
	r1, r2 := w.relay(t, "relay-1"), w.relay(t, "relay-2")
	a := w.agent(t, "a", r1, agentOptions{})
	a.attached(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r1.srv.Drain(ctx, []*dp.RelayRef{{Id: "relay-2", Addresses: []string{r2.addr}}})
	}()
	a.attached(t)
	a.a.mu.Lock()
	addr := a.a.rc.addr
	a.a.mu.Unlock()
	assert.Equal(t, r2.addr, addr)
	select {
	case <-done:
		assert.NoError(t, ctx.Err(), "the agent closed its session before the drain time ended")
	case <-time.After(10 * time.Second):
		t.Fatal("drain did not end")
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
