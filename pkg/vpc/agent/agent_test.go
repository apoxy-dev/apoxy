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
}
