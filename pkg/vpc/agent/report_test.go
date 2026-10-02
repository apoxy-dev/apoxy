// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// pspPeer returns the binding peer of the PSP peer session of a.
func pspPeer(t *testing.T, a *Agent) *psp.Peer {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.bp != nil && !p.quic {
			return p.bp
		}
	}
	t.Fatal("no PSP peer session")
	return nil
}

// rxCount is the sum of the receive counters of the SAs of p.
type rxCount struct{ packets, seq uint64 }

func rxCountOf(p *psp.Peer) rxCount {
	var c rxCount
	for _, sa := range p.RxReport() {
		c.packets += sa.Packets
		c.seq += uint64(sa.Seq)
	}
	return c
}

// lossBetween is the loss from x to y: the packets that did not arrive.
func lossBetween(x, y rxCount) float64 {
	return 1 - float64(y.packets-x.packets)/float64(y.seq-x.seq)
}

// TestBreaker sends UDP from a to b at twice the meter rate of the relay. The
// breaker of a trips on the receive reports of b, and its gate drops the
// excess at a, so that the relay meter stops dropping.
func TestBreaker(t *testing.T) {
	const meter = 250_000 // Bytes per second.
	w := newWorld(t)
	w.relayCfg = relay.Config{LaneRate: meter}
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{mode: TransportPSP})
	b := w.agent(t, "b", r, agentOptions{mode: TransportPSP})
	ea, eb := a.attached(t), b.attached(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.a.Connect(ctx, eb.addr))
	toB, fromA := pspPeer(t, a.a), pspPeer(t, b.a)

	sink, err := gonet.DialUDP(b.stack, fullAddr(eb.addr, 9000), nil, ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := sink.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	c, err := gonet.DialUDP(a.stack, fullAddr(ea.addr, 0), fullAddr(eb.addr, 9000), ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	stop := make(chan struct{})
	done := make(chan struct{})
	defer func() {
		close(stop)
		<-done
	}()
	go func() {
		defer close(done)
		// 1000 B each 2 ms: twice the meter rate.
		tk := time.NewTicker(2 * time.Millisecond)
		defer tk.Stop()
		payload := make([]byte, 1000)
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				_, _ = c.Write(payload)
			}
		}
	}()

	start := rxCountOf(fromA)
	require.Eventually(t, func() bool { return toB.Limit() > 0 }, 20*time.Second, 50*time.Millisecond, "breaker did not trip")
	tripped, gateDrops := rxCountOf(fromA), a.binding().Stats().TxGateDrops
	assert.GreaterOrEqual(t, lossBetween(start, tripped), 0.2, "loss at the relay meter before the trip")
	assert.LessOrEqual(t, toB.Limit(), int64(meter*3/4), "about half of the rate that arrived")

	require.Eventually(t, func() bool { return rxCountOf(fromA).seq-tripped.seq >= 300 }, 10*time.Second, 50*time.Millisecond)
	after := rxCountOf(fromA)
	assert.Less(t, lossBetween(tripped, after), 0.05, "loss at the relay meter after the trip")
	assert.Greater(t, a.binding().Stats().TxGateDrops, gateDrops, "the gate drops the excess")
	t.Logf("loss before %.3f, limit %d B/s, loss after %.3f, gate drops %d", lossBetween(start, tripped),
		toB.Limit(), lossBetween(tripped, after), a.binding().Stats().TxGateDrops-gateDrops)
}
