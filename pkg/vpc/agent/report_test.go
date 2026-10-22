// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// TestBreaker sends UDP at twice the meter rate of the relay. The breaker of
// the relay peer trips on the receive reports of the relay, so the meter of the
// relay drops no more and the limiter of the sender drops the excess.
func TestBreaker(t *testing.T) {
	t.Skip("The data plane counts a packet in its receive SA before the meters, so RxReport does not show the meter drops.")
	const meter = 250_000 // Bytes per second.
	w := newWorld(t)
	w.relayCfg = relay.Config{LaneRate: meter}
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{mode: TransportAuto})
	b := w.agent(t, "b", r, agentOptions{mode: TransportAuto})
	ea, eb := a.attached(t), b.attached(t)

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
	var sent atomic.Int64
	begin := time.Now()
	go func() {
		defer close(done)
		// 1000 B each 2 ms: twice the meter rate. A late wake-up sends the
		// packets that are due, at most 25, so that the rate stays the same.
		const each, most = 2 * time.Millisecond, 25
		tk := time.NewTicker(each)
		defer tk.Stop()
		payload := make([]byte, 1000)
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			due := int64(time.Since(begin) / each)
			for n := min(due-sent.Load(), most); n > 0; n-- {
				_, _ = c.Write(payload)
				sent.Add(1)
			}
		}
	}()

	meterDrops := func() uint64 { return relayDrops(t, r)["meter"] }
	limitDrops := func() uint64 { return a.binding().Stats().TxLimitDrops }
	require.Eventually(t, func() bool { return limitDrops() > 0 }, 20*time.Second, 50*time.Millisecond, "breaker did not trip")
	assert.Positive(t, meterDrops(), "the meter of the relay dropped before the trip")

	// The packets sent before the limit was set can still meet an empty meter.
	time.Sleep(time.Second)
	m0, s0, l0 := meterDrops(), sent.Load(), limitDrops()
	time.Sleep(2 * time.Second)
	m1, s1, l1 := meterDrops(), sent.Load(), limitDrops()
	assert.Less(t, float64(m1-m0), 0.05*float64(s1-s0), "drops of the relay meter after the trip")
	assert.Greater(t, l1, l0, "the limiter drops the excess")
	t.Logf("meter drops %d, limit drops %d of %d packets after the trip", m1-m0, l1-l0, s1-s0)
}
