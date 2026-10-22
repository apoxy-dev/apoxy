// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/softpsp/vtep/netstack"
)

// TestHeads checks the packet heads that TakeHead gives for the ICMP error of
// a NoRoute: one for each destination in headHold, from the first packet of
// a flow after the last error.
func TestHeads(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	require.NoError(t, a.l.AddSource(netip.PrefixFrom(a.v4, 32)))
	require.NoError(t, a.l.AddSource(netip.PrefixFrom(a.v6, 128)))
	other, err := a.b.AddLink()
	require.NoError(t, err)
	far := netip.MustParseAddr("10.9.9.9")
	small, small2 := packet(a.v4, b.v4, 17, 1, 2, 100), packet(a.v4, b.v4, 17, 3, 4, 120)
	large := packet(a.v6, b.v6, 17, 1, 2, DefaultMTU)
	t0 := time.Now()
	send := func(pkts ...[]byte) func() {
		return func() {
			for _, pkt := range pkts {
				var f netstack.TxFrame
				_ = a.b.prepare(pkt, &f)
			}
		}
	}
	steps := []struct {
		name string
		do   func()
		l    *Link
		dst  netip.Addr
		at   time.Duration // Time of TakeHead after t0.
		want []byte
	}{
		{name: "no packet", dst: b.v4},
		{name: "first packet of two", do: send(small, small2), dst: b.v4, want: small},
		{name: "head given", dst: b.v4},
		{name: "new packet before headHold", do: send(small2), dst: b.v4, at: headHold / 2},
		{name: "new packet after headHold", dst: b.v4, at: headHold, want: small2},
		{name: "large packet", do: send(large), dst: b.v6, want: large[:quoteLen]},
		{name: "no route", do: send(packet(a.v4, far, 17, 1, 2, 100)), dst: far},
		{name: "other link", do: send(small), l: other, dst: b.v4, at: 2 * headHold},
	}
	for _, st := range steps {
		if st.do != nil {
			st.do()
		}
		l := st.l
		if l == nil {
			l = a.l
		}
		assert.Equal(t, st.want, a.b.TakeHead(l, st.dst, t0.Add(st.at)), st.name)
	}

	t.Run("full table", func(t *testing.T) {
		a, b := newPair(t)
		offer(t, time.Now(), a, b)
		pfx := netip.MustParsePrefix("10.8.0.0/16")
		require.NoError(t, a.b.AddRoute(pfx, a.peer))
		dst := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 8, byte(i >> 8), byte(i)}) }
		for i := range headSlots + 1 {
			var f netstack.TxFrame
			_ = a.b.prepare(packet(a.v4, dst(i), 17, 1, 2, 100), &f)
		}
		now := time.Now()
		assert.NotNil(t, a.b.TakeHead(a.l, dst(0), now), "a head in the table")
		assert.Nil(t, a.b.TakeHead(a.l, dst(headSlots), now), "a full table keeps no new head")
	})
}

// TestCloseJoins checks that Close returns after the inject workers of the
// netstack driver returned.
func TestCloseJoins(t *testing.T) {
	a, _ := newPair(t)
	startNetstack(t, a, 0)
	require.True(t, injectRuns(), "the netstack driver has inject workers")
	require.NoError(t, a.b.Close())
	assert.False(t, injectRuns(), "an inject worker runs after Close")
}

// injectRuns reports whether a goroutine runs an inject worker.
func injectRuns() bool {
	// The buffer grows until it has the stacks of all goroutines.
	for n := 1 << 22; ; n *= 2 {
		buf := make([]byte, n)
		if m := runtime.Stack(buf, true); m < n {
			return strings.Contains(string(buf[:m]), "(*injectBatch).run")
		}
	}
}
