// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// testWindow keeps TCP small, so that race builds stay fast.
const testWindow = 24 << 10

// TestDirect sends UDP between two bindings with no QUIC session on their sockets.
func TestDirect(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	sa, sb := startNetstack(t, a, 0), startNetstack(t, b, 0)
	for _, dst := range []netip.Addr{b.v4, b.v6} {
		t.Run(dst.String(), func(t *testing.T) {
			recv, err := gonet.DialUDP(sb, ptr(fullAddr(dst, 9)), nil, protoOf(dst))
			require.NoError(t, err)
			defer recv.Close()
			src := a.v4
			if dst.Is6() {
				src = a.v6
			}
			send, err := gonet.DialUDP(sa, ptr(fullAddr(src, 0)), ptr(fullAddr(dst, 9)), protoOf(dst))
			require.NoError(t, err)
			defer send.Close()
			_, err = send.Write([]byte("hello"))
			require.NoError(t, err)
			require.NoError(t, recv.SetReadDeadline(time.Now().Add(10*time.Second)))
			buf := make([]byte, 100)
			n, err := recv.Read(buf)
			require.NoError(t, err)
			assert.Equal(t, "hello", string(buf[:n]))
		})
	}
}

// TestDirectTCP sends TCP between two bindings with no relay, at the default
// and the largest MTU. TCP gives GSO packets to the driver, which cuts them.
func TestDirectTCP(t *testing.T) {
	for _, mtu := range []int{DefaultMTU, MaxMTU} {
		t.Run(fmt.Sprintf("mtu=%d", mtu), func(t *testing.T) {
			a, b := newPairMTU(t, mtu)
			offer(t, time.Now(), a, b)
			sa, sb := startNetstack(t, a, testWindow), startNetstack(t, b, testWindow)
			for i, dst := range []netip.Addr{b.v4, b.v6} {
				t.Run(dst.String(), func(t *testing.T) {
					port := uint16(8000 + i)
					echo(t, sb, dst, port)
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					c, err := gonet.DialContextTCP(ctx, sa, fullAddr(dst, port), protoOf(dst))
					require.NoError(t, err)
					defer c.Close()
					data := make([]byte, testData)
					_, _ = rand.Read(data)
					go func() { _, _ = c.Write(data) }()
					got := make([]byte, len(data))
					_, err = io.ReadFull(c, got)
					require.NoError(t, err)
					assert.True(t, bytes.Equal(data, got))
				})
			}
			for _, x := range []struct {
				n *node
				s *stack.Stack
			}{{a, sa}, {b, sb}} {
				st := x.n.b.Stats()
				assert.Zero(t, st.RxDrops)
				assert.Zero(t, st.TxDrops)
				// The binding sends more packets than the NIC, so TCP used GSO.
				assert.Less(t, x.s.NICInfo()[1].Stats.Tx.Packets.Value(), st.TxPackets)
			}
		})
	}
}

// echo listens on s, and serves one TCP connection that sends back what it reads.
func echo(t *testing.T, s *stack.Stack, a netip.Addr, port uint16) {
	ln, err := gonet.ListenTCP(s, fullAddr(a, port), protoOf(a))
	require.NoError(t, err)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if !assert.NoError(t, err) {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
}

func ptr[T any](v T) *T { return &v }
