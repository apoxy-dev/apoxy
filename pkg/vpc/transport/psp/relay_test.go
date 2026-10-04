// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// testWindow keeps TCP small, so that race builds stay fast.
const testWindow = 24 << 10

// TestRelay sends TCP through a relay that forwards by SPI, while relay
// calls run on the QUIC session of the same socket.
func TestRelay(t *testing.T) {
	a, b, fr := newRelayPair(t)
	offer(t, time.Now(), a, b)
	sa, sb := startNetstack(t, a, testWindow), startNetstack(t, b, testWindow)

	cases := []struct {
		name string
		dst  netip.Addr
	}{
		{"IPv4", b.v4},
		{"IPv6", b.v6},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := uint16(8000 + i)
			echo(t, sb, tc.dst, port)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, sa, fullAddr(tc.dst, port), protoOf(tc.dst))
			require.NoError(t, err)
			defer c.Close()

			data := make([]byte, testData)
			_, _ = rand.Read(data)
			var calls sync.WaitGroup
			calls.Go(func() {
				for range 20 {
					res, err := a.rc.ResolvePeer(ctx, &dp.ResolvePeerRequest{
						Vpc:     &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC},
						Address: tc.dst.String(),
					})
					if assert.NoError(t, err) {
						assert.Equal(t, dp.Reach_REACH_LOCAL, res.Reach)
					}
				}
			})
			go func() { _, _ = c.Write(data) }()
			got := make([]byte, len(data))
			_, err = io.ReadFull(c, got)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(data, got))
			calls.Wait()
		})
	}
	for _, n := range []*node{a, b} {
		st := n.b.Stats()
		assert.NotZero(t, st.RxPackets)
		assert.NotZero(t, st.TxPackets)
		assert.Zero(t, st.RxDrops)
		assert.Zero(t, st.TxDrops)
	}
	assert.Zero(t, fr.drops.Load())
}

// TestRelayLanes sends UDP flows through the relay from the lane sockets whose
// ports the relay took, or from the agent socket when it took none. With
// receive, the relay sends SA lane i to lane socket i mod (ports+1).
func TestRelayLanes(t *testing.T) {
	const flows = 32
	cases := []struct {
		name       string
		lanes      int // SAs that each node offers.
		relayLanes int // Lane port limit of the relay.
		ports      int // Lane ports of each node.
		receive    bool
		wantLanes  bool
		wantRx     bool
	}{
		{"one lane", 1, relay.MaxLaneSources, 0, false, false, false},
		{"4 lanes", 4, relay.MaxLaneSources, 3, false, true, false},
		{"relay takes no lane ports", 4, 0, 3, false, false, false},
		{"4 lanes, receive", 4, relay.MaxLaneSources, 3, true, true, true},
		{"4 lanes, 2 lane ports, receive", 4, relay.MaxLaneSources, 2, true, true, true},
		{"relay takes no lane ports, receive", 4, 0, 3, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b, fr := newRelayPairRecv(t, tc.lanes, tc.relayLanes, tc.ports, tc.receive)
			if tc.wantRx {
				// The relay uses a lane port after its first keepalive.
				require.Eventually(t, func() bool { return fr.keepalives.Load() >= uint64(2*tc.ports) },
					5*time.Second, time.Millisecond)
			}
			offer(t, time.Now(), a, b)
			sa, sb := startNetstack(t, a, 0), startNetstack(t, b, 0)
			recv, err := gonet.DialUDP(sb, ptr(fullAddr(b.v4, 9)), nil, protoOf(b.v4))
			require.NoError(t, err)
			defer recv.Close()
			for range flows {
				send, err := gonet.DialUDP(sa, ptr(fullAddr(a.v4, 0)), ptr(fullAddr(b.v4, 9)), protoOf(b.v4))
				require.NoError(t, err)
				defer send.Close()
				_, err = send.Write([]byte("hello"))
				require.NoError(t, err)
			}
			buf := make([]byte, 100)
			for i := range flows {
				require.NoError(t, recv.SetReadDeadline(time.Now().Add(10*time.Second)))
				_, err := recv.Read(buf)
				require.NoError(t, err, "datagram %d", i)
			}
			lanes := a.b.LanePackets()
			assert.Equal(t, tc.wantLanes, len(lanes) > 1, "packets of each lane: %v", lanes)
			rx := b.b.RxLanePackets()
			assert.Equal(t, tc.wantRx, len(rx) > 1, "packets of each receive socket: %v", rx)
			assert.LessOrEqual(t, len(rx), tc.ports+1)
			assert.Zero(t, fr.drops.Load())
		})
	}
}

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

// TestRelayRekey rekeys both receivers while datagrams are in flight, and no
// datagram is lost. Each round waits for all datagrams, so timing has no effect.
func TestRelayRekey(t *testing.T) {
	a, b, fr := newRelayPair(t)
	now := time.Now()
	offer(t, now, a, b)
	type flow struct {
		send, recv *gonet.UDPConn
		next       uint32
		got        atomic.Uint32
	}
	stacks := map[*node]*stack.Stack{a: startNetstack(t, a, 0), b: startNetstack(t, b, 0)}
	var flows []*flow
	var readers sync.WaitGroup
	for _, n := range []*node{a, b} {
		recv, err := gonet.DialUDP(stacks[n.other], ptr(fullAddr(n.other.v4, 9)), nil, protoOf(n.v4))
		require.NoError(t, err)
		send, err := gonet.DialUDP(stacks[n], ptr(fullAddr(n.v4, 0)), ptr(fullAddr(n.other.v4, 9)), protoOf(n.v4))
		require.NoError(t, err)
		f := &flow{send: send, recv: recv}
		flows = append(flows, f)
		readers.Go(func() {
			seen := map[uint32]bool{}
			buf := make([]byte, 2000)
			for {
				m, err := recv.Read(buf)
				if err != nil {
					return // The test closed recv.
				}
				if i := binary.BigEndian.Uint32(buf[:m]); !seen[i] {
					seen[i] = true
					f.got.Add(1)
				}
			}
		})
	}
	defer func() {
		for _, f := range flows {
			_ = f.send.Close()
			_ = f.recv.Close()
		}
		readers.Wait()
	}()
	sendAll := func(count int) {
		buf := make([]byte, 1000)
		for _, f := range flows {
			for range count {
				binary.BigEndian.PutUint32(buf, f.next)
				f.next++
				_, err := f.send.Write(buf)
				require.NoError(t, err)
			}
		}
	}

	const rounds, perRound = 6, 16
	for round := range rounds {
		sendAll(perRound / 2)
		// Past 3/4 of the 10 minute lifetime: each SA is due, and the SAs
		// that the last round replaced end.
		now = now.Add(8 * time.Minute)
		ups, err := rekey(now, a, b)
		require.NoError(t, err)
		require.Equal(t, 2, ups, "round %d", round)
		sendAll(perRound / 2)
		require.Eventually(t, func() bool {
			for _, f := range flows {
				if f.got.Load() != f.next {
					return false
				}
			}
			return true
		}, 20*time.Second, time.Millisecond, "round %d: datagrams lost", round)
	}
	for _, n := range []*node{a, b} {
		// The binding counts a packet after the driver gets it, so the count can be late.
		require.Eventually(t, func() bool { return n.b.Stats().RxPackets >= rounds*perRound }, time.Second, time.Millisecond)
		st := n.b.Stats()
		assert.Zero(t, st.RxDrops)
		assert.Zero(t, st.TxDrops)
		assert.Equal(t, uint64(rounds*perRound), st.RxPackets)
	}
	assert.Zero(t, fr.drops.Load())
}

func ptr[T any](v T) *T { return &v }
