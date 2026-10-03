// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// nullStack returns the endpoint of a netstack NIC with no addresses.
func nullStack(b *testing.B) *channel.Endpoint {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}})
	b.Cleanup(s.Close)
	ep := channel.New(16, DefaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		b.Fatalf("create NIC: %v", err)
	}
	return ep
}

// BenchmarkVirtToPhy makes the send frame of a 1280 B TCP packet, with the MSS clamp off and
// on, as PSP and as a QUIC data frame.
func BenchmarkVirtToPhy(b *testing.B) {
	for _, bc := range []struct {
		clamp int
		quic  bool
	}{{0, false}, {DefaultMTU, false}, {0, true}} {
		b.Run(fmt.Sprintf("clamp=%d/quic=%t", bc.clamp, bc.quic), func(b *testing.B) {
			x, y := newPairMTU(b, MaxMTU)
			offer(b, time.Now(), x, y)
			x.b.SetClampMTU(bc.clamp)
			if bc.quic {
				x.b.UseQUIC(&peerconn.Conn{})
			}
			d := &driver{b: x.b}
			pkt := packet(x.v4, y.v4, 6, 1, 2, DefaultMTU)
			phy := make([]byte, 2048)
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			for b.Loop() {
				if n, _ := d.VirtToPhy(pkt, phy); n == 0 {
					b.Fatal("no packet")
				}
			}
		})
	}
}

// BenchmarkRoundTrip seals one packet and gives it to the receive path, which
// opens it in place.
func BenchmarkRoundTrip(b *testing.B) {
	for _, to := range []string{"none", "netstack"} {
		b.Run("deliver="+to, func(b *testing.B) {
			x, y := newPair(b)
			offer(b, time.Now(), x, y)
			deliver := func([]byte, int) bool { return true }
			if to == "netstack" {
				// The netstack drops the packet: it has no address.
				ep := nullStack(b)
				deliver = func(buf []byte, off int) bool { return inject(ep, buf[off:]) }
			}
			y.b.drv.Store(newDriver(y.b, deliver))
			tx := &driver{b: x.b}
			pkt := packet(x.v4, y.v4, 6, 1, 2, DefaultMTU)
			phy := make([]byte, 2048)
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			for b.Loop() {
				n, _ := tx.VirtToPhy(pkt, phy)
				y.b.receive(phy[addrLen:n])
			}
			require.Equal(b, uint64(b.N), y.b.Stats().RxPackets)
		})
	}
}

// nopTun is a TUN device that drops the packets that it writes.
type nopTun struct{ *fakeTun }

func (nopTun) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// BenchmarkTunBatch copies 1280 B packets into a TUN batch, and writes each full batch.
func BenchmarkTunBatch(b *testing.B) {
	var bd Binding
	bt := newTunBatch(&tunWriter{dev: nopTun{newFakeTun(1)}}, &bd.stats)
	pkt := packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 6, 1, 2, DefaultMTU)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		bt.add(pkt)
	}
	bt.flush()
	require.Equal(b, uint64(b.N), bd.Stats().RxPackets)
}

// BenchmarkHandleData opens one QUIC data frame and gives it to a driver, with the MSS
// clamp off and on.
func BenchmarkHandleData(b *testing.B) {
	for _, clamp := range []int{0, DefaultMTU} {
		b.Run(fmt.Sprintf("clamp=%d", clamp), func(b *testing.B) {
			x, y := newPairMTU(b, MaxMTU)
			y.b.SetClampMTU(clamp)
			y.b.drv.Store(newDriver(y.b, func([]byte, int) bool { return true }))
			frame := peerconn.EncodeData(nil, testVNI, packet(x.v4, y.v4, 6, 1, 2, DefaultMTU))
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			for b.Loop() {
				y.b.HandleData(frame)
			}
			require.Equal(b, uint64(b.N), y.b.Stats().RxPackets)
		})
	}
}

// BenchmarkWriteFrames sends 64 PSP packets to a UDP socket, with sendmmsg
// and with one write for each packet.
func BenchmarkWriteFrames(b *testing.B) {
	for _, batch := range []bool{true, false} {
		b.Run(fmt.Sprintf("sendmmsg=%t", batch), func(b *testing.B) {
			x, y := newPair(b)
			offer(b, time.Now(), x, y)
			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(b, err)
			defer sink.Close()
			x.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
			d := newDriver(x.b, nil)
			if !batch {
				d.tx = nil
			}
			phy := make([]byte, 2048)
			n, _ := d.VirtToPhy(packet(x.v4, y.v4, 6, 1, 2, DefaultMTU), phy)
			frames := repeat(phy[:n], 64)
			b.SetBytes(int64(len(frames) * (n - addrLen)))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = d.WriteFrames(frames)
			}
			require.Zero(b, x.b.Stats().TxDrops)
		})
	}
}

// BenchmarkThroughput sends TCP from one netstack to another, directly or
// through the relay, on 1 or 4 flows.
func BenchmarkThroughput(b *testing.B) {
	for _, path := range []string{"direct", "relay"} {
		for _, flows := range []int{1, 4} {
			b.Run(fmt.Sprintf("%s/flows=%d", path, flows), func(b *testing.B) {
				benchThroughput(b, path == "relay", flows)
			})
		}
	}
}

func benchThroughput(b *testing.B, viaRelay bool, flows int) {
	var x, y *node
	var fr *fakeRelay
	if viaRelay {
		x, y, fr = newRelayPair(b)
	} else {
		x, y = newPair(b)
	}
	offer(b, time.Now(), x, y)
	sx, sy := startNetstack(b, x, 4<<20), startNetstack(b, y, 4<<20)

	ln, err := gonet.ListenTCP(sy, fullAddr(y.v4, 5001), protoOf(y.v4))
	require.NoError(b, err)
	defer ln.Close()
	var got atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(counter{&got}, c)
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conns := make([]net.Conn, flows)
	for i := range conns {
		conns[i], err = gonet.DialContextTCP(ctx, sx, fullAddr(y.v4, 5001), protoOf(y.v4))
		require.NoError(b, err)
	}

	const perOp = 1 << 20
	buf := make([]byte, 64<<10)
	tx0, rx0 := x.b.Stats().TxPackets, y.b.Stats().RxPackets
	b.SetBytes(perOp)
	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() {
			for left := int64(b.N) * perOp / int64(flows); left > 0; left -= int64(len(buf)) {
				if _, err := c.Write(buf[:min(left, int64(len(buf)))]); err != nil {
					b.Error(err)
					return
				}
			}
			_ = c.Close()
		})
	}
	wg.Wait()
	total := int64(b.N) * perOp / int64(flows) * int64(flows)
	for got.Load() < total && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	elapsed := time.Since(start)
	b.StopTimer()
	require.Equal(b, total, got.Load(), "x %+v; y %+v", x.b.Stats(), y.b.Stats())
	b.ReportMetric(float64(total)*8/elapsed.Seconds()/1e9, "Gbit/s")
	// Data packets that the sender sent and the receiver did not open.
	tx, rx := x.b.Stats().TxPackets-tx0, y.b.Stats().RxPackets-rx0
	if tx > 0 {
		b.ReportMetric(100*float64(tx-min(tx, rx))/float64(tx), "loss%")
	}
	if fr != nil {
		b.ReportMetric(float64(fr.drops.Load()), "relaydrops")
	}
}

// counter counts the bytes written to it.
type counter struct{ n *atomic.Int64 }

func (c counter) Write(p []byte) (int, error) {
	c.n.Add(int64(len(p)))
	return len(p), nil
}
