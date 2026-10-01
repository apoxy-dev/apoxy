// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"context"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func BenchmarkVirtToPhy(b *testing.B) {
	x, y := newPair(b)
	offer(b, time.Now(), x, y)
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
}

// BenchmarkRoundTrip seals and opens one packet.
func BenchmarkRoundTrip(b *testing.B) {
	x, y := newPair(b)
	offer(b, time.Now(), x, y)
	tx, rx := &driver{b: x.b}, &driver{b: y.b}
	pkt := packet(x.v4, y.v4, 6, 1, 2, DefaultMTU)
	phy, virt := make([]byte, 2048), make([]byte, 2048)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		n, _ := tx.VirtToPhy(pkt, phy)
		if rx.PhyToVirt(phy[addrLen:n], virt) == 0 {
			b.Fatal("no packet")
		}
	}
}

func BenchmarkFlowHash(b *testing.B) {
	x, y := newPair(b)
	pkt := packet(x.v6, y.v6, 6, 1, 2, 100)
	seed := maphash.MakeSeed()
	b.ReportAllocs()
	for b.Loop() {
		flowHash(seed, pkt)
	}
}

// BenchmarkWriteFrames sends one PSP packet to a UDP socket.
func BenchmarkWriteFrames(b *testing.B) {
	x, y := newPair(b)
	offer(b, time.Now(), x, y)
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(b, err)
	defer sink.Close()
	x.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
	d := newDriver(x.b)
	phy := make([]byte, 2048)
	n, _ := d.VirtToPhy(packet(x.v4, y.v4, 6, 1, 2, DefaultMTU), phy)
	frames := [][]byte{phy[:n]}
	b.SetBytes(int64(n - addrLen))
	b.ReportAllocs()
	for b.Loop() {
		_, _ = d.WriteFrames(frames)
	}
	require.Zero(b, x.b.Stats().TxDrops)
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
	tx0, rx0, full0 := x.b.Stats().TxPackets, y.b.Stats().RxPackets, y.b.Stats().RxFull
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
	b.ReportMetric(float64(y.b.Stats().RxFull-full0), "rxfull")
}

// counter counts the bytes written to it.
type counter struct{ n *atomic.Int64 }

func (c counter) Write(p []byte) (int, error) {
	c.n.Add(int64(len(p)))
	return len(p), nil
}
