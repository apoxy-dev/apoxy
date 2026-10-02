// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// TestWriteFrames sends frames to a UDP socket with sendmmsg, and with one
// write for each packet.
func TestWriteFrames(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer sink.Close()
	_ = sink.SetReadBuffer(1 << 20)
	a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())

	frame := seal(a, packet(a.v4, b.v4, 17, 1, 2, 200))
	bad := bytes.Clone(frame) // An IPv6 address on an IPv4 socket.
	copy(bad, net.ParseIP("::1"))
	data := bytes.Clone(frame) // A data frame with no UseQUIC.
	clear(data[:addrLen])
	cases := []struct {
		name   string
		frames [][]byte
		batch  bool
		want   Stats
	}{
		{"one", [][]byte{frame}, true, Stats{TxPackets: 1}},
		{"more than one batch", repeat(frame, maxBatch+3), true, Stats{TxPackets: maxBatch + 3}},
		{"bad address in the middle", [][]byte{frame, bad, frame}, true, Stats{TxPackets: 2, TxDrops: 1}},
		{"bad address first", [][]byte{bad, frame, frame}, true, Stats{TxPackets: 2, TxDrops: 1}},
		{"data frame with no QUIC", [][]byte{data, frame}, true, Stats{TxPackets: 1, TxDrops: 1}},
		{"one write for each packet", [][]byte{frame, bad, frame}, false, Stats{TxPackets: 2, TxDrops: 1}},
	}
	buf := make([]byte, 2048)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(a.b, nil)
			if !tc.batch {
				d.pc = nil
			}
			before := a.b.Stats()
			n, err := d.WriteFrames(tc.frames)
			require.NoError(t, err)
			assert.Equal(t, len(tc.frames), n)
			assert.Equal(t, tc.want, sub(a.b.Stats(), before))
			for range tc.want.TxPackets {
				require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
				m, err := sink.Read(buf)
				require.NoError(t, err)
				require.Equal(t, frame[addrLen:], buf[:m])
			}
		})
	}

	require.NoError(t, a.b.Close())
	_, err = newDriver(a.b, nil).WriteFrames([][]byte{frame})
	assert.ErrorIs(t, err, net.ErrClosed)
}

func repeat(f []byte, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = f
	}
	return out
}

func TestTunWriter(t *testing.T) {
	pkt := packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 17, 1, 2, 300)
	cases := []struct {
		name string
		buf  []byte
		off  int
		err  error
		ok   bool
	}{
		{"space before the packet", append(make([]byte, 24), pkt...), 24, nil, true},
		{"little space before the packet", append(make([]byte, 5), pkt...), 5, nil, true},
		{"too large to copy", make([]byte, 5+DefaultMTU+1), 5, nil, false},
		{"device error", append(make([]byte, 24), pkt...), 24, errors.New("down"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := newFakeTun(1)
			dev.err = tc.err
			w := &tunWriter{dev: dev, bufs: make([][]byte, 1), scratch: make([]byte, tunOffset+DefaultMTU)}
			assert.Equal(t, tc.ok, w.write(tc.buf, tc.off))
			if tc.ok {
				assert.Equal(t, pkt, <-dev.out)
			}
			assert.Empty(t, dev.out)
		})
	}
}

// TestTun sends packets between two tun drivers on TUN devices in memory.
func TestTun(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	devs := map[*node]*fakeTun{}
	for _, n := range []*node{a, b} {
		dev := newFakeTun(16)
		td, err := n.b.Tun(dev)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- td.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			require.NoError(t, <-done)
			assert.Nil(t, n.b.drv.Load(), "the driver leaves the binding when it stops")
		})
		devs[n] = dev
	}
	_, err := a.b.Tun(newFakeTun(1))
	assert.Error(t, err, "a binding has one driver")

	cases := []struct {
		name string
		from *node
		pkt  []byte
	}{
		{"IPv4", a, packet(a.v4, b.v4, 17, 1, 2, 1000)},
		{"IPv6 MTU-size", b, packet(b.v6, a.v6, 6, 1, 2, DefaultMTU)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			devs[tc.from].in <- tc.pkt
			select {
			case got := <-devs[tc.from.other].out:
				assert.Equal(t, tc.pkt, got)
			case <-time.After(5 * time.Second):
				t.Fatalf("no packet; from %+v, to %+v", tc.from.b.Stats(), tc.from.other.b.Stats())
			}
		})
	}
}

// TestQUIC sends inner packets as data frames on a QUIC connection, which a
// peerconn reader gives to the binding.
func TestQUIC(t *testing.T) {
	a, b := newPair(t)
	qa, qb := quicPair(t, a.tr, b.tr)
	pa, pb := peerconn.New(qa, a.v4), peerconn.New(qb, b.v4)
	t.Cleanup(func() { _ = pa.Close(); _ = pb.Close() })
	pb.HandleData(b.b.HandleData)
	got := &capture{}
	b.b.drv.Store(newDriver(b.b, got.deliver))

	d := newDriver(a.b, nil)
	send := func(pkt []byte) func() {
		return func() {
			phy := make([]byte, 2048)
			if n, _ := d.VirtToPhy(pkt, phy); n > 0 {
				_, err := d.WriteFrames([][]byte{phy[:n]})
				require.NoError(t, err)
			}
		}
	}
	raw := func(vni uint32, pkt []byte) func() {
		return func() { require.NoError(t, qa.SendDatagram(peerconn.EncodeData(nil, vni, pkt))) }
	}
	v4, v6 := packet(a.v4, b.v4, 17, 1, 2, 1000), packet(a.v6, b.v6, 6, 1, 2, DefaultMTU)
	far := netip.MustParseAddr("10.9.9.9")
	cases := []struct {
		name    string
		quic    bool
		send    func()
		tx, rx  Stats
		deliver []byte
	}{
		{"IPv4", true, send(v4), Stats{TxPackets: 1}, Stats{RxPackets: 1}, v4},
		{"IPv6 MTU-size", true, send(v6), Stats{TxPackets: 1}, Stats{RxPackets: 1}, v6},
		{"no route", true, send(packet(a.v4, far, 17, 1, 2, 100)), Stats{TxNoRoute: 1}, Stats{}, nil},
		{"other VNI", true, raw(testVNI+1, v4), Stats{}, Stats{RxDrops: 1}, nil},
		{"source not routed", true, raw(testVNI, packet(far, b.v4, 17, 1, 2, 100)), Stats{}, Stats{RxDrops: 1}, nil},
		{"PSP again, no SA", false, send(v4), Stats{TxNoRoute: 1}, Stats{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.quic {
				a.b.UseQUIC(pa)
			} else {
				a.b.UseQUIC(nil)
			}
			txBefore, rxBefore := a.b.Stats(), b.b.Stats()
			got.mu.Lock()
			got.got = nil
			got.mu.Unlock()
			tc.send()
			if tc.rx != (Stats{}) {
				require.Eventually(t, func() bool { return b.b.Stats() != rxBefore }, 5*time.Second, time.Millisecond)
			}
			assert.Equal(t, tc.tx, sub(a.b.Stats(), txBefore))
			assert.Equal(t, tc.rx, sub(b.b.Stats(), rxBefore))
			if tc.deliver != nil {
				assert.Equal(t, [][]byte{tc.deliver}, got.got)
			}
		})
	}
}

// TestHandleDataConcurrent gives data frames to a tun driver from several
// readers at once, as the readers of QUIC connection shards do.
func TestHandleDataConcurrent(t *testing.T) {
	a, b := newPair(t)
	const readers, frames = 4, 200
	dev := newFakeTun(readers * frames)
	td, err := b.b.Tun(dev)
	require.NoError(t, err)
	defer td.Close()
	var wg sync.WaitGroup
	for r := range readers {
		wg.Go(func() {
			for i := range frames {
				pkt := packet(a.v4, b.v4, 17, uint16(r), uint16(i), 100+i)
				b.b.HandleData(peerconn.EncodeData(nil, testVNI, pkt))
			}
		})
	}
	wg.Wait()
	assert.Equal(t, Stats{RxPackets: readers * frames}, b.b.Stats())
	assert.Len(t, dev.out, readers*frames)
}
