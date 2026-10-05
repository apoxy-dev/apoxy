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

// TestWriteFrames sends frames to a UDP socket in batches, and with one write
// for each packet. The socket gets the PSP packets in order.
func TestWriteFrames(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer sink.Close()
	_ = sink.SetReadBuffer(1 << 20)
	a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())

	frame := seal(a, packet(a.v4, b.v4, 17, 1, 2, 200))
	small := seal(a, packet(a.v4, b.v4, 17, 1, 2, 100))
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
		{"two sizes", [][]byte{frame, frame, small, frame, small, small}, true, Stats{TxPackets: 6}},
		{"bad address in the middle", [][]byte{frame, bad, frame}, true, Stats{TxPackets: 2, TxDrops: 1}},
		{"bad address first", [][]byte{bad, frame, frame}, true, Stats{TxPackets: 2, TxDrops: 1}},
		{"data frame with no QUIC", [][]byte{data, frame}, true, Stats{TxPackets: 1, TxDrops: 1}},
		{"one write for each packet", [][]byte{frame, bad, small}, false, Stats{TxPackets: 2, TxDrops: 1}},
	}
	buf := make([]byte, 2048)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(a.b, nil)
			if !tc.batch {
				d.tx = nil
			}
			before := a.b.Stats()
			n, err := d.WriteFrames(tc.frames)
			require.NoError(t, err)
			assert.Equal(t, len(tc.frames), n)
			assert.Equal(t, tc.want, sub(a.b.Stats(), before))
			for i, f := range tc.frames {
				if !bytes.Equal(f[:addrLen], frame[:addrLen]) {
					continue
				}
				require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
				m, err := sink.Read(buf)
				require.NoError(t, err)
				require.Equal(t, f[addrLen:], buf[:m], "frame %d", i)
			}
		})
	}

	require.NoError(t, a.b.Close())
	_, err = newDriver(a.b, nil).WriteFrames([][]byte{frame})
	assert.ErrorIs(t, err, net.ErrClosed)
}

// TestSendLanes sends 64 flows to a peer that receives on some lanes. Each
// lane sends from its own UDP port, and the peer opens the packets of all
// lanes.
func TestSendLanes(t *testing.T) {
	const flows = 64
	cases := []struct {
		name     string
		lanes    int
		sockets  int // Lane sockets of the peer. Zero is all.
		batch    bool
		noSocket int // A lane whose socket closes before the send. Zero is none.
		ports    int
	}{
		{name: "one lane", lanes: 1, batch: true, ports: 1},
		{name: "4 lanes", lanes: 4, batch: true, ports: 4},
		{name: "4 lanes, one write for each packet", lanes: 4, ports: 4},
		{name: "lane with no socket sends on lane 0", lanes: 4, batch: true, noSocket: 2, ports: 3},
		{name: "peer with no lane sockets", lanes: 4, sockets: 1, batch: true, ports: 1},
		{name: "peer with 2 lane sockets", lanes: 4, sockets: 2, batch: true, ports: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairLanes(t, 0, tc.lanes)
			sent := tc.lanes
			if tc.sockets > 0 {
				a.peer.SetLaneSockets(tc.sockets)
				sent = tc.sockets
			}
			offer(t, time.Now(), a, b)
			// Apply opens only the sockets that the peer uses.
			assert.Len(t, a.b.LaneConns(), sent-1)
			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer sink.Close()
			_ = sink.SetReadBuffer(1 << 20)
			a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
			if tc.noSocket > 0 {
				require.NoError(t, a.b.laneConns[tc.noSocket].Swap(nil).Close())
			}
			d := newDriver(a.b, nil)
			if !tc.batch {
				d.tx = nil
			}
			frames := make([][]byte, flows)
			for i := range frames {
				frames[i] = seal(a, packet(a.v4, b.v4, 17, uint16(1000+i), 9, 200))
			}
			n, err := d.WriteFrames(frames)
			require.NoError(t, err)
			require.Equal(t, flows, n)

			ports := map[uint16]uint64{}
			buf := make([]byte, 2048)
			for range flows {
				require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
				m, from, err := sink.ReadFromUDPAddrPort(buf)
				require.NoError(t, err)
				require.Equal(t, addrOf(a.tr).Addr(), from.Addr().Unmap())
				ports[from.Port()]++
				require.NotNil(t, open(b.b, buf[:m]), "the peer opens the packets of each lane")
			}
			assert.Len(t, ports, tc.ports)
			lanes := lanePacketsAt(t, a.b, flows)
			require.Len(t, lanes, sent)
			assert.Equal(t, lanes[0], ports[addrOf(a.tr).Port()], "lane 0 sends on the agent socket")
			if tc.noSocket > 0 {
				assert.Zero(t, lanes[tc.noSocket])
			}
		})
	}

	// Close stops the lane senders and closes the lane sockets.
	a, b := newPairLanes(t, 0, 2)
	offer(t, time.Now(), a, b)
	frames := make([][]byte, 16)
	for i := range frames {
		frames[i] = seal(a, packet(a.v4, b.v4, 17, uint16(1000+i), 9, 200))
	}
	d := newDriver(a.b, nil)
	_, err := d.WriteFrames(frames)
	require.NoError(t, err)
	l, c := d.lanes[1], a.b.laneConn(1)
	require.NotNil(t, l, "16 flows use lane 1")
	require.NoError(t, a.b.Close())
	select {
	case <-l.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the lane sender did not stop")
	}
	_, err = d.WriteFrames(frames)
	assert.ErrorIs(t, err, net.ErrClosed)
	_, err = c.WriteToUDPAddrPort([]byte{1}, addrOf(b.tr))
	assert.ErrorIs(t, err, net.ErrClosed)
}

// lanePacketsAt waits until the send lanes of b counted n packets, and returns
// the packets of each lane. A lane sender counts after the socket has the packets.
func lanePacketsAt(t testing.TB, b *Binding, n uint64) []uint64 {
	t.Helper()
	var lanes []uint64
	require.Eventually(t, func() bool {
		lanes = b.LanePackets()
		sum := uint64(0)
		for _, c := range lanes {
			sum += c
		}
		return sum == n
	}, 5*time.Second, time.Millisecond)
	return lanes
}

// laneFlows returns the source port of one flow from n for each of its send lanes.
func laneFlows(t testing.TB, n *node, lanes int) []uint16 {
	t.Helper()
	ports := make([]uint16, lanes)
	for found, p := 0, uint16(1000); found < lanes; p++ {
		require.Less(t, p, uint16(3000), "no flow for each lane: %v", ports)
		f := seal(n, packet(n.v4, n.other.v4, 17, p, 9, 100))
		require.NotNil(t, f)
		if ports[f[laneOff]] == 0 {
			ports[f[laneOff]] = p
			found++
		}
	}
	return ports
}

// exits fails the test when a lane sender of d runs after d closed.
func exits(t *testing.T, d *driver) {
	t.Helper()
	require.NoError(t, d.Close())
	for i, l := range d.lanes {
		if l == nil {
			continue
		}
		select {
		case <-l.exited:
		case <-time.After(5 * time.Second):
			t.Fatalf("the sender of lane %d did not stop", i)
		}
	}
}

// TestLaneOrder sends the frames of 4 flows on 4 lanes at the same time, in
// many small calls. Each lane socket sends its frames in the order of the calls.
func TestLaneOrder(t *testing.T) {
	const (
		lanes   = 4
		rounds  = 40
		calls   = 8 // More than laneBatches, so that the queue of a lane can fill.
		perCall = 4 // Frames of each lane in one call.
	)
	a, b := newPairLanes(t, 0, lanes)
	offer(t, time.Now(), a, b)
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer sink.Close()
	_ = sink.SetReadBuffer(1 << 20)
	a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
	flows := laneFlows(t, a, lanes)
	laneOf := map[uint16]int{addrOf(a.tr).Port(): 0}
	for i := 1; i < lanes; i++ {
		laneOf[a.b.laneConn(byte(i)).LocalAddr().(*net.UDPAddr).AddrPort().Port()] = i
	}

	d := newDriver(a.b, nil)
	var want [lanes][][]byte
	var got [lanes]int
	buf := make([]byte, 2048)
	for range rounds {
		// The sink has space for the frames of one round.
		for range calls {
			frames := make([][]byte, 0, lanes*perCall)
			for range perCall {
				for lane, port := range flows {
					f := seal(a, packet(a.v4, b.v4, 17, port, 9, 100))
					require.Equal(t, byte(lane), f[laneOff])
					want[lane] = append(want[lane], f[addrLen:])
					frames = append(frames, f)
				}
			}
			n, err := d.WriteFrames(frames)
			require.NoError(t, err)
			require.Equal(t, len(frames), n)
			// The driver does not keep the frames.
			for _, f := range frames {
				clear(f[:addrLen])
			}
		}
		for range calls * perCall * lanes {
			require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
			m, from, err := sink.ReadFromUDPAddrPort(buf)
			require.NoError(t, err)
			lane, ok := laneOf[from.Port()]
			require.True(t, ok, "port %d", from.Port())
			require.Less(t, got[lane], len(want[lane]))
			require.Equal(t, want[lane][got[lane]], buf[:m], "lane %d, frame %d", lane, got[lane])
			got[lane]++
		}
	}
	const each = rounds * calls * perCall
	assert.Equal(t, []uint64{each, each, each, each}, lanePacketsAt(t, a.b, lanes*each))
	assert.Zero(t, a.b.Stats().TxDrops)
	exits(t, d)
}

// TestLaneQueue fills the queue of lane 1, which has no sender. The driver
// waits and does not drop, lane 2 sends its frame, and a close ends the wait.
func TestLaneQueue(t *testing.T) {
	cases := []struct {
		name string
		// end ends the wait. Nil takes one batch from the queue of lane 1.
		end func(d *driver, n *node, l *laneSender)
		err error
		// stopped runs the sender of lane 1 after the end. It must return at once.
		stopped bool
	}{
		{name: "the lane has space again"},
		{"the driver closes", func(d *driver, _ *node, _ *laneSender) { _ = d.Close() }, net.ErrClosed, true},
		{"the binding closes", func(_ *driver, n *node, _ *laneSender) { _ = n.b.Close() }, net.ErrClosed, true},
		{"the lane sender stops", func(_ *driver, _ *node, l *laneSender) { close(l.exited) }, net.ErrClosed, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPairLanes(t, 0, 3)
			offer(t, time.Now(), a, b)
			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer sink.Close()
			a.peer.SetAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())
			flows := laneFlows(t, a, 3)
			frame := func(lane int) []byte { return seal(a, packet(a.v4, b.v4, 17, flows[lane], 9, 100)) }
			buf := make([]byte, 2048)
			read := func(want []byte) {
				t.Helper()
				require.NoError(t, sink.SetReadDeadline(time.Now().Add(5*time.Second)))
				m, err := sink.Read(buf)
				require.NoError(t, err)
				require.Equal(t, want[addrLen:], buf[:m])
			}

			// A frame of lane 2 starts the senders of lanes 0 and 2.
			d := newDriver(a.b, nil)
			defer d.Close()
			first := frame(2)
			_, err = d.WriteFrames([][]byte{first})
			require.NoError(t, err)
			read(first)
			l := d.newLane(1, nil)
			d.lanes[1] = l
			var want [][]byte
			take := func() {
				t.Helper()
				select {
				case q := <-l.work:
					require.LessOrEqual(t, len(q.frames), len(want))
					for i, f := range q.frames {
						require.Equal(t, want[i], f, "frame %d", i)
					}
					want = want[len(q.frames):]
					q.frames = q.frames[:0]
					l.free <- q
				case <-time.After(5 * time.Second):
					t.Fatal("no batch for lane 1")
				}
			}

			for range laneBatches {
				full := make([][]byte, laneFrames)
				for i := range full {
					full[i] = frame(1)
				}
				want = append(want, full...)
				n, err := d.WriteFrames(full)
				require.NoError(t, err)
				require.Equal(t, laneFrames, n)
			}
			// The queue of lane 1 is full, so the frame of lane 1 waits.
			last := [][]byte{frame(2), frame(1), frame(2)}
			want = append(want, last[1])
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			go func() {
				n, err := d.WriteFrames(last)
				done <- result{n, err}
			}()
			read(last[0])
			select {
			case r := <-done:
				t.Fatalf("the driver did not wait: %+v", r)
			case <-time.After(20 * time.Millisecond):
			}

			if tc.end == nil {
				take()
			} else {
				tc.end(d, a, l)
			}
			var r result
			select {
			case r = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the driver waits after the end")
			}
			if tc.err != nil {
				assert.ErrorIs(t, r.err, tc.err)
				assert.Zero(t, r.n)
			} else {
				require.NoError(t, r.err)
				assert.Equal(t, len(last), r.n)
				read(last[2])
				for len(want) > 0 {
					take()
				}
				assert.Zero(t, a.b.Stats().TxDrops)
			}
			if tc.stopped {
				// The sender counts the frames of its queue as drops.
				l.run(d.done)
				assert.Equal(t, uint64(laneBatches*laneFrames), a.b.Stats().TxDrops)
			}
			d.lanes[1] = nil // It has no goroutine.
			exits(t, d)
		})
	}
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

// TestTunBatch writes the packets of a batch in one call, and a full batch at once.
func TestTunBatch(t *testing.T) {
	pkt := packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 6, 1, 2, DefaultMTU)
	cases := []struct {
		name  string
		n     int
		err   error
		calls []int
		want  Stats
	}{
		{"no packets", 0, nil, nil, Stats{}},
		{"one packet", 1, nil, []int{1}, Stats{RxPackets: 1}},
		{"full batch", rxBatch, nil, []int{rxBatch}, Stats{RxPackets: rxBatch}},
		{"more than one batch", rxBatch + 3, nil, []int{rxBatch, 3}, Stats{RxPackets: rxBatch + 3}},
		{"device error", 3, errors.New("down"), []int{3}, Stats{RxDrops: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := newFakeTun(tc.n)
			dev.err = tc.err
			var b Binding
			bt := newTunBatch(&tunWriter{dev: dev}, &b.stats)
			for _, s := range bt.bufs {
				require.Equal(t, rxSlot, cap(s), "the device can coalesce into each slot")
			}
			for range tc.n {
				bt.add(pkt)
			}
			bt.flush()
			assert.Equal(t, tc.calls, dev.calls)
			assert.Equal(t, tc.want, b.Stats())
			for range tc.want.RxPackets {
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
		{"Send", true, func() {
			n, err := a.b.Send([][]byte{v4})
			require.NoError(t, err)
			require.Equal(t, 1, n)
		}, Stats{TxPackets: 1}, Stats{RxPackets: 1}, v4},
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

// TestNoRoute checks that Config.NoRoute gets the packets with no route or no
// transmit SA, and no other packets.
func TestNoRoute(t *testing.T) {
	a, b := newPair(t)
	var got [][]byte
	a.b.noRoute = func(pkt []byte) { got = append(got, bytes.Clone(pkt)) }
	far := netip.MustParseAddr("10.9.9.9")
	ok := packet(a.v4, b.v4, 17, 1, 2, 100)
	// The rows run in order: the SAs come before the second row.
	cases := []struct {
		name  string
		offer bool
		pkt   []byte
		hook  bool
		want  Stats
	}{
		{name: "no transmit SA", pkt: ok, hook: true, want: Stats{TxNoRoute: 1}},
		{name: "no route", offer: true, pkt: packet(a.v4, far, 17, 1, 2, 100), hook: true, want: Stats{TxNoRoute: 1}},
		{name: "routed", pkt: ok},
		{name: "too large", pkt: packet(a.v4, b.v4, 17, 1, 2, DefaultMTU+1), want: Stats{TxDrops: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.offer {
				offer(t, time.Now(), a, b)
			}
			got = nil
			before := a.b.Stats()
			phy := make([]byte, 2048)
			n, _ := (&driver{b: a.b}).VirtToPhy(tc.pkt, phy)
			assert.Equal(t, tc.want, sub(a.b.Stats(), before))
			if tc.hook {
				assert.Zero(t, n)
				assert.Equal(t, [][]byte{tc.pkt}, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// TestSend sends packets outside the driver to the socket of the other node.
func TestSend(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	got := &capture{}
	b.b.drv.Store(newDriver(b.b, got.deliver))
	far := netip.MustParseAddr("10.9.9.9")
	p1, p2 := packet(a.v4, b.v4, 17, 1, 2, 100), packet(a.v6, b.v6, 17, 3, 4, DefaultMTU)
	cases := []struct {
		name    string
		pkts    [][]byte
		sent    int
		err     error
		deliver [][]byte
	}{
		{name: "all", pkts: [][]byte{p1, p2}, sent: 2, deliver: [][]byte{p1, p2}},
		{name: "stops at no route", pkts: [][]byte{p1, packet(a.v4, far, 17, 1, 2, 100), p2}, sent: 1, err: ErrNoRoute, deliver: [][]byte{p1}},
		{name: "too large", pkts: [][]byte{packet(a.v4, b.v4, 17, 1, 2, DefaultMTU+1), p1}, sent: 1, deliver: [][]byte{p1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got.mu.Lock()
			got.got = nil
			got.mu.Unlock()
			sent, err := a.b.Send(tc.pkts)
			assert.Equal(t, tc.sent, sent)
			assert.Equal(t, tc.err, err)
			require.Eventually(t, func() bool {
				got.mu.Lock()
				defer got.mu.Unlock()
				return len(got.got) == len(tc.deliver)
			}, 5*time.Second, time.Millisecond)
			assert.Equal(t, tc.deliver, got.got)
		})
	}
	require.NoError(t, a.b.Close())
	_, err := a.b.Send([][]byte{p1})
	assert.ErrorIs(t, err, ErrClosed)
}

// TestDeliver gives a packet from the agent to the driver at once, while the
// TUN batch of a read keeps its packets until the batch ends.
func TestDeliver(t *testing.T) {
	a, _ := newPair(t)
	pkt, read := packet(a.v4, a.v4, 1, 0, 0, 60), packet(a.v4, a.v4, 17, 1, 2, 100)
	assert.False(t, a.b.Deliver(pkt), "no driver")
	dev := newFakeTun(2)
	w := &tunWriter{dev: dev, bufs: make([][]byte, 1), scratch: make([]byte, tunOffset+a.b.mtu)}
	d := newDriver(a.b, w.write)
	bt := newTunBatch(w, &a.b.stats)
	d.batch = bt
	a.b.drv.Store(d)
	bt.add(read)

	assert.True(t, a.b.Deliver(pkt))
	assert.Equal(t, []int{1}, dev.calls)
	assert.Equal(t, pkt, <-dev.out)
	assert.Len(t, bt.out, 1)
	assert.Equal(t, Stats{}, a.b.Stats(), "no receive counters")
	bt.flush()
	assert.Equal(t, read, <-dev.out)
}
