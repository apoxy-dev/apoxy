// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// keptWrite is one WriteKept call of a test. When the frames have no user
// left, it clears them, as a send pipe that uses its set again.
type keptWrite struct {
	k      *netstack.Kept
	frames [][]byte
	freed  atomic.Int32 // The times that the frames had no user left.
}

// writeKept gives copies of frames to d as the send pipe does: the writer is a
// user until the write returns.
func writeKept(d *driver, frames [][]byte) (*keptWrite, int, error) {
	w := &keptWrite{frames: make([][]byte, len(frames))}
	for i, f := range frames {
		w.frames[i] = bytes.Clone(f)
	}
	w.k = netstack.NewKept(func() {
		for _, f := range w.frames {
			clear(f)
		}
		w.freed.Add(1)
	})
	w.k.Keep()
	n, err := d.WriteKept(w.frames, w.k)
	w.k.Release()
	return w, n, err
}

// write gives frames to d with WriteKept, or with WriteFrames when kept is
// false. Then it returns no keptWrite.
func write(d *driver, frames [][]byte, kept bool) (*keptWrite, int, error) {
	if kept {
		return writeKept(d, frames)
	}
	n, err := d.WriteFrames(frames)
	return nil, n, err
}

// allReleased waits until the frames of each write have no user, and checks
// that each Keep of the driver had one Release.
func allReleased(t testing.TB, writes ...*keptWrite) {
	t.Helper()
	for i, w := range writes {
		if w == nil {
			continue
		}
		require.Eventually(t, func() bool { return w.freed.Load() > 0 }, 5*time.Second, time.Millisecond, "write %d keeps frames", i)
		// One more user finds the count at zero only then.
		w.k.Keep()
		w.k.Release()
		require.Equal(t, int32(2), w.freed.Load(), "write %d", i)
	}
}

// TestWriteFrames checks that a UDP socket gets the PSP packets in order, in
// batches and one by one, and that no frame is kept with no sender.
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
		for _, kept := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/kept=%t", tc.name, kept), func(t *testing.T) {
				d := fakeDriver(a.b, nil)
				if !tc.batch {
					d.tx = nil
				}
				before := a.b.Stats()
				w, n, err := write(d, tc.frames, kept)
				require.NoError(t, err)
				assert.Equal(t, len(tc.frames), n)
				if kept {
					assert.Equal(t, int32(1), w.freed.Load(), "the driver keeps frames after the write")
				}
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
	}

	require.NoError(t, a.b.Close())
	for _, kept := range []bool{false, true} {
		w, _, err := write(fakeDriver(a.b, nil), [][]byte{frame}, kept)
		assert.ErrorIs(t, err, net.ErrClosed)
		allReleased(t, w)
	}
}

// TestSendLanes sends 64 flows to a peer that receives on some lanes. Each lane
// sends from its own UDP port, and the peer opens all packets.
func TestSendLanes(t *testing.T) {
	const flows = 64
	cases := []struct {
		name     string
		lanes    int
		sockets  int // Lane sockets of the peer. Zero is all.
		batch    bool
		kept     bool // The driver gets the frames with WriteKept.
		noSocket int  // A lane whose socket closes before the send. Zero is none.
		ports    int
	}{
		{name: "one lane", lanes: 1, batch: true, ports: 1},
		{name: "4 lanes", lanes: 4, batch: true, ports: 4},
		{name: "4 lanes, one write for each packet", lanes: 4, ports: 4},
		{name: "lane with no socket sends on lane 0", lanes: 4, batch: true, noSocket: 2, ports: 3},
		{name: "peer with no lane sockets", lanes: 4, sockets: 1, batch: true, ports: 1},
		{name: "peer with 2 lane sockets", lanes: 4, sockets: 2, batch: true, ports: 2},
		{name: "4 lanes, kept frames", lanes: 4, batch: true, kept: true, ports: 4},
		{name: "4 lanes, kept frames, one write for each packet", lanes: 4, kept: true, ports: 4},
		{name: "lane with no socket sends kept frames on lane 0", lanes: 4, batch: true, kept: true, noSocket: 2, ports: 3},
		{name: "peer with no lane sockets, kept frames", lanes: 4, sockets: 1, batch: true, kept: true, ports: 1},
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
			d := fakeDriver(a.b, nil)
			if !tc.batch {
				d.tx = nil
			}
			frames := make([][]byte, flows)
			for i := range frames {
				frames[i] = seal(a, packet(a.v4, b.v4, 17, uint16(1000+i), 9, 200))
			}
			w, n, err := write(d, frames, tc.kept)
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
			allReleased(t, w)
		})
	}
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

// TestLaneOrder checks that each of 4 lane sockets sends its frames in the
// order of many small calls, for copied and for kept frames.
func TestLaneOrder(t *testing.T) {
	const (
		lanes   = 4
		rounds  = 40
		calls   = 8 // More than laneBatches, so that the queue of a lane can fill.
		perCall = 4 // Frames of each lane in one call.
	)
	for _, kept := range []bool{false, true} {
		t.Run(fmt.Sprintf("kept=%t", kept), func(t *testing.T) {
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

			d := fakeDriver(a.b, nil)
			var want [lanes][][]byte
			var got [lanes]int
			var writes []*keptWrite
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
					w, n, err := write(d, frames, kept)
					require.NoError(t, err)
					require.Equal(t, len(frames), n)
					writes = append(writes, w)
					// The driver does not keep the frames of WriteFrames.
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
			allReleased(t, writes...)
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
	pa, pb := peerconn.New(qa), peerconn.New(qb)
	t.Cleanup(func() { _ = pa.Close(); _ = pb.Close() })
	pb.HandleData(b.l)
	got := &capture{}
	b.b.drv.Store(fakeDriver(b.b, got.deliver))

	d := fakeDriver(a.b, nil)
	send := func(pkt []byte, kept bool) func() {
		return func() {
			phy := make([]byte, 2048)
			if n, _ := d.VirtToPhy(pkt, phy); n > 0 {
				w, _, err := write(d, [][]byte{phy[:n]}, kept)
				require.NoError(t, err)
				if kept {
					require.Equal(t, int32(1), w.freed.Load(), "the driver keeps a data frame after the write")
				}
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
		{"IPv4", true, send(v4, false), Stats{TxPackets: 1}, Stats{RxPackets: 1}, v4},
		{"IPv6 MTU-size", true, send(v6, false), Stats{TxPackets: 1}, Stats{RxPackets: 1}, v6},
		{"IPv4, kept frame", true, send(v4, true), Stats{TxPackets: 1}, Stats{RxPackets: 1}, v4},
		{"IPv6 MTU-size, kept frame", true, send(v6, true), Stats{TxPackets: 1}, Stats{RxPackets: 1}, v6},
		{"no route", true, send(packet(a.v4, far, 17, 1, 2, 100), false), Stats{TxNoRoute: 1}, Stats{}, nil},
		{"other VNI", true, raw(testVNI+1, v4), Stats{}, Stats{RxDrops: 1}, nil},
		{"source not routed", true, raw(testVNI, packet(far, b.v4, 17, 1, 2, 100)), Stats{}, Stats{RxDrops: 1}, nil},
		{"Send", true, func() {
			n, err := a.b.Send([][]byte{v4})
			require.NoError(t, err)
			require.Equal(t, 1, n)
		}, Stats{TxPackets: 1}, Stats{RxPackets: 1}, v4},
		{"PSP again, no SA", false, send(v4, false), Stats{TxNoRoute: 1}, Stats{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.quic {
				require.NoError(t, a.peer.UseQUIC(pa))
			} else {
				require.NoError(t, a.peer.UseQUIC(nil))
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

// TestPeerQUIC checks which relay session gets the data frame of a packet: the
// session of the peer that routes it, after Peer.UseQUIC.
func TestPeerQUIC(t *testing.T) {
	a, b := newPair(t)
	qa1, qb1 := quicPair(t, a.tr, b.tr)
	qb2, qa2 := quicPair(t, b.tr, a.tr)
	type frames struct {
		mu  sync.Mutex
		got [][]byte
	}
	var onPeer, onOther frames
	conn := func(qa, qb *quic.Conn, f *frames) *peerconn.Conn {
		pa, pb := peerconn.New(qa), peerconn.New(qb)
		t.Cleanup(func() { _ = pa.Close(); _ = pb.Close() })
		pb.HandleData(handlerFunc(func(frame []byte) {
			_, inner, err := peerconn.DecodeData(frame)
			f.mu.Lock()
			defer f.mu.Unlock()
			if err == nil {
				f.got = append(f.got, bytes.Clone(inner))
			}
		}))
		return pa
	}
	ofPeer, ofOther := conn(qa1, qb1, &onPeer), conn(qa2, qb2, &onOther)
	far := netip.MustParseAddr("10.9.9.9")
	other, err := a.l.AddRelay(netip.MustParseAddrPort("192.0.2.1:1"))
	require.NoError(t, err)
	require.NoError(t, a.b.AddRoute(netip.PrefixFrom(far, 32), other))
	toPeer, toOther := packet(a.v4, b.v4, 17, 1, 2, 500), packet(a.v4, far, 17, 1, 2, 500)

	cases := []struct {
		name        string
		peer, other *peerconn.Conn // Session of UseQUIC of the peer and of the other peer.
		pkt         []byte
		want        *frames // Session that gets the data frame. Nil is none.
		tx          Stats
	}{
		{name: "session of the peer", peer: ofPeer, pkt: toPeer, want: &onPeer, tx: Stats{TxPackets: 1}},
		{name: "other peer has no session, and no SA", peer: ofPeer, pkt: toOther},
		{name: "two sessions, packet of the peer", peer: ofPeer, other: ofOther, pkt: toPeer, want: &onPeer, tx: Stats{TxPackets: 1}},
		{name: "two sessions, packet of the other peer", peer: ofPeer, other: ofOther, pkt: toOther, want: &onOther, tx: Stats{TxPackets: 1}},
		{name: "session of the peer ended, and no SA", other: ofOther, pkt: toPeer},
		{name: "no session, and no SA", pkt: toPeer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, a.peer.UseQUIC(tc.peer))
			require.NoError(t, other.UseQUIC(tc.other))
			assert.Equal(t, tc.peer != nil || tc.other != nil, a.b.quicPath())
			for _, f := range []*frames{&onPeer, &onOther} {
				f.mu.Lock()
				f.got = nil
				f.mu.Unlock()
			}
			before := a.b.Stats()
			_, err := a.b.Send([][]byte{tc.pkt})
			if tc.want == nil {
				// The packet goes as a PSP packet, and the peer has no SA.
				assert.ErrorIs(t, err, ErrNoRoute)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.tx, sub(a.b.Stats(), before))
			count := func(f *frames) int {
				f.mu.Lock()
				defer f.mu.Unlock()
				return len(f.got)
			}
			if tc.want != nil {
				require.Eventually(t, func() bool { return count(tc.want) == 1 }, 5*time.Second, time.Millisecond)
				tc.want.mu.Lock()
				assert.Equal(t, tc.pkt, tc.want.got[0])
				tc.want.mu.Unlock()
			}
			// A frame on the wrong session arrives in this time too.
			time.Sleep(20 * time.Millisecond)
			for _, f := range []*frames{&onPeer, &onOther} {
				if f != tc.want {
					assert.Zero(t, count(f), "frames on the other session")
				}
			}
		})
	}

	t.Run("many sessions", func(t *testing.T) {
		require.NoError(t, other.UseQUIC(nil))
		// More sessions than a one-byte slot index has.
		const n = 300
		var peers []*Peer
		for i := range n {
			p, err := a.l.AddRelay(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), uint16(1+i)))
			require.NoError(t, err)
			require.NoError(t, p.UseQUIC(ofPeer))
			peers = append(peers, p)
		}
		last := peers[n-1]
		require.NoError(t, last.UseQUIC(ofOther))
		toLast := packet(a.v4, netip.MustParseAddr("10.9.9.10"), 17, 1, 2, 500)
		require.NoError(t, a.b.AddRoute(netip.MustParsePrefix("10.9.9.10/32"), last))
		onOther.mu.Lock()
		onOther.got = nil
		onOther.mu.Unlock()
		_, err := a.b.Send([][]byte{toLast})
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			onOther.mu.Lock()
			defer onOther.mu.Unlock()
			return len(onOther.got) == 1
		}, 5*time.Second, time.Millisecond, "the session of the last peer gets the frame")
		// A peer that is removed gives its session back.
		a.b.RemovePeer(peers[0])
		require.ErrorIs(t, peers[0].UseQUIC(ofPeer), ErrClosed)
		for _, p := range peers[1:] {
			a.b.RemovePeer(p)
		}
		require.NoError(t, a.peer.UseQUIC(nil))
		assert.False(t, a.b.quicPath())
	})
}

// TestHandleDataConcurrent gives data frames to a tun driver from the links of several relay
// sessions at once. One goroutine reads each link, as the session reader does.
func TestHandleDataConcurrent(t *testing.T) {
	_, b := newPair(t)
	const links, frames = 4, 200
	dev := newFakeTun(links * frames)
	td, err := b.b.Tun(dev)
	require.NoError(t, err)
	defer td.Close()
	var wg sync.WaitGroup
	for r := range links {
		l, err := b.b.AddLink()
		require.NoError(t, err)
		relay, err := l.AddRelay(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(1+r)))
		require.NoError(t, err)
		src := netip.AddrFrom4([4]byte{10, 5, 0, byte(1 + r)})
		require.NoError(t, b.b.AddRoute(netip.PrefixFrom(src, 32), relay))
		wg.Go(func() {
			for i := range frames {
				l.HandleData(peerconn.EncodeData(nil, testVNI, packet(src, b.v4, 17, uint16(r), uint16(i), 100+i)))
				if i%16 == 15 {
					l.BatchEnd()
				}
			}
			l.BatchEnd()
		})
	}
	wg.Wait()
	assert.Equal(t, Stats{RxPackets: links * frames}, b.b.Stats())
	assert.Len(t, dev.out, links*frames)
}

// relayOf adds a relay to the link of n at the socket of the other node, with
// default routes and SAs from the other node.
func relayOf(t *testing.T, n *node) *Peer {
	t.Helper()
	r, err := n.l.AddRelay(addrOf(n.other.tr))
	require.NoError(t, err)
	for _, pfx := range []string{"0.0.0.0/0", "::/0"} {
		require.NoError(t, n.b.AddRoute(netip.MustParsePrefix(pfx), r))
	}
	rx, err := n.other.l.AddRelay(addrOf(n.tr))
	require.NoError(t, err)
	req, err := rx.Offer(time.Now())
	require.NoError(t, err)
	_, err = r.Apply(req, time.Now())
	require.NoError(t, err)
	return r
}

// TestRelayRoutes checks the send routes of a link with two relays: a packet
// goes to the relay with the longest prefix of its destination.
func TestRelayRoutes(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	r := relayOf(t, a)
	far := netip.MustParseAddr("10.9.9.9")
	host := netip.PrefixFrom(b.v4, 32)
	steps := []struct {
		name string
		do   func()
		dst  netip.Addr
		want *Peer
	}{
		{name: "host route", dst: b.v4, want: a.peer},
		{name: "default route", dst: far, want: r},
		{name: "host route removed", do: func() { a.b.RemoveRoute(host, a.peer) }, dst: b.v4, want: r},
		{name: "host route of the other relay", do: func() { require.NoError(t, a.b.AddRoute(host, r)) }, dst: b.v4, want: r},
		{name: "relay removed", do: func() { a.b.RemovePeer(r) }, dst: b.v6, want: a.peer},
	}
	for _, st := range steps {
		if st.do != nil {
			st.do()
		}
		pkt := packet(a.v4, st.dst, 17, 1, 2, 100)
		if st.dst.Is6() {
			pkt = packet(a.v6, st.dst, 17, 1, 2, 100)
		}
		var f netstack.TxFrame
		require.NoError(t, a.b.prepare(pkt, &f), st.name)
		sa, _ := st.want.txSA(pkt)
		assert.Same(t, sa, f.SA, st.name)
	}
}

// TestSend sends packets outside the driver to the socket of the other node.
func TestSend(t *testing.T) {
	a, b := newPair(t)
	offer(t, time.Now(), a, b)
	got := &capture{}
	b.b.drv.Store(fakeDriver(b.b, got.deliver))
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
