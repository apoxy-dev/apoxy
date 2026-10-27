// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/atoonk/packetio"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/softpsp/psp"

	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// fakeRxFrame is the frame size of a fakeRx, and fakeRxHeadroom the room in front of each received
// frame, as with AF_XDP.
const fakeRxFrame, fakeRxHeadroom = 2048, 256

// fakeRx is a packetio.RxQueue and the NIC side of its rings. wire puts frames from the wire into
// the frames of the fill ring.
type fakeRx struct {
	mu    sync.Mutex
	mem   []byte
	ring  int             // The size of the fill ring.
	free  []packetio.Desc // The pool.
	fill  []packetio.Desc // On the fill ring.
	ready []packetio.Desc // Received, and not taken by Receive yet.
	out   []packetio.Desc
	lost  int // Wire frames with no frame on the fill ring.
	wake  chan struct{}
}

// newFakeRx returns a fakeRx with all its frames on the fill ring, so that a frame from the wire
// does not wait for the first Fill.
func newFakeRx(frames int) *fakeRx {
	f := &fakeRx{mem: make([]byte, frames*fakeRxFrame), ring: frames, wake: make(chan struct{}, 1)}
	for i := range frames {
		f.fill = append(f.fill, packetio.Desc{Addr: uint64(i * fakeRxFrame)})
	}
	return f
}

// wire receives frames from the wire, each into a frame of the fill ring.
func (f *fakeRx) wire(frames ...[]byte) {
	f.mu.Lock()
	for _, b := range frames {
		if len(f.fill) == 0 {
			f.lost++
			continue
		}
		d := packetio.Desc{Addr: f.fill[0].Addr + fakeRxHeadroom}
		f.fill = f.fill[1:]
		d.Len = uint32(copy(f.mem[d.Addr:d.Addr-fakeRxHeadroom+fakeRxFrame], b))
		f.ready = append(f.ready, d)
	}
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// queued returns the frames that the queue has: in the pool, on the fill ring and received. The
// other frames are at the device.
func (f *fakeRx) queued() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.free) + len(f.fill) + len(f.ready)
}

func (f *fakeRx) Region() packetio.Region { return fakeRxRegion{f} }

func (f *fakeRx) Fill(n int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n = min(n, len(f.free), f.ring-len(f.fill))
	f.fill = append(f.fill, f.free[len(f.free)-n:]...)
	f.free = f.free[:len(f.free)-n]
	return n
}

func (f *fakeRx) Poll(timeout time.Duration) (int, error) {
	if n := f.NumReceived(); n > 0 || timeout == 0 {
		return n, nil
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-f.wake:
	case <-t.C:
	}
	return f.NumReceived(), nil
}

func (f *fakeRx) Receive(max int) []packetio.Desc {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := min(max, len(f.ready))
	f.out = append(f.out[:0], f.ready[:n]...)
	f.ready = f.ready[n:]
	return f.out
}

func (f *fakeRx) Recycle(descs []packetio.Desc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range descs {
		f.free = append(f.free, packetio.Desc{Addr: d.Addr - d.Addr%fakeRxFrame})
	}
}

func (f *fakeRx) Err() error { return nil }

func (f *fakeRx) NumFreeFillSlots() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ring - len(f.fill)
}

func (f *fakeRx) NumReceived() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ready)
}

func (f *fakeRx) NumFreeFrames() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.free)
}

func (f *fakeRx) Stats() (packetio.RxStats, error) { return packetio.RxStats{}, nil }
func (f *fakeRx) Close() error                     { return nil }

type fakeRxRegion struct{ f *fakeRx }

func (r fakeRxRegion) Bytes() []byte                { return r.f.mem }
func (r fakeRxRegion) Frame(d packetio.Desc) []byte { return r.f.mem[d.Addr : d.Addr+uint64(d.Len)] }
func (r fakeRxRegion) FrameSize() int               { return fakeRxFrame }
func (r fakeRxRegion) NumFrames() int               { return len(r.f.mem) / fakeRxFrame }
func (r fakeRxRegion) Writable(d packetio.Desc) []byte {
	return r.f.mem[d.Addr : d.Addr-d.Addr%fakeRxFrame+fakeRxFrame]
}

// fakeQueues is a packetio.Device on fake TX and RX queues.
type fakeQueues struct {
	tx []*fakeTx
	rx []*fakeRx
}

func (d fakeQueues) Capabilities() packetio.Capabilities { return packetio.Capabilities{} }
func (d fakeQueues) NumTxQueues() int                    { return len(d.tx) }
func (d fakeQueues) NumRxQueues() int                    { return len(d.rx) }
func (d fakeQueues) TxQueue(i int) packetio.TxQueue      { return d.tx[i] }
func (d fakeQueues) RxQueue(i int) packetio.RxQueue      { return d.rx[i] }
func (d fakeQueues) Close() error                        { return nil }

// The agents of the engine tests: A1 (port 1) and A3 (port 3) send to A2 (port 2) at fakePeer, which
// has a static MAC. A2 is at port 1000, so that demux reads the frames that the relay sends to it.
var (
	engA1 = netip.MustParseAddrPort("10.99.0.3:4000")
	engA3 = netip.MustParseAddrPort("10.99.0.4:4000")
	engA2 = netip.AddrPortFrom(fakePeer.Addr(), PortData)
)

const (
	engSPIA1, engSPIA3, engSPIA2 = 0x101, 0x301, 0x211
	engOutCell                   = 32
	engInner                     = 100 // The size of an inner packet.
)

func engKey(spi uint32) []byte { return binary.BigEndian.AppendUint32(make([]byte, 12), spi) }

func keysUpdate(typ p4.Update_Type, dir dpv1.PspSaDirection, spi uint32, port uint64) *p4.Update {
	x, err := KeysEntry(&dpv1.PspSaEntry{Direction: dir, Spi: spi, Key: engKey(spi), Port: port, Session: 1})
	if err != nil {
		panic(err)
	}
	return &p4.Update{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: x}}}
}

func rxKeys(spi uint32, port uint64) *p4.Update {
	return keysUpdate(p4.Update_INSERT, dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, spi, port)
}

func tableUpdate(e *p4.TableEntry) *p4.Update {
	return &p4.Update{Type: p4.Update_INSERT, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}}}
}

func writeAll(t *testing.T, p *Pipeline, us ...*p4.Update) error {
	t.Helper()
	return p.Write(t.Context(), &p4.WriteRequest{Atomicity: p4.WriteRequest_DATAPLANE_ATOMIC, Updates: us})
}

// engTables are the tables of A1, A2 and A3.
func engTables() []*p4.Update {
	return []*p4.Update{
		tableUpdate(PortsKey{Port: 1}.Entry(PortAction{Session: 1, Addr: engA1, MTU: 1400, MeterIndex: 1})),
		tableUpdate(PortsKey{Port: 2}.Entry(PortAction{Session: 1, Addr: engA2, MTU: 1400, MeterIndex: 2})),
		tableUpdate(PortsKey{Port: 3}.Entry(PortAction{Session: 1, Addr: engA3, MTU: 1400, MeterIndex: 3})),
		tableUpdate(ClassifyKey{Port: 1, Session: 1}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: 1})),
		tableUpdate(ClassifyKey{Port: 3, Session: 1}.Entry(ContextAction{VPC: "uid-a/1", VNI: 100, Cell: 3})),
		tableUpdate(SourceKey{Port: 1, Session: 1, Src: netip.MustParsePrefix("100.64.1.0/24")}.Entry(NoAction{})),
		tableUpdate(SourceKey{Port: 3, Session: 1, Src: netip.MustParsePrefix("100.64.3.0/24")}.Entry(NoAction{})),
		tableUpdate(RouteKey{VPC: "uid-a/1", Dst: netip.MustParsePrefix("100.64.2.0/24")}.Entry(ForwardAction{Port: 2, Cell: engOutCell, LocalPort: 2, LocalCell: engOutCell})),
		rxKeys(engSPIA1, 1),
		rxKeys(engSPIA3, 3),
		keysUpdate(p4.Update_INSERT, dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, engSPIA2, 2),
	}
}

// engine is a device on fake queues with the tables of A1, A2 and A3.
type engine struct {
	*Device
	txs  []*fakeTx
	rxs  []*fakeRx
	stop func() error // Stops Run and returns its error. nil before start.
}

// newEngine opens a device on nTx fake TX queues of txFrames frames of 256 bytes, and nRx fake RX
// queues, with an IPv4 and an IPv6 own address.
func newEngine(t *testing.T, nTx, nRx, txFrames int) *engine {
	t.Helper()
	return newEngineSize(t, nTx, nRx, txFrames, 256)
}

// newEngineSize is newEngine with TX frames of size bytes.
func newEngineSize(t *testing.T, nTx, nRx, txFrames, size int) *engine {
	t.Helper()
	e := &engine{}
	var ports []txPort
	for range nTx {
		f := newFakeTxSize(txFrames, txFrames, size)
		e.txs, ports = append(e.txs, f), append(ports, f.port())
	}
	for range nRx {
		e.rxs = append(e.rxs, newFakeRx(256))
	}
	ifc := Interface{Name: "fake0", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Own: []netip.Prefix{fakeOwn, fakeOwn6}}
	d, err := newDevice(ifc, fakeQueues{tx: e.txs, rx: e.rxs}, ports, 1500, emptyImpair{}, goAEAD{})
	require.NoError(t, err)
	e.Device = d
	t.Cleanup(func() {
		if e.stop == nil {
			d.ns.close() // Run closes it.
		}
	})
	require.Nil(t, d.ns.s.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpipAddr(fakePeer.Addr()), fakePeerMAC))
	require.Nil(t, d.ns.s.AddStaticNeighbor(nicID, ipv6.ProtocolNumber, tcpipAddr(fakePeer6.Addr()), fakePeerMAC))
	require.NoError(t, writeAll(t, d.p, engTables()...))
	return e
}

// start runs the device until the test ends or stop.
func (e *engine) start(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	var once sync.Once
	var err error
	e.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				err = errors.New("run did not stop")
			}
		})
		return err
	}
	t.Cleanup(func() { assert.NoError(t, e.stop()) })
}

// inner returns an IPv4 packet from src to 100.64.2.5 with mark in byte 20.
func inner(src string, mark byte) []byte {
	b := make([]byte, engInner)
	b[0], b[9] = 0x45, 17
	binary.BigEndian.PutUint16(b[2:], engInner)
	s := netip.MustParseAddr(src).As4()
	copy(b[12:], s[:])
	copy(b[16:], []byte{100, 64, 2, 5})
	b[20] = mark
	return b
}

// sealIn returns a PSP packet of spi with sequence number seq of inner, as the agent makes it.
func sealIn(t *testing.T, spi, seq uint32, inner []byte) []byte {
	t.Helper()
	a, err := psp.NewAEAD(engKey(spi))
	require.NoError(t, err)
	out := make([]byte, len(inner)+psp.Overhead)
	n, err := psp.Seal(a, psp.Header{Version: psp.AESGCM128, SPI: spi, IV: uint64(seq), VNI: 100, Flags: psp.FlagSeq, Seq: seq}, out, inner)
	require.NoError(t, err)
	return out[:n]
}

// agentFrame returns the frame of a PSP packet from agent A1 or A3 to the relay at port 1000.
func agentFrame(t *testing.T, from netip.AddrPort, seq uint32, mark byte) []byte {
	t.Helper()
	spi, src := uint32(engSPIA1), "100.64.1.5"
	if from == engA3 {
		spi, src = engSPIA3, "100.64.3.5"
	}
	frame := make([]byte, 1500)
	n := encodeUDP(frame, fakePeerMAC, "\x02\x00\x00\x00\x00\x01", from, netip.AddrPortFrom(fakeOwn.Addr(), PortData), 0, sealIn(t, spi, seq, inner(src, mark)))
	require.NotZero(t, n)
	return frame[:n]
}

// working waits until worker w of e took an item and is in its part: it took TX frames.
func (e *engine) working(t *testing.T, w, frames int) {
	t.Helper()
	require.Eventually(t, func() bool { return e.txs[w].NumFreeFrames() == 64-frames }, 2*time.Second, time.Millisecond,
		"worker %d takes the item", w)
}

// portDrops returns the port_drops indexes of d that are not zero.
func portDrops(d *Device) []int {
	var out []int
	for i := range d.p.portDrops {
		if d.p.portDrops[i].packets.Load() != 0 {
			out = append(out, i)
		}
	}
	return out
}

// openPSP opens the PSP packet pkt of an inner IP packet in place with the softpsp code of the
// agent: ParseTrunkHeader, then OpenInPlace, which also checks Next Header. It returns the header
// and the inner packet.
func openPSP(t *testing.T, a cipher.AEAD, pkt []byte) (psp.Header, []byte) {
	t.Helper()
	h, err := psp.ParseTrunkHeader(pkt)
	require.NoError(t, err)
	p, err := psp.OpenInPlace(a, pkt)
	require.NoError(t, err)
	return h, p
}

// openToA2 opens a copy of a PSP packet that the relay sealed for A2 with the key a, checks its
// header, and returns the header and the inner packet. The caller checks the sequence number.
func openToA2(t *testing.T, a cipher.AEAD, payload []byte) (psp.Header, []byte) {
	t.Helper()
	h, p := openPSP(t, a, bytes.Clone(payload))
	assert.Equal(t, psp.Header{
		NextHdr: psp.NextHdrV4, Version: psp.AESGCM128, SPI: engSPIA2, IV: uint64(h.Seq), VNI: 100,
		Flags: psp.FlagSeq, Seq: h.Seq,
	}, h, "the PSP header to A2")
	return h, p
}

// openedInners opens the frames that the relay sent to A2 and returns the inner packet and the
// sequence number of each.
func openedInners(t *testing.T, frames [][]byte) (inners [][]byte, seqs []uint32) {
	t.Helper()
	a, err := psp.NewAEAD(engKey(engSPIA2))
	require.NoError(t, err)
	for _, frame := range frames {
		to, dg := demux(frame, func(a netip.Addr) bool { return a == engA2.Addr() })
		require.Equal(t, toPipeline, to)
		h, p := openToA2(t, a, dg.payload)
		inners, seqs = append(inners, p), append(seqs, h.Seq)
	}
	return inners, seqs
}

// TestSteering checks the steering map of each Write: a new port session goes to the worker with
// the fewest port sessions, on equal counts the lowest; a rekey keeps the worker; a removed port
// session gives its place back; a failed Write changes nothing.
func TestSteering(t *testing.T) {
	del := func(spi uint32, port uint64) *p4.Update {
		return keysUpdate(p4.Update_DELETE, dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, spi, port)
	}
	type step struct {
		updates []*p4.Update
		fail    bool
		want    steerMap
	}
	cases := []struct {
		name    string
		workers int
		steps   []step
	}{
		{name: "fewest sessions, ties to the lowest worker", workers: 3, steps: []step{
			{updates: []*p4.Update{rxKeys(0x401, 4), rxKeys(0x101, 1), rxKeys(0x301, 3), rxKeys(0x201, 2)},
				want: steerMap{0x101: 0, 0x201: 1, 0x301: 2, 0x401: 0}},
			{updates: []*p4.Update{rxKeys(0x501, 5)}, want: steerMap{0x101: 0, 0x201: 1, 0x301: 2, 0x401: 0, 0x501: 1}},
		}},
		{name: "a rekey keeps the worker", workers: 2, steps: []step{
			{updates: []*p4.Update{rxKeys(0x101, 1), rxKeys(0x201, 2)}, want: steerMap{0x101: 0, 0x201: 1}},
			{updates: []*p4.Update{rxKeys(0x202, 2)}, want: steerMap{0x101: 0, 0x201: 1, 0x202: 1}},
			{updates: []*p4.Update{del(0x201, 2)}, want: steerMap{0x101: 0, 0x202: 1}},
		}},
		{name: "a removed session gives its place back", workers: 2, steps: []step{
			{updates: []*p4.Update{rxKeys(0x101, 1), rxKeys(0x201, 2)}, want: steerMap{0x101: 0, 0x201: 1}},
			{updates: []*p4.Update{del(0x101, 1)}, want: steerMap{0x201: 1}},
			{updates: []*p4.Update{rxKeys(0x301, 3)}, want: steerMap{0x201: 1, 0x301: 0}},
		}},
		{name: "a failed write changes nothing", workers: 2, steps: []step{
			{updates: []*p4.Update{rxKeys(0x101, 1)}, want: steerMap{0x101: 0}},
			{updates: []*p4.Update{rxKeys(0x201, 2), del(0x999, 9)}, fail: true, want: steerMap{0x101: 0}},
			{updates: []*p4.Update{rxKeys(0x301, 3)}, want: steerMap{0x101: 0, 0x301: 1}},
		}},
		{name: "one worker", workers: 1, steps: []step{
			{updates: []*p4.Update{rxKeys(0x101, 1), rxKeys(0x201, 2)}, want: steerMap{0x101: 0, 0x201: 0}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(nil, goAEAD{})
			p.setWorkers(tc.workers)
			for i, s := range tc.steps {
				before := p.steering.Load()
				err := writeAll(t, p, s.updates...)
				require.Equal(t, s.fail, err != nil, "step %d: %v", i, err)
				if s.fail {
					assert.Same(t, before, p.steering.Load(), "step %d: the map of a failed write", i)
				}
				require.NotNil(t, p.steering.Load(), "step %d", i)
				assert.Equal(t, s.want, *p.steering.Load(), "step %d", i)
			}
		})
	}
	t.Run("no workers", func(t *testing.T) {
		p := New(nil, goAEAD{})
		require.NoError(t, writeAll(t, p, rxKeys(0x101, 1)))
		assert.Nil(t, p.steering.Load())
	})
}

// TestSteerTurn checks the worker of each packet of a turn: the worker of its SPI in the map, else
// the default worker. Before a packet goes to the default worker, the RX goroutine reads the map
// one more time.
func TestSteerTurn(t *testing.T) {
	spi := func(s uint32) []byte { return binary.BigEndian.AppendUint32([]byte{0, 0, 0, 0}, s) }
	cases := []struct {
		name    string
		turn    *steerMap // The map that the RX goroutine read after the frames of the turn.
		now     *steerMap // The map of the pipeline at the handoff.
		payload []byte
		worker  int
	}{
		{name: "an SPI in the map", turn: &steerMap{0x201: 2}, now: &steerMap{0x201: 2}, payload: spi(0x201), worker: 2},
		{name: "an SPI that is not in the map", turn: &steerMap{0x201: 2}, now: &steerMap{0x201: 2}, payload: spi(0x301), worker: defaultWorker},
		{name: "no map", payload: spi(0x201), worker: defaultWorker},
		{name: "a short payload", turn: &steerMap{0x201: 2}, now: &steerMap{0x201: 2}, payload: []byte{1, 2, 3}, worker: defaultWorker},
		{name: "a worker that the device does not have", turn: &steerMap{0x201: 7}, now: &steerMap{0x201: 7}, payload: spi(0x201), worker: defaultWorker},
		{name: "a new SPI after the read of the turn", turn: &steerMap{}, now: &steerMap{0x201: 1}, payload: spi(0x201), worker: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, 3, 1, 8)
			e.p.steering.Store(tc.now)
			h := e.newRxHandoff()
			h.pend = append(h.pend, rxPending{pkt: RxPacket{Payload: tc.payload}, desc: packetio.Desc{Addr: 1}})
			free := e.handoff(h, tc.turn, nil)
			assert.Empty(t, free, "no drop")
			for w, wk := range e.workers {
				if w == tc.worker {
					require.Len(t, wk.in, 1, "worker %d", w)
					it := <-wk.in
					assert.Equal(t, []packetio.Desc{{Addr: 1}}, it.descs)
				} else {
					assert.Empty(t, wk.in, "worker %d", w)
				}
			}
		})
	}
}

// TestHandoffDrops checks the two drops of the handoff, with the workers stopped. An item over the
// frame allowance of its RX queue drops (worker_allowance), else an item with no room in the
// channel of its worker drops (worker_full). Each packet of the item counts with its size, with no
// port_drops, and its frames go back at once. The other items go to their workers.
func TestHandoffDrops(t *testing.T) {
	// The turn has three packets of A1 for worker 1 and one of A3 for worker 0. The handoff gives
	// the item of worker 0 first.
	cases := []struct {
		name      string
		out       int  // The frames of the RX queue at the workers before the turn.
		full      bool // The channel of worker 1 is full.
		allowance int  // Packets that drop worker_allowance.
		full1     int  // Packets that drop worker_full.
		given     int  // Items that go to worker 1.
	}{
		{name: "room", out: 0, given: 1},
		{name: "the allowance, exactly", out: frameAllowance - 4, given: 1},
		{name: "over the allowance", out: frameAllowance - 3, allowance: 3},
		{name: "a full worker", full: true, full1: 3},
		{name: "over the allowance and a full worker", out: frameAllowance - 1, full: true, allowance: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, 2, 1, 8)
			e.p.steering.Store(&steerMap{engSPIA1: 1, engSPIA3: 0})
			if tc.full {
				for range workerQueue {
					e.workers[1].in <- &workItem{}
				}
			}
			h := e.newRxHandoff()
			h.out = tc.out
			var want []packetio.Desc
			for i := range 3 {
				d := packetio.Desc{Addr: uint64(i)}
				h.pend = append(h.pend, rxPending{pkt: RxPacket{Payload: sealIn(t, engSPIA1, uint32(i+1), inner("100.64.1.5", 0))}, desc: d})
				want = append(want, d)
			}
			h.pend = append(h.pend, rxPending{pkt: RxPacket{Payload: sealIn(t, engSPIA3, 1, inner("100.64.3.5", 0))}, desc: packetio.Desc{Addr: 9}})
			free := e.handoff(h, e.p.steering.Load(), nil)

			size := engInner + psp.Overhead
			if tc.given == 0 {
				assert.Equal(t, want, free, "the frames of the dropped item")
			} else {
				assert.Empty(t, free)
			}
			assert.Equal(t, tc.allowance, counted(e.Device, ReasonWorkerAllowance), "worker_allowance")
			assert.Equal(t, uint64(tc.allowance*size), e.p.drops[ReasonWorkerAllowance].bytes.Load(), "worker_allowance bytes")
			assert.Equal(t, tc.full1, counted(e.Device, ReasonWorkerFull), "worker_full")
			assert.Equal(t, uint64(tc.full1*size), e.p.drops[ReasonWorkerFull].bytes.Load(), "worker_full bytes")
			assert.Empty(t, portDrops(e.Device), "port_drops")
			assert.Len(t, h.outs[0].given, 1, "items at worker 0")
			assert.Len(t, h.outs[1].given, tc.given, "items at worker 1")
			assert.Equal(t, tc.out+1+3*tc.given, h.out, "frames at the workers")
		})
	}
}

// TestRxOutRead checks that the RX goroutine takes back the frames of the done items at the head
// only, oldest first.
func TestRxOutRead(t *testing.T) {
	item := func(addrs ...uint64) *workItem {
		it := &workItem{}
		for _, a := range addrs {
			it.descs = append(it.descs, packetio.Desc{Addr: a})
			it.rx = append(it.rx, RxPacket{})
		}
		return it
	}
	cases := []struct {
		name   string
		done   []bool // Of each item.
		back   []uint64
		frames int
		left   int // Items that stay at the worker.
	}{
		{name: "none done", done: []bool{false, false, false}, left: 3},
		{name: "a done item after one that is not done", done: []bool{false, true, false}, left: 3},
		{name: "the oldest done", done: []bool{true, false, true}, back: []uint64{1, 2}, frames: 2, left: 2},
		{name: "all done", done: []bool{true, true, true}, back: []uint64{1, 2, 3, 4, 5}, frames: 5, left: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &rxOut{given: []*workItem{item(1, 2), item(3), item(4, 5)}}
			for i, d := range tc.done {
				o.given[i].done.Store(d)
			}
			back, frames := o.read(nil)
			var addrs []uint64
			for _, d := range back {
				addrs = append(addrs, d.Addr)
			}
			assert.Equal(t, tc.back, addrs)
			assert.Equal(t, tc.frames, frames)
			assert.Len(t, o.given, tc.left)
			assert.Len(t, o.free, 3-tc.left, "items that the RX goroutine can use again")
			for _, it := range o.free {
				assert.Empty(t, it.rx)
				assert.False(t, it.done.Load())
			}
		})
	}
}

// TestWorkerPart checks that a part takes the items that wait, in order, up to rxBatch packets. An
// item over that waits for the next part.
func TestWorkerPart(t *testing.T) {
	item := func(n int, mark byte) *workItem {
		it := &workItem{}
		for range n {
			it.rx = append(it.rx, RxPacket{Payload: []byte{mark}})
		}
		return it
	}
	cases := []struct {
		name  string
		sizes []int // The first item, then the items that wait.
		parts []int // The packets of each part.
	}{
		{name: "one item", sizes: []int{3}, parts: []int{3}},
		{name: "all items that wait", sizes: []int{3, 30, 31}, parts: []int{64}},
		{name: "an item over 64 waits", sizes: []int{40, 30, 10}, parts: []int{40, 40}},
		{name: "a full item", sizes: []int{64, 1}, parts: []int{64, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorker(0, nil)
			var marks []byte
			for i, n := range tc.sizes[1:] {
				w.in <- item(n, byte(i+1))
			}
			next := item(tc.sizes[0], 0)
			var parts []int
			var got []byte
			for next != nil {
				var items []*workItem
				var rx []RxPacket
				items, rx, next = w.part(next, nil, nil)
				parts = append(parts, len(rx))
				for _, it := range items {
					got = append(got, it.rx[0].Payload[0])
				}
				if next == nil && len(w.in) > 0 {
					next = <-w.in
				}
			}
			for i := range tc.sizes {
				marks = append(marks, byte(i))
			}
			assert.Equal(t, tc.parts, parts)
			assert.Equal(t, marks, got, "the items in order")
		})
	}
}

// TestRunHandoff runs a device on fake queues with packets from A1 and A3 to A2. The workers seal
// each packet into a TX frame of their own TX queue, and the RX goroutines take back each RX frame
// when its worker is done.
func TestRunHandoff(t *testing.T) {
	type pkt struct {
		rx   int // The RX queue.
		from netip.AddrPort
	}
	plain := func(from netip.AddrPort, i int) []byte {
		if from == engA3 {
			return inner("100.64.3.5", byte(i))
		}
		return inner("100.64.1.5", byte(i))
	}
	cases := []struct {
		name     string
		nTx, nRx int
		pkts     []pkt
		marks    [][]byte // The marks of the packets on each TX queue: the index of each packet.
	}{
		{name: "two RX memories into one TX memory", nTx: 1, nRx: 2,
			pkts:  []pkt{{0, engA1}, {1, engA1}},
			marks: [][]byte{{0, 1}}},
		{name: "the sealed packets on the TX queue of their worker", nTx: 2, nRx: 1,
			pkts:  []pkt{{0, engA1}, {0, engA3}, {0, engA1}},
			marks: [][]byte{{0, 2}, {1}}},
		{name: "two RX queues and two workers", nTx: 2, nRx: 2,
			pkts:  []pkt{{0, engA1}, {1, engA3}, {1, engA1}, {0, engA3}},
			marks: [][]byte{{0, 2}, {1, 3}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine(t, tc.nTx, tc.nRx, 64)
			if tc.nTx == 2 {
				require.Equal(t, steerMap{engSPIA1: 0, engSPIA3: 1}, *e.p.steering.Load())
			}
			e.start(t)
			seq := map[netip.AddrPort]uint32{}
			for i, p := range tc.pkts {
				seq[p.from]++
				frame := agentFrame(t, p.from, seq[p.from], byte(i))
				require.False(t, bytes.Contains(frame, plain(p.from, i)), "packet %d is sealed on the wire", i)
				e.rxs[p.rx].wire(frame)
				// One packet at a time, so the order on each TX queue is the order of the packets.
				require.Eventually(t, func() bool {
					n := 0
					for _, f := range e.txs {
						n += len(f.sent())
					}
					return n == i+1
				}, 2*time.Second, time.Millisecond, "packet %d", i)
			}
			// The workers seal with the one TX entry of A2, and the packets go one at a time, so
			// packet i has sequence number i.
			for q, f := range e.txs {
				var want [][]byte
				var wantSeqs []uint32
				for _, m := range tc.marks[q] {
					want, wantSeqs = append(want, plain(tc.pkts[m].from, int(m))), append(wantSeqs, uint32(m))
				}
				inners, seqs := openedInners(t, f.sent())
				assert.Equal(t, want, inners, "TX queue %d", q)
				assert.Equal(t, wantSeqs, seqs, "the sequence numbers on TX queue %d", q)
			}
			for q, r := range e.rxs {
				require.Eventually(t, func() bool { return r.queued() == 256 }, 2*time.Second, time.Millisecond,
					"the frames of RX queue %d are back", q)
			}
			// The workers open in place: the RX frames have the inner packets in clear.
			for i, p := range tc.pkts {
				assert.True(t, bytes.Contains(e.rxs[p.rx].mem, plain(p.from, i)), "packet %d is open in its RX frame", i)
			}
			require.NoError(t, e.stop())
			assert.Zero(t, counted(e.Device, ReasonWorkerFull)+counted(e.Device, ReasonWorkerAllowance)+counted(e.Device, ReasonTXFull), "drops")
		})
	}
}

// TestRunPart checks that a worker takes the items of two RX queues that wait as one part: one
// Send and one publish. The worker waits for the pipeline lock while the items come.
func TestRunPart(t *testing.T) {
	e := newEngine(t, 1, 2, 64)
	e.start(t)
	w := e.workers[0]
	e.p.mu.Lock()
	e.rxs[0].wire(agentFrame(t, engA1, 1, 0))
	e.working(t, 0, 1)
	e.rxs[1].wire(agentFrame(t, engA1, 2, 1))
	require.Eventually(t, func() bool { return len(w.in) == 1 }, 2*time.Second, time.Millisecond)
	e.rxs[0].wire(agentFrame(t, engA1, 3, 2))
	require.Eventually(t, func() bool { return len(w.in) == 2 }, 2*time.Second, time.Millisecond)
	e.p.mu.Unlock()

	f := e.txs[0]
	require.Eventually(t, func() bool { return len(f.sent()) == 3 }, 2*time.Second, time.Millisecond)
	want := [][]byte{inner("100.64.1.5", 0), inner("100.64.1.5", 1), inner("100.64.1.5", 2)}
	inners, seqs := openedInners(t, f.sent())
	assert.Equal(t, want, inners, "the items in order")
	assert.Equal(t, []uint32{0, 1, 2}, seqs, "the sequence numbers")
	assert.Equal(t, 2, f.numSends(), "a part of the first item, and a part of the two items that waited")
}

// TestRunStop stops a device while a worker has an item. Run waits for the part of the worker,
// which goes out, and then stops.
func TestRunStop(t *testing.T) {
	e := newEngine(t, 1, 1, 64)
	e.start(t)
	e.p.mu.Lock()
	e.rxs[0].wire(agentFrame(t, engA1, 1, 7))
	e.working(t, 0, 1)
	stopped := make(chan error, 1)
	go func() { stopped <- e.stop() }()
	select {
	case <-stopped:
		t.Fatal("Run stopped while a worker had an item")
	case <-time.After(200 * time.Millisecond):
	}
	e.p.mu.Unlock()
	select {
	case err := <-stopped:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	// The kickers stop before the workers, so the packet can stay on the TX ring.
	f := e.txs[0]
	inners, seqs := openedInners(t, append(f.sent(), f.onRing()...))
	assert.Equal(t, [][]byte{inner("100.64.1.5", 7)}, inners, "the part of the worker went out")
	assert.Equal(t, []uint32{0}, seqs, "the sequence number")
}

// TestBusy checks the busy time of the threads of a device. A wait for frames, an item or a wake
// adds no busy time; a worker that waits for the pipeline lock is busy for that wait. Each upper
// bound is half of the wait, so the scheduler cannot make a correct count fail.
func TestBusy(t *testing.T) {
	busy := func(e *engine, kind string) time.Duration {
		var sum time.Duration
		for _, b := range e.Busy() {
			if b.Kind == kind {
				sum += b.Busy
			}
		}
		return sum
	}
	sent := func(e *engine) int {
		n := 0
		for _, f := range e.txs {
			n += len(f.sent())
		}
		return n
	}
	t.Run("idle waits", func(t *testing.T) {
		const idle = 300 * time.Millisecond
		e := newEngine(t, 2, 2, 64)
		e.start(t)
		time.Sleep(idle)
		// The packet ends the idle wait of an RX goroutine, of a worker and of a kicker.
		e.rxs[0].wire(agentFrame(t, engA1, 1, 0))
		require.Eventually(t, func() bool { return sent(e) == 1 }, 2*time.Second, time.Millisecond)
		require.NoError(t, e.stop())
		got := e.Busy()
		require.Len(t, got, 6, "two RX goroutines, two workers and two kickers")
		for _, b := range got {
			assert.Less(t, b.Busy, idle/2, "%s %d", b.Kind, b.Index)
		}
	})
	t.Run("a lock wait", func(t *testing.T) {
		const wait = 200 * time.Millisecond
		e := newEngine(t, 1, 1, 64)
		e.start(t)
		e.p.mu.Lock()
		e.rxs[0].wire(agentFrame(t, engA1, 1, 0))
		e.working(t, 0, 1)
		time.Sleep(wait)
		e.p.mu.Unlock()
		require.Eventually(t, func() bool { return sent(e) == 1 }, 2*time.Second, time.Millisecond)
		require.Eventually(t, func() bool { return busy(e, "worker") >= wait }, 2*time.Second, time.Millisecond,
			"the worker is busy while it waits for the lock: %v", busy(e, "worker"))
		assert.Less(t, busy(e, "rx"), wait/2, "the RX goroutine does not wait for the lock")
	})
}
