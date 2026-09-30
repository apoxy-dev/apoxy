package main

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

const (
	// oobSize holds the ECN and packet info control messages, as in quic-go.
	oobSize = 128
	// flowQueue is the number of batches that wait for a flow reader, as in bifurcate.
	flowQueue = 1024
)

// batchReader is the interface that quic-go uses for batched reads. If the
// conn does not implement it, quic-go reads the socket file descriptor itself.
type batchReader interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

var (
	_ quic.OOBCapablePacketConn = (*flow)(nil)
	_ batchReader               = (*flow)(nil)
)

type packet struct {
	buf   []byte
	oob   []byte
	n, nn int
	flags int
	addr  net.Addr
}

var packetPool = sync.Pool{New: func() any {
	return &packet{buf: make([]byte, batchpc.MaxDatagramSize), oob: make([]byte, oobSize)}
}}

// demux reads one UDP socket in batches, with control messages. It sends
// Geneve packets to one flow and QUIC packets to a flow for each remote
// address, as bifurcate and conntrackpc do. Each flow implements quic-go's
// OOBCapablePacketConn and batch reads, so quic-go keeps GSO, ECN and batched
// reads.
type demux struct {
	uc     *net.UDPConn
	bc     *ipv4.PacketConn
	geneve *flow

	mu    sync.RWMutex
	flows map[netip.AddrPort]*flow
	any   *flow

	drops atomic.Uint64
}

func newDemux(uc *net.UDPConn) *demux {
	d := &demux{uc: uc, bc: ipv4.NewPacketConn(uc), flows: map[netip.AddrPort]*flow{}}
	d.geneve = newFlow(d)
	go d.readLoop()
	return d
}

// Geneve returns the flow of the data plane.
func (d *demux) Geneve() *flow { return d.geneve }

// Open returns the flow for QUIC packets from remote, as conntrackpc.Open does.
func (d *demux) Open(remote netip.AddrPort) *flow {
	key := addrKey(remote)
	d.mu.Lock()
	defer d.mu.Unlock()
	if f, ok := d.flows[key]; ok {
		return f
	}
	f := newFlow(d)
	f.unregister = func() {
		d.mu.Lock()
		if d.flows[key] == f {
			delete(d.flows, key)
		}
		d.mu.Unlock()
	}
	d.flows[key] = f
	return f
}

// Any returns the flow for QUIC packets from remotes that have no flow. The
// relay gives all QUIC packets to one conn in this way.
func (d *demux) Any() *flow {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.any == nil {
		f := newFlow(d)
		f.unregister = func() {
			d.mu.Lock()
			if d.any == f {
				d.any = nil
			}
			d.mu.Unlock()
		}
		d.any = f
	}
	return d.any
}

// Close closes the socket and all flows.
func (d *demux) Close() error {
	return d.uc.Close()
}

func (d *demux) readLoop() {
	msgs := make([]ipv4.Message, batchpc.MaxBatchSize)
	pkts := make([]*packet, batchpc.MaxBatchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}
	var touched []*flow
	for {
		for i := range msgs {
			if pkts[i] == nil {
				pkts[i] = packetPool.Get().(*packet)
			}
			msgs[i].Buffers[0] = pkts[i].buf
			msgs[i].OOB = pkts[i].oob
		}
		n, err := d.bc.ReadBatch(msgs, 0)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				d.closeFlows()
				if drops := d.drops.Load(); drops > 0 {
					slog.Warn("Demux dropped packets", "packets", drops)
				}
				return
			}
			slog.Warn("Failed to read UDP batch", "error", err)
			continue
		}
		for i := range n {
			p := pkts[i]
			pkts[i] = nil
			p.n, p.nn, p.flags, p.addr = msgs[i].N, msgs[i].NN, msgs[i].Flags, msgs[i].Addr
			f := d.route(p)
			if f == nil {
				d.drops.Add(1)
				packetPool.Put(p)
				continue
			}
			if f.staged == nil {
				f.staged = make([]*packet, 0, n)
				touched = append(touched, f)
			}
			f.staged = append(f.staged, p)
		}
		for _, f := range touched {
			f.deliver()
		}
		touched = touched[:0]
	}
}

// route returns the flow for p, or nil when no flow takes it.
func (d *demux) route(p *packet) *flow {
	if isGeneve(p.buf[:p.n]) {
		return d.geneve
	}
	var key netip.AddrPort
	if ua, ok := p.addr.(*net.UDPAddr); ok {
		key = addrKey(ua.AddrPort())
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if f, ok := d.flows[key]; ok {
		return f
	}
	return d.any
}

func (d *demux) closeFlows() {
	d.mu.Lock()
	fs := []*flow{d.geneve}
	if d.any != nil {
		fs = append(fs, d.any)
	}
	for _, f := range d.flows {
		fs = append(fs, f)
	}
	d.mu.Unlock()
	for _, f := range fs {
		f.shut()
	}
}

// addrKey removes the IPv4-mapped prefix, so that both forms of an IPv4
// address give the same key.
func addrKey(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// isGeneve is the check that bifurcate uses: Geneve version 0 with an IPv4,
// IPv6 or zero protocol type. A QUIC packet has its fixed bit set, so it does
// not match.
func isGeneve(b []byte) bool {
	if len(b) < 8 || b[0]>>6 != 0 {
		return false
	}
	proto := binary.BigEndian.Uint16(b[2:4])
	return proto == 0x0800 || proto == 0x86dd || proto == 0
}

// flow is one logical conn on the shared socket. Reads come from the demux.
// Writes go to the socket with their control messages, so GSO and ECN work.
type flow struct {
	d          *demux
	ch         chan []*packet
	unregister func()
	staged     []*packet // Only readLoop uses it.

	rmu     sync.Mutex // One reader at a time.
	pending []*packet

	deadline atomic.Int64 // Read deadline in Unix ns; 0 is no deadline.
	tmu      sync.Mutex
	timer    *time.Timer
	wake     chan struct{}

	done     chan struct{}
	doneOnce sync.Once
}

func newFlow(d *demux) *flow {
	return &flow{
		d:          d,
		ch:         make(chan []*packet, flowQueue),
		unregister: func() {},
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
	}
}

// deliver gives the staged batch to the flow reader. When the queue is full it
// drops the batch, as conntrackpc does, so a slow flow does not stop the others.
func (f *flow) deliver() {
	b := f.staged
	f.staged = nil
	select {
	case f.ch <- b:
	default:
		f.d.drops.Add(uint64(len(b)))
		for _, p := range b {
			packetPool.Put(p)
		}
	}
}

// ReadBatch copies waiting packets into ms. It blocks until at least one
// packet is available.
func (f *flow) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	if len(ms) == 0 {
		return 0, nil
	}
	f.rmu.Lock()
	defer f.rmu.Unlock()
	for len(f.pending) == 0 {
		if f.expired() {
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case f.pending = <-f.ch:
		case <-f.wake:
		case <-f.done:
			return 0, net.ErrClosed
		}
	}
	n := 0
	for n < len(ms) {
		if len(f.pending) == 0 {
			select {
			case f.pending = <-f.ch:
				continue
			default:
				return n, nil
			}
		}
		p := f.pending[0]
		f.pending = f.pending[1:]
		m := &ms[n]
		m.N = copy(m.Buffers[0], p.buf[:p.n])
		m.NN = copy(m.OOB, p.oob[:p.nn])
		m.Flags = p.flags
		m.Addr = p.addr
		packetPool.Put(p)
		n++
	}
	return n, nil
}

func (f *flow) ReadFrom(b []byte) (int, net.Addr, error) {
	ms := []ipv4.Message{{Buffers: [][]byte{b}}}
	if _, err := f.ReadBatch(ms, 0); err != nil {
		return 0, nil, err
	}
	return ms[0].N, ms[0].Addr, nil
}

func (f *flow) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	ms := []ipv4.Message{{Buffers: [][]byte{b}, OOB: oob}}
	if _, err := f.ReadBatch(ms, 0); err != nil {
		return 0, 0, 0, nil, err
	}
	addr, _ = ms[0].Addr.(*net.UDPAddr)
	return ms[0].N, ms[0].NN, ms[0].Flags, addr, nil
}

func (f *flow) WriteTo(b []byte, addr net.Addr) (int, error) { return f.d.uc.WriteTo(b, addr) }

func (f *flow) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return f.d.uc.WriteMsgUDP(b, oob, addr)
}

// SyscallConn gives quic-go the socket, so that it can set DF, ECN and packet
// info options and find GSO support.
func (f *flow) SyscallConn() (syscall.RawConn, error) { return f.d.uc.SyscallConn() }

func (f *flow) SetReadBuffer(n int) error  { return f.d.uc.SetReadBuffer(n) }
func (f *flow) SetWriteBuffer(n int) error { return f.d.uc.SetWriteBuffer(n) }
func (f *flow) LocalAddr() net.Addr        { return f.d.uc.LocalAddr() }

func (f *flow) SetDeadline(t time.Time) error    { return f.SetReadDeadline(t) }
func (f *flow) SetWriteDeadline(time.Time) error { return nil }

func (f *flow) SetReadDeadline(t time.Time) error {
	f.tmu.Lock()
	defer f.tmu.Unlock()
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
	if t.IsZero() {
		f.deadline.Store(0)
	} else {
		f.deadline.Store(t.UnixNano())
		if d := time.Until(t); d > 0 {
			f.timer = time.AfterFunc(d, f.poke)
		}
	}
	f.poke()
	return nil
}

func (f *flow) expired() bool {
	d := f.deadline.Load()
	return d != 0 && time.Now().UnixNano() >= d
}

// poke wakes a blocked reader so that it checks the deadline again.
func (f *flow) poke() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Close closes the flow. The socket stays open for the other flows.
func (f *flow) Close() error {
	f.shut()
	f.unregister()
	return nil
}

func (f *flow) shut() {
	f.doneOnce.Do(func() { close(f.done) })
}
