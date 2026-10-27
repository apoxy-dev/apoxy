// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/atoonk/packetio"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
)

// Target is the DP as the CP calls it (p4 = p4runtime/go/p4/v1). A gRPC server can wrap it later.
type Target interface {
	// Write applies the batch at one commit, or none of it. The DP copies what it keeps.
	Write(ctx context.Context, req *p4.WriteRequest) error
	// Read calls each for each entity that matches, from one snapshot.
	Read(ctx context.Context, req *p4.ReadRequest, each func(*p4.Entity)) error
	// PacketOut takes FRAME in (it starts at ports), SEAL and RAW. It never waits.
	PacketOut(p *p4.PacketOut) error
	// OnPacketIn sets the root's callback for PUNT and MISS. False: full, drop.
	OnPacketIn(fn func(p *p4.PacketIn) bool)
	// SetFrameWriter sets the QUIC datagram writer of a port for FRAME out; nil clears it. w never
	// waits: on a full datagram queue it drops the frame (datagram_full).
	SetFrameWriter(port uint64, w func(b []byte) error)
}

// The kind field of packet_in and packet_out.
const (
	KindPunt  uint8 = 1
	KindMiss  uint8 = 2
	KindFrame uint8 = 4
	KindSeal  uint8 = 5
	KindRaw   uint8 = 6
)

// RxPacket is one UDP payload of port 1000 and its outer source address. In a batch of a worker of
// the device, the payload is in its RX frame, and the pipeline opens it in place. In another batch,
// the pipeline opens a copy and does not change the payload.
type RxPacket struct {
	From    netip.AddrPort
	Payload []byte

	mem int // In a batch of a worker: the memory of Payload in the batch.
}

// TxBatch is the sealed PSP and RAW payloads of one batch, in order: at most rxBatch. A batch of a
// worker of the device has the memories of the device (mems): packet i is in TX frame i of the
// batch, from the TX queue of the worker. Another batch has its packets, and the copies of the
// packets that it opens, in buf. The zero value is an empty batch.
type TxBatch struct {
	to     []netip.AddrPort
	starts []int
	ends   []int
	buf    []byte
	one    [1][]byte // The memories of a batch with no mems: buf.

	mems   [][]byte        // The memories of a batch of a worker, or nil.
	txMem  int             // The memory of the TX frames in mems.
	frames []packetio.Desc // The TX frames that the worker took for the part.
	txq    *txQueue        // The TX queue of the worker, or nil.
	hops   hopCache        // The next-hop MACs of the worker, or nil.

	rx    []rxState // The parse result of each RX packet of the part of Receive.
	opens []AEADOp  // The open ops of the part.
	seals []AEADOp  // The seal ops of the part.
}

// Len is the number of packets in the batch.
func (b *TxBatch) Len() int { return len(b.to) }

// Packet returns packet i and its outer address. The payload is valid until the batch is reset.
func (b *TxBatch) Packet(i int) (to netip.AddrPort, payload []byte) {
	m := b.memories()[b.txMem]
	return b.to[i], m[b.starts[i]:b.ends[i]:b.ends[i]]
}

// memories returns the memories of the ops and the packets of the batch: mems, or buf alone.
func (b *TxBatch) memories() [][]byte {
	if b.mems != nil {
		return b.mems
	}
	b.one[0] = b.buf
	return b.one[:]
}

// slot adds n bytes at the end of buf and returns their offset. buf can move, so a caller keeps
// the offset, not a slice.
func (b *TxBatch) slot(n int) int {
	off := len(b.buf)
	b.buf = slices.Grow(b.buf, n)[:off+n]
	return off
}

// in returns the memory and the offset of p in the batch. A batch of a worker has p in memory mem;
// another batch copies p into a new slot of buf, memory 0.
func (b *TxBatch) in(mem int, p []byte) (int, int) {
	if b.mems == nil {
		off := b.slot(len(p))
		copy(b.buf[off:], p)
		return 0, off
	}
	return mem, b.offset(mem, p)
}

// offset returns the offset of p in memory mem of the batch, or 0 for an empty p. A p that is not
// in it is a program error: offset panics.
func (b *TxBatch) offset(mem int, p []byte) int {
	if len(p) == 0 {
		return 0
	}
	m := b.memories()[mem]
	off := uintptr(unsafe.Pointer(unsafe.SliceData(p))) - uintptr(unsafe.Pointer(unsafe.SliceData(m)))
	if off > uintptr(len(m)) || uintptr(len(p)) > uintptr(len(m))-off {
		panic("dp: a packet is not in the memory of its batch")
	}
	return int(off)
}

// room returns the offset of n bytes for the next packet, in the memory of the TX packets:
// udpHeaderRoom bytes into the next TX frame of a batch of a worker, else a new slot. It returns
// false when no TX frame is left or the frame is too small.
func (b *TxBatch) room(n int) (int, bool) {
	if b.mems == nil {
		return b.slot(n), true
	}
	if len(b.to) == len(b.frames) {
		return 0, false
	}
	f := b.frames[len(b.to)]
	if udpHeaderRoom+n > len(b.txq.q.Region().Writable(f)) {
		return 0, false
	}
	return int(f.Addr) + udpHeaderRoom, true
}

// add adds n bytes at off in the memory of the TX packets as the next packet, to the outer address
// to.
func (b *TxBatch) add(to netip.AddrPort, off, n int) {
	b.to = append(b.to, to)
	b.starts = append(b.starts, off)
	b.ends = append(b.ends, off+n)
}

// reset empties the batch. It also clears the parse results and the ops, which hold keys, so an
// idle batch keeps no key. The TX frames stay: Send and the worker give them back.
func (b *TxBatch) reset() {
	clear(b.rx)
	clear(b.opens)
	clear(b.seals)
	b.one[0] = nil
	b.to, b.starts, b.ends, b.buf = b.to[:0], b.starts[:0], b.ends[:0], b.buf[:0]
	b.rx, b.opens, b.seals = b.rx[:0], b.opens[:0], b.seals[:0]
}

// Sender sends the UDP payloads of port 1000 of a batch. Send never waits: it drops and counts
// (tx_full) what does not fit. b is valid only during the call.
type Sender interface {
	Send(b *TxBatch)
}

// counter is one index of a packets_and_bytes counter.
type counter struct {
	packets, bytes atomic.Uint64
}

func (c *counter) add(n int) {
	c.packets.Add(1)
	c.bytes.Add(uint64(n))
}

// Pipeline is the Go pipeline of relay.p4. Write takes the lock; each part of a batch of packets
// takes the read lock one time. The frame writers and OnPacketIn run with the read lock held and
// must not call the Pipeline. The Sender runs after the part releases the read lock.
type Pipeline struct {
	send     Sender
	aead     AEAD
	defaults map[uint32]Action
	packetIn atomic.Pointer[func(*p4.PacketIn) bool]
	bufs     sync.Pool
	batches  sync.Pool // The TxBatch of a PacketOut.

	cells     []counter
	drops     []counter
	portDrops []counter // Packets only.

	mu      sync.RWMutex
	st      state
	writers map[uint64]func([]byte) error

	// The steering of the device (steer.go): the workers and the worker of each port session, under
	// mu, and the map that the RX goroutines read with no lock.
	workers  int
	workerOf map[portSession]int
	steering atomic.Pointer[steerMap]
}

var _ Target = (*Pipeline)(nil)

// New returns an empty pipeline with the built-in schema. send gets the sealed PSP and RAW packets,
// and aead opens and seals the PSP packets.
func New(send Sender, aead AEAD) *Pipeline {
	p := &Pipeline{
		send:      send,
		aead:      aead,
		defaults:  map[uint32]Action{},
		cells:     make([]counter, counterSizes[CounterCells]),
		drops:     make([]counter, counterSizes[CounterDrops]),
		portDrops: make([]counter, counterSizes[CounterPortDrops]),
		st:        newState(),
		writers:   map[uint64]func([]byte) error{},
	}
	for id, a := range defaultActions {
		d, err := decodeAction(a)
		if err != nil {
			panic(err) // The generated default actions always decode.
		}
		p.defaults[id] = d
	}
	p.bufs.New = func() any { b := make([]byte, maxPacket); return &b }
	p.batches.New = func() any { return &TxBatch{} }
	return p
}

// Write applies the updates of a DATAPLANE_ATOMIC request at one commit, or none of them. An error
// of one update gives a status with one p4.Error for each update: the code of the failed update,
// and ABORTED for the others.
func (p *Pipeline) Write(ctx context.Context, req *p4.WriteRequest) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	if req.GetAtomicity() != p4.WriteRequest_DATAPLANE_ATOMIC {
		return status.Error(codes.InvalidArgument, "the target takes only DATAPLANE_ATOMIC writes")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var t txn
	for i, u := range req.GetUpdates() {
		err := p.update(&t, u)
		if err == nil {
			continue
		}
		t.rollback()
		details := make([]protoadapt.MessageV1, len(req.GetUpdates()))
		for j := range details {
			details[j] = &p4.Error{CanonicalCode: int32(codes.Aborted), Message: "the batch was not applied"}
		}
		st := status.Convert(err)
		details[i] = &p4.Error{CanonicalCode: int32(st.Code()), Message: st.Message()}
		s, derr := status.New(codes.Unknown, "update "+strconv.Itoa(i)+": "+st.Message()).WithDetails(details...)
		if derr != nil {
			return status.Error(codes.Internal, derr.Error())
		}
		return s.Err()
	}
	p.steer()
	return nil
}

func (p *Pipeline) update(t *txn, u *p4.Update) error {
	switch e := u.GetEntity().GetEntity().(type) {
	case *p4.Entity_TableEntry:
		return p.st.writeTable(t, u.GetType(), e.TableEntry)
	case *p4.Entity_ExternEntry:
		return p.st.writeKeys(t, u.GetType(), e.ExternEntry, p.aead)
	case *p4.Entity_CounterEntry:
		return p.writeCounter(t, u.GetType(), e.CounterEntry)
	case *p4.Entity_MeterEntry:
		return p.st.writeMeter(t, u.GetType(), e.MeterEntry)
	case nil:
		return status.Error(codes.InvalidArgument, "the update has no entity")
	}
	return status.Error(codes.Unimplemented, "the target does not have this entity type")
}

// Read gives each entity that matches the request, from one snapshot. A table entry filter can
// have a table ID (0: all tables), metadata, and a full match key.
func (p *Pipeline) Read(ctx context.Context, req *p4.ReadRequest, each func(*p4.Entity)) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	var out []*p4.Entity
	p.mu.RLock()
	err := p.read(req, &out)
	p.mu.RUnlock()
	if err != nil {
		return err
	}
	for _, e := range out {
		each(e)
	}
	return nil
}

func (p *Pipeline) read(req *p4.ReadRequest, out *[]*p4.Entity) error {
	for _, e := range req.GetEntities() {
		var err error
		switch e := e.GetEntity().(type) {
		case *p4.Entity_TableEntry:
			err = p.st.readTables(e.TableEntry, out)
		case *p4.Entity_ExternEntry:
			err = p.st.readKeys(e.ExternEntry, out)
		case *p4.Entity_CounterEntry:
			err = p.readCounters(e.CounterEntry, out)
		case *p4.Entity_MeterEntry:
			err = p.st.readMeters(e.MeterEntry, out)
		default:
			err = status.Error(codes.Unimplemented, "the target does not have this entity type")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// OnPacketIn sets the root's callback for PUNT and MISS.
func (p *Pipeline) OnPacketIn(fn func(p *p4.PacketIn) bool) {
	if fn == nil {
		p.packetIn.Store(nil)
		return
	}
	p.packetIn.Store(&fn)
}

// SetFrameWriter sets the frame writer of a port. w gets a frame that is valid only during the call.
func (p *Pipeline) SetFrameWriter(port uint64, w func(b []byte) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if w == nil {
		delete(p.writers, port)
		return
	}
	p.writers[port] = w
}

func (p *Pipeline) counterAt(id uint32, index *p4.Index) (*counter, error) {
	var cs []counter
	switch id {
	case CounterCells:
		cs = p.cells
	case CounterDrops:
		cs = p.drops
	case CounterPortDrops:
		cs = p.portDrops
	default:
		return nil, status.Errorf(codes.NotFound, "unknown counter %d", id)
	}
	if index == nil {
		return nil, status.Error(codes.InvalidArgument, "the counter entry has no index")
	}
	if i := index.GetIndex(); i < 0 || i >= int64(len(cs)) {
		return nil, status.Errorf(codes.OutOfRange, "counter index %d is out of range", i)
	}
	return &cs[index.GetIndex()], nil
}

// writeCounter applies a MODIFY of a counter index, for example to 0 after the final count.
func (p *Pipeline) writeCounter(t *txn, typ p4.Update_Type, ce *p4.CounterEntry) error {
	if typ != p4.Update_MODIFY {
		return status.Error(codes.InvalidArgument, "a counter takes only MODIFY")
	}
	c, err := p.counterAt(ce.GetCounterId(), ce.GetIndex())
	if err != nil {
		return err
	}
	d := ce.GetData()
	if d.GetPacketCount() < 0 || d.GetByteCount() < 0 {
		return status.Error(codes.InvalidArgument, "a counter value must not be negative")
	}
	oldP, oldB := c.packets.Load(), c.bytes.Load()
	c.packets.Store(uint64(d.GetPacketCount()))
	c.bytes.Store(uint64(d.GetByteCount()))
	t.onUndo(func() {
		c.packets.Store(oldP)
		c.bytes.Store(oldB)
	})
	return nil
}

// readCounters gives the counter entries that match ce. With no index, it gives the indices that
// are not zero.
func (p *Pipeline) readCounters(ce *p4.CounterEntry, out *[]*p4.Entity) error {
	add := func(id uint32, i int, c *counter) {
		*out = append(*out, &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
			CounterId: id,
			Index:     &p4.Index{Index: int64(i)},
			Data:      &p4.CounterData{PacketCount: int64(c.packets.Load()), ByteCount: int64(c.bytes.Load())},
		}}})
	}
	if ce.GetIndex() != nil {
		c, err := p.counterAt(ce.GetCounterId(), ce.GetIndex())
		if err != nil {
			return err
		}
		add(ce.GetCounterId(), int(ce.GetIndex().GetIndex()), c)
		return nil
	}
	found := false
	for _, x := range []struct {
		id uint32
		cs []counter
	}{{CounterCells, p.cells}, {CounterDrops, p.drops}, {CounterPortDrops, p.portDrops}} {
		if ce.GetCounterId() != 0 && ce.GetCounterId() != x.id {
			continue
		}
		found = true
		for i := range x.cs {
			if x.cs[i].packets.Load() != 0 || x.cs[i].bytes.Load() != 0 {
				add(x.id, i, &x.cs[i])
			}
		}
	}
	if !found {
		return status.Errorf(codes.NotFound, "unknown counter %d", ce.GetCounterId())
	}
	return nil
}

// readTables gives the table entries that match te.
func (s *state) readTables(te *p4.TableEntry, out *[]*p4.Entity) error {
	id := te.GetTableId()
	if id != 0 && id != TablePorts && id != TableClassify && id != TableSource && id != TableRoute {
		return status.Errorf(codes.NotFound, "unknown table %d", id)
	}
	md := te.GetMetadata()
	var key any
	if len(te.GetMatch()) > 0 {
		var err error
		switch id {
		case TablePorts:
			key, err = decodePortsKey(te.GetMatch())
		case TableClassify:
			key, err = decodeClassifyKey(te.GetMatch())
		case TableSource:
			key, err = decodeSourceKey(te.GetMatch())
		case TableRoute:
			key, err = decodeRouteKey(te.GetMatch())
		default:
			err = status.Error(codes.InvalidArgument, "a match filter needs a table ID")
		}
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	add := func(k interface{ Entry(Action) *p4.TableEntry }, a Action, emd []byte) {
		if (len(md) > 0 && string(md) != string(emd)) || (key != nil && key != any(k)) {
			return
		}
		e := k.Entry(a)
		e.Metadata = append([]byte(nil), emd...)
		*out = append(*out, &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}})
	}
	if id == 0 || id == TablePorts {
		for _, e := range s.ports {
			add(e.key, e.action, e.md)
		}
	}
	if id == 0 || id == TableClassify {
		for _, e := range s.classify {
			add(e.key, e.action, e.md)
		}
	}
	if id == 0 || id == TableSource {
		for _, l := range s.source {
			for _, e := range l.m {
				add(e.key, e.action, e.md)
			}
		}
	}
	if id == 0 || id == TableRoute {
		for _, l := range s.route {
			for _, e := range l.m {
				add(e.key, e.action, e.md)
			}
		}
	}
	return nil
}
