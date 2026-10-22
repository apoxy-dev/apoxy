// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

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

// Sender sends one UDP payload of port 1000 to an outer address. It never waits, and b is valid
// only during the call.
type Sender func(to netip.AddrPort, b []byte)

// counter is one index of a packets_and_bytes counter.
type counter struct {
	packets, bytes atomic.Uint64
}

func (c *counter) add(n int) {
	c.packets.Add(1)
	c.bytes.Add(uint64(n))
}

// Pipeline is the Go pipeline of relay.p4. Write takes the lock; the packets take the read lock.
// The callbacks (Sender, frame writers, OnPacketIn) run with the read lock held and must not call
// the Pipeline.
type Pipeline struct {
	send     Sender
	defaults map[uint32]Action
	packetIn atomic.Pointer[func(*p4.PacketIn) bool]
	bufs     sync.Pool

	cells []counter
	drops []counter

	mu      sync.RWMutex
	st      state
	writers map[uint64]func([]byte) error
}

var _ Target = (*Pipeline)(nil)

// New returns an empty pipeline with the built-in schema. send gets the sealed PSP and RAW packets.
func New(send Sender) *Pipeline {
	p := &Pipeline{
		send:     send,
		defaults: map[uint32]Action{},
		cells:    make([]counter, counterSizes[CounterCells]),
		drops:    make([]counter, counterSizes[CounterDrops]),
		st:       newState(),
		writers:  map[uint64]func([]byte) error{},
	}
	for id, a := range defaultActions {
		d, err := decodeAction(a)
		if err != nil {
			panic(err) // The generated default actions always decode.
		}
		p.defaults[id] = d
	}
	p.bufs.New = func() any { b := make([]byte, maxPacket); return &b }
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
	return nil
}

func (p *Pipeline) update(t *txn, u *p4.Update) error {
	switch e := u.GetEntity().GetEntity().(type) {
	case *p4.Entity_TableEntry:
		return p.st.writeTable(t, u.GetType(), e.TableEntry)
	case *p4.Entity_ExternEntry:
		return p.st.writeKeys(t, u.GetType(), e.ExternEntry)
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
	}{{CounterCells, p.cells}, {CounterDrops, p.drops}} {
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
