// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"strconv"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// accessSession is the session of an access port. Only a trunk port changes its session.
const accessSession = 1

// batch is the updates of one atomic Write.
type batch []*p4.Update

func (b *batch) table(typ p4.Update_Type, e *p4.TableEntry, md string) {
	e.Metadata = []byte(md)
	*b = append(*b, &p4.Update{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_TableEntry{TableEntry: e}}})
}

func (b *batch) insert(e *p4.TableEntry, md string) { b.table(p4.Update_INSERT, e, md) }
func (b *batch) modify(e *p4.TableEntry, md string) { b.table(p4.Update_MODIFY, e, md) }
func (b *batch) remove(e *p4.TableEntry)            { b.table(p4.Update_DELETE, e, "") }

// keys adds an update of a keys entry.
func (b *batch) keys(typ p4.Update_Type, e *dpv1.PspSaEntry) error {
	x, err := dp.KeysEntry(e)
	if err != nil {
		return err
	}
	*b = append(*b, &p4.Update{Type: typ, Entity: &p4.Entity{Entity: &p4.Entity_ExternEntry{ExternEntry: x}}})
	return nil
}

// zeroCell sets both counter indices of a cell to 0.
func (b *batch) zeroCell(cell uint32) {
	for _, i := range []int64{2 * int64(cell), 2*int64(cell) + 1} {
		*b = append(*b, &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
			CounterId: dp.CounterCells, Index: &p4.Index{Index: i}, Data: &p4.CounterData{},
		}}}})
	}
}

// portReasons is the number of port_drops indices of one meter index: one for each reason.
const portReasons = 1 << 5

// portDropIndex returns the port_drops index of a drop at meter index i.
func portDropIndex(i uint32, reason uint8) int64 { return int64(i)<<5 | int64(reason) }

// zeroPortDrops sets the port_drops indices of meter index i to 0.
func (b *batch) zeroPortDrops(i uint32) {
	for reason := range uint8(portReasons) {
		*b = append(*b, &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
			CounterId: dp.CounterPortDrops, Index: &p4.Index{Index: portDropIndex(i, reason)}, Data: &p4.CounterData{},
		}}}})
	}
}

// meter sets meter index i to rate bytes per second with burst bytes. A zero rate removes the
// limit.
func (b *batch) meter(id, i uint32, rate float64, burst int) {
	me := &p4.MeterEntry{MeterId: id, Index: &p4.Index{Index: int64(i)}}
	if rate > 0 {
		r, s := int64(rate), int64(burst)
		me.Config = &p4.MeterConfig{Cir: r, Cburst: s, Pir: r, Pburst: s}
	}
	*b = append(*b, &p4.Update{Type: p4.Update_MODIFY, Entity: &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: me}}})
}

// write applies b at one commit, or none of it.
func (b batch) write(ctx context.Context, t dp.Target) error {
	if len(b) == 0 {
		return nil
	}
	return t.Write(ctx, &p4.WriteRequest{Atomicity: p4.WriteRequest_DATAPLANE_ATOMIC, Updates: b})
}

// tableWriter sends the table changes of a process up to the root as tables events, one at a
// time. The changes of later steps wait for the answer, tablesDone, and go in the next event.
type tableWriter struct {
	busy bool          // An event is at the root.
	wait []func(error) // They run after the next event.
	run  []func(error) // They run after the event at the root.
}

// then runs fn after the next event, with the error of its write.
func (w *tableWriter) then(fn func(error)) { w.wait = append(w.wait, fn) }

// pending reports whether an event is at the root or a function waits for the next one.
func (w *tableWriter) pending() bool { return w.busy || len(w.wait) > 0 }

// send sends b up with up. After the answer, commit runs, then each function of then. With no
// updates in b, they run at once.
func (w *tableWriter) send(b batch, commit func(error), up func(batch)) {
	fns := append([]func(error){commit}, w.wait...)
	w.wait = nil
	if len(b) == 0 {
		for _, fn := range fns {
			fn(nil)
		}
		return
	}
	w.busy, w.run = true, fns
	up(b)
}

// done takes the answer of the root to the event.
func (w *tableWriter) done(err error) {
	if !w.busy {
		return
	}
	fns := w.run
	w.busy, w.run = false, nil
	for _, fn := range fns {
		fn(err)
	}
}

// tally counts packets and bytes.
type tally struct{ packets, bytes uint64 }

func (t *tally) add(o tally) {
	t.packets += o.packets
	t.bytes += o.bytes
}

// readCell returns the receive and transmit counts of a cell.
func readCell(ctx context.Context, t dp.Target, cell uint32) (rx, tx tally, err error) {
	req := &p4.ReadRequest{}
	for _, i := range []int64{2 * int64(cell), 2*int64(cell) + 1} {
		req.Entities = append(req.Entities, &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
			CounterId: dp.CounterCells, Index: &p4.Index{Index: i},
		}}})
	}
	err = t.Read(ctx, req, func(e *p4.Entity) {
		ce := e.GetCounterEntry()
		n := tally{uint64(ce.GetData().GetPacketCount()), uint64(ce.GetData().GetByteCount())}
		if ce.GetIndex().GetIndex()%2 == 0 {
			rx = n
		} else {
			tx = n
		}
	})
	return rx, tx, err
}

// trunkCounts is the counts of a trunk port: its cell, and the port_drops of its meter index by
// reason.
type trunkCounts struct {
	rx, tx tally
	drops  [portReasons]uint64
}

func (c *trunkCounts) add(o trunkCounts) {
	c.rx.add(o.rx)
	c.tx.add(o.tx)
	for i, n := range o.drops {
		c.drops[i] += n
	}
}

// readTrunk reads the counts of a trunk port with cell and meter index.
func readTrunk(ctx context.Context, t dp.Target, cell, meter uint32) (trunkCounts, error) {
	var n trunkCounts
	var err error
	if n.rx, n.tx, err = readCell(ctx, t, cell); err != nil {
		return n, err
	}
	req := &p4.ReadRequest{}
	for reason := range uint8(portReasons) {
		req.Entities = append(req.Entities, &p4.Entity{Entity: &p4.Entity_CounterEntry{CounterEntry: &p4.CounterEntry{
			CounterId: dp.CounterPortDrops, Index: &p4.Index{Index: portDropIndex(meter, reason)},
		}}})
	}
	err = t.Read(ctx, req, func(e *p4.Entity) {
		ce := e.GetCounterEntry()
		n.drops[ce.GetIndex().GetIndex()%portReasons] = uint64(ce.GetData().GetPacketCount())
	})
	return n, err
}

// vpcName is the name of a VPC in the data plane. A new network ID gives a new name, so old
// classify entries never match the route entries of a new V.
func vpcName(vpc VPCKey, networkID uint32) string {
	return vpc.UID + "/" + strconv.FormatUint(uint64(networkID), 10)
}

// portKey is the writer key of the entries of a port session.
func portKey(port uint64) string { return fmt.Sprintf("p/%d/%d", port, accessSession) }

// pool gives indices from 1 to max-1. An index comes again only after it is given back, and after
// the indices that were given back before it.
type pool struct {
	next, max uint32
	free      []uint32
}

func (p *pool) get() (uint32, bool) {
	if len(p.free) > 0 {
		i := p.free[0]
		p.free = p.free[1:]
		return i, true
	}
	if p.next+1 >= p.max {
		return 0, false
	}
	p.next++
	return p.next, true
}

func (p *pool) put(i uint32) {
	if i != 0 {
		p.free = append(p.free, i)
	}
}
