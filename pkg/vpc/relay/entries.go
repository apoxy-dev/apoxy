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
