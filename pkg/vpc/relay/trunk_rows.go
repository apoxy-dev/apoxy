// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// maxSPIRows is the most rows of one SPIRowUpdate.
const maxSPIRows = 256

// trunkSeal is how the packet of a row to another relay goes on the trunk: the
// SA of that relay for whole PSP packets, and the tag of the sender.
type trunkSeal struct {
	sa  *engine.TxSA
	tag uint32
}

// rowKey names a row for the relay that has its receiver: the tag of the
// sender session on this relay, and the SPI.
type rowKey struct {
	tag, spi uint32
}

// rowState is the last state of a row that another relay must get.
type rowState struct {
	vpc       VPCKey
	networkID uint32
	dst       netip.Addr
	expires   time.Time // The zero time is a row that ended.
}

// lost reports whether w is a row to another relay whose trunk has no SA: the
// relay is down, it is at a new address, or its keys ended.
func (w *row) lost() bool { return w.trunk != nil && w.trunk.tx.SA(trunkLanePSP) == nil }

// trunkOf returns the pair of the relay that has the session to, if the trunk
// carries the packets of sender c to it now. Router.mu must be held.
func (r *Router) trunkOf(c, to *Session) *trunkPair {
	t := r.trunk.Load()
	// The other relay knows a sender by its tag, which comes with an attachment.
	if t == nil || c.tag == 0 {
		return nil
	}
	if p := t.pair(to.home); p != nil && p.tx.SA(trunkLanePSP) != nil {
		return p
	}
	return nil
}

// trunkFits checks that the trunk of p carries a PSP packet of size bytes of
// sender s with sa. It counts the drop if not.
func (r *Router) trunkFits(s *Session, p *trunkPair, sa *engine.TxSA, size int) Verdict {
	if sa == nil {
		s.dropTrunk.Add(1)
		r.drops[dropTrunkKeys].Add(1)
		return DropTrunkKeys
	}
	// The limit of the trunk is an inner MTU, and size has the PSP overhead.
	if size > p.mtu()+pspwire.Overhead {
		s.dropTrunk.Add(1)
		r.drops[dropTrunkMTU].Add(1)
		return DropTrunkMTU
	}
	return Pass
}

// aim sends the packets of w to the session of o, on the trunk of p when that
// session is on another relay. Router.mu must be held for writing.
func (r *Router) aim(w *row, o owner, p *trunkPair) {
	if w.trunk != p {
		r.untrunk(w)
	}
	r.retarget(w, o)
	w.trunk = p
}

// move gives w to o, the new owner of its destination. The row ends if o is on
// another relay and no trunk carries it. Router.mu must be held for writing.
func (r *Router) move(w *row, o owner) {
	var p *trunkPair
	if o.s.home != "" {
		if p = r.trunkOf(w.sender, o.s); p == nil {
			r.removeRow(w)
			return
		}
	}
	told := w.trunk == p
	r.aim(w, o, p)
	if !told {
		r.tellRow(w)
	}
}

// stateOf returns the state of the live row w for the relay that has its
// receiver. Router.mu must be held.
func (r *Router) stateOf(w *row) (rowKey, rowState) {
	st := rowState{vpc: w.vpc, dst: w.dst, expires: w.expires}
	if d := r.domains[w.vpc]; d != nil && d.known {
		st.networkID = d.networkID
	}
	return rowKey{w.sender.tag, w.spi}, st
}

// tellRow gives the row w and its end time to the relay that has its receiver,
// if that is another relay. Router.mu must be held.
func (r *Router) tellRow(w *row) {
	if t := r.trunk.Load(); t != nil && w.trunk != nil {
		k, st := r.stateOf(w)
		t.tell(w.trunk, k, st)
	}
}

// untrunk takes w off the trunk, and the relay that has its receiver learns
// that the row ended. Router.mu must be held for writing.
func (r *Router) untrunk(w *row) {
	if t := r.trunk.Load(); t != nil && w.trunk != nil {
		k, st := r.stateOf(w)
		st.expires = time.Time{}
		t.tell(w.trunk, k, st)
	}
	w.trunk = nil
}

// liveRows gives ts, the new session of p, each row to the relay of p.
// Router.mu and trunk.mu must be held.
func (r *Router) liveRows(p *trunkPair, ts *trunkSession) {
	for s := range r.sessions {
		for _, w := range s.rows {
			if w.trunk == p {
				k, st := r.stateOf(w)
				ts.rows[k] = st
			}
		}
	}
	if len(ts.rows) > 0 {
		select {
		case ts.rowWake <- struct{}{}:
		default:
		}
	}
}

// tell keeps the state st of row k for the SPIRows call of the session of p.
// With no session, the next session gets the live rows. Router.mu must be held.
func (t *trunk) tell(p *trunkPair, k rowKey, st rowState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ts := p.sess
	if ts == nil || ts.rowsDone {
		return
	}
	// A later state of a row replaces the state that waits.
	ts.rows[k] = st
	select {
	case ts.rowWake <- struct{}{}:
	default:
	}
}

// takeRows returns the messages for the rows of ts that wait, in the order of
// tag and SPI. A live row has the time that it has left at now.
func (t *trunk) takeRows(ts *trunkSession, now time.Time) []*dp.SPIRowUpdate {
	// The read lock keeps the rows of one change of the router in one take.
	t.r.mu.RLock()
	t.mu.Lock()
	waiting := ts.rows
	ts.rows = map[rowKey]rowState{}
	t.mu.Unlock()
	t.r.mu.RUnlock()
	rows := make([]*dp.SPIRow, 0, len(waiting))
	for k, st := range waiting {
		row := &dp.SPIRow{
			Vpc:       &dp.VPCRef{ProjectId: st.vpc.Project, VpcUid: st.vpc.UID, NetworkId: st.networkID},
			SenderTag: k.tag,
			Spi:       k.spi,
		}
		if left := st.expires.Sub(now); !st.expires.IsZero() && left > 0 {
			row.Destination, row.ExpiresIn = st.dst.String(), durationpb.New(left)
		} else {
			row.Removed = true
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b *dp.SPIRow) int {
		return cmp.Or(cmp.Compare(a.GetSenderTag(), b.GetSenderTag()), cmp.Compare(a.GetSpi(), b.GetSpi()))
	})
	var msgs []*dp.SPIRowUpdate
	for part := range slices.Chunk(rows, maxSPIRows) {
		msgs = append(msgs, &dp.SPIRowUpdate{Rows: part})
	}
	return msgs
}

// sendRows sends the rows of p on the SPIRows call of ts until the session
// ends. The call opens at the first row, and a failed call gets no new call.
func (t *trunk) sendRows(p *trunkPair, ts *trunkSession) {
	ctx := ts.s.Context()
	var st rpc.ClientStreamClient[dp.SPIRowUpdate, emptypb.Empty]
	var err error
	for err == nil {
		select {
		case <-ctx.Done():
			return
		case <-ts.rowWake:
		}
		msgs := t.takeRows(ts, time.Now())
		if st == nil && len(msgs) > 0 {
			st, err = ts.s.Client().SPIRows(ctx)
		}
		for _, u := range msgs {
			if err != nil {
				break
			}
			if err = st.Send(u); err != nil {
				// The answer of the other relay has the cause.
				if _, cerr := st.CloseAndRecv(); cerr != nil {
					err = cerr
				}
			}
		}
	}
	t.mu.Lock()
	ts.rowsDone, ts.rows = true, nil
	t.mu.Unlock()
	switch {
	case ctx.Err() != nil:
	case rpc.CodeOf(err) == rpc.Unimplemented:
		slog.Info("Mesh member takes no SPI rows", "relay", p.name)
	default:
		slog.Warn("Failed to send SPI rows to a mesh member", "relay", p.name, "error", err)
	}
}
