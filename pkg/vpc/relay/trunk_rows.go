// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// maxSPIRows is the most rows of one SPIRowUpdate.
const maxSPIRows = 256

// rowState is the last state of a row that another relay must get. That relay
// knows the row by its SPI, and the sender by the tag of its session on this relay.
type rowState struct {
	tag       uint32
	vpc       VPCKey
	networkID uint32
	dst       netip.Addr
	expires   time.Time // The zero time is a row that ended.
}

// to reports whether the packets of w go to relay home. The empty name is
// this relay.
func (w *row) to(home string) bool {
	if w.trunk == nil {
		return home == ""
	}
	return w.trunk.name == home
}

// trunked reports whether sender c can have a row to another relay. That
// relay knows a sender by its tag, which comes with an attachment.
func (r *Router) trunked(c *Session) bool { return r.trunk.Load() != nil && c.tag != 0 }

// trunkFits checks that the path of p carries a PSP packet of size bytes of sender
// s to member home. A nil p is no trunk to home now. It counts the drop if not.
func (r *Router) trunkFits(s *Session, home string, p *trunkPair, size int) Verdict {
	if p == nil {
		s.dropTrunk.Add(1)
		r.drops[dropTrunkKeys].Add(1)
		r.peers.of(home).drops[dropTrunkKeys].Add(1)
		return DropTrunkKeys
	}
	// The limit of the trunk is an inner MTU, and size has the PSP overhead.
	if size > p.mtu()+pspwire.Overhead {
		s.dropTrunk.Add(1)
		r.drops[dropTrunkMTU].Add(1)
		p.stats.drops[dropTrunkMTU].Add(1)
		return DropTrunkMTU
	}
	return Pass
}

// spiTaken reports whether relay home has spi in use for a row that is not w, or
// for a trunk SA. It counts the refusal. Router.mu must be held for writing.
func (r *Router) spiTaken(home string, spi uint32, w *row) bool {
	why, taken := r.trunk.Load().inUse(home, spi, w)
	if taken {
		r.refusals[why].Add(1)
	}
	return taken
}

// aim sends the packets of w to the session of o. For a session of another relay,
// w takes its SPI at that relay: see spiTaken. Router.mu must be held for writing.
func (r *Router) aim(w *row, o owner) {
	if home := o.s.home; !w.to(home) {
		r.untrunk(w)
		if home != "" {
			w.trunk = r.trunk.Load().hold(home, w)
		}
	}
	r.retarget(w, o)
}

// move gives w to o, the new owner of its destination. A relay that did not
// have the receiver before gets the row. Router.mu must be held for writing.
func (r *Router) move(w *row, o owner) {
	// Only a route of another relay goes to another relay, so the sender has a tag.
	home := o.s.home
	told := w.to(home)
	// The new relay can have the SPI in use. Then w ends, and its agent gets new keys.
	if !told && home != "" && r.spiTaken(home, w.spi, w) {
		r.removeRow(w)
		return
	}
	r.aim(w, o)
	if !told {
		r.tellRow(w)
	}
}

// stateOf returns the state of the live row w for the relay that has its
// receiver. Router.mu must be held.
func (r *Router) stateOf(w *row) rowState {
	st := rowState{tag: w.sender.tag, vpc: w.vpc, dst: w.dst, expires: w.expires}
	if d := r.domains[w.vpc]; d != nil && d.known {
		st.networkID = d.networkID
	}
	return st
}

// tellRow gives the row w and its end time to the relay that has its receiver,
// if that is another relay. Router.mu must be held.
func (r *Router) tellRow(w *row) {
	if t := r.trunk.Load(); t != nil && w.trunk != nil {
		t.tell(w.trunk, w.spi, r.stateOf(w))
	}
}

// untrunk takes w off the trunk, and the relay that has its receiver learns
// that the row ended. Router.mu must be held for writing.
func (r *Router) untrunk(w *row) {
	if t := r.trunk.Load(); t != nil && w.trunk != nil {
		st := r.stateOf(w)
		st.expires = time.Time{}
		t.release(w.trunk, w.spi, st)
	}
	w.trunk = nil
}

// liveRows gives ts, the new session of p, each row to the relay of p.
// Router.mu and trunk.mu must be held.
func (r *Router) liveRows(p *trunkPair, ts *trunkSession) {
	for spi, w := range r.trunk.Load().place(p.name).rows {
		ts.rows[spi] = r.stateOf(w)
	}
	if len(ts.rows) > 0 {
		select {
		case ts.rowWake <- struct{}{}:
		default:
		}
	}
}

// tell keeps the state st of the row with spi for the SPIRows call to member m.
// With no session, the next session gets the live rows. Router.mu must be held.
func (t *trunk) tell(m *trunkMember, spi uint32, st rowState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.queue(m, spi, st)
}

// release is tell for the row with spi that ended. Another row to m can have
// the SPI from now. Router.mu must be held.
func (t *trunk) release(m *trunkMember, spi uint32, st rowState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.queue(m, spi, st)
	delete(m.rows, spi)
	t.forget(m)
}

// queue keeps the state st of the row with spi for the session of member m.
// t.mu must be held.
func (t *trunk) queue(m *trunkMember, spi uint32, st rowState) {
	p := t.pairs[m.name]
	if p == nil || p.sess == nil || p.sess.rowsDone {
		return
	}
	ts := p.sess
	// A later state of an SPI replaces the state that waits, also from another row.
	ts.rows[spi] = st
	select {
	case ts.rowWake <- struct{}{}:
	default:
	}
}

// takeRows returns the messages for the rows of ts that wait, in the order of
// the SPIs. A live row has the time that it has left at now.
func (t *trunk) takeRows(ts *trunkSession, now time.Time) []*dp.SPIRowUpdate {
	// The read lock keeps the rows of one change of the router in one take.
	t.r.mu.RLock()
	t.mu.Lock()
	waiting := ts.rows
	ts.rows = map[uint32]rowState{}
	t.mu.Unlock()
	t.r.mu.RUnlock()
	rows := make([]*dp.SPIRow, 0, len(waiting))
	for spi, st := range waiting {
		row := &dp.SPIRow{
			Vpc:       &dp.VPCRef{ProjectId: st.vpc.Project, VpcUid: st.vpc.UID, NetworkId: st.networkID},
			SenderTag: st.tag,
			Spi:       spi,
		}
		if left := st.expires.Sub(now); !st.expires.IsZero() && left > 0 {
			row.Destination, row.ExpiresIn = st.dst.String(), durationpb.New(left)
		} else {
			row.Removed = true
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b *dp.SPIRow) int { return cmp.Compare(a.GetSpi(), b.GetSpi()) })
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
