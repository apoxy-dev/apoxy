// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// inRows are the SPI rows that one member gave on one mesh session, for its
// senders and the receivers on this relay. Router.mu guards them.
type inRows struct {
	sess *MeshSession
	rows map[rowKey]*inRow
}

// inRow is one row of a member: where the PSP packets of a sender tag and an
// SPI go. The fields do not change.
type inRow struct {
	vpc     VPCKey
	dst     netip.Addr
	expires time.Time
	hop     atomic.Pointer[inHop] // Last result of the checks of the row.
}

// inHop is the result of the checks of an inRow at one epoch of the router.
type inHop struct {
	epoch uint64
	to    *Session    // Receiver on this relay, or nil.
	att   *Attachment // Attachment of the destination at the receiver, or nil.
	why   dropReason  // Reason that the row has no receiver.
}

// SPIRows keeps the SPI rows that the calling relay gives for its senders. A
// session has one SPIRows call, and a row with a wrong form does not end it.
func (m *Mesh) SPIRows(ctx context.Context, st rpc.ClientStreamServer[dp.SPIRowUpdate]) (*emptypb.Empty, error) {
	s, err := m.SessionOf(ctx)
	if err != nil {
		return nil, err
	}
	t := m.trunk.Load()
	if t == nil {
		return nil, rpc.Errorf(rpc.Unimplemented, "relay has no trunk")
	}
	if err := t.rowsFrom(s); err != nil {
		return nil, err
	}
	for {
		u, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return &emptypb.Empty{}, nil
		}
		if err != nil {
			return nil, err
		}
		if err := t.setRows(s, u, time.Now()); err != nil {
			return nil, err
		}
	}
}

// rowsFrom makes s the session whose SPIRows call gives the rows of its
// member. The rows from a session before s end.
func (t *trunk) rowsFrom(s *MeshSession) error {
	if got := s.Version().GetRevision(); got < trunkRowsRevision {
		return rpc.Errorf(rpc.FailedPrecondition, "revision %d has no SPI rows", got)
	}
	// Mesh.mu keeps a newer session out, so that its rows do not come first.
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	if mem := t.m.members[s.name]; mem == nil || mem.sess != s {
		return rpc.Errorf(rpc.FailedPrecondition, "relay %q is not a member with this session", s.name)
	}
	r := t.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if in := r.in[s.name]; in != nil && in.sess == s {
		return rpc.Errorf(rpc.FailedPrecondition, "session already has an SPIRows call")
	}
	r.in[s.name] = &inRows{sess: s, rows: map[rowKey]*inRow{}}
	return nil
}

// setRows keeps the rows of u, from the SPIRows call of s. The rows with a
// wrong form get one warning.
func (t *trunk) setRows(s *MeshSession, u *dp.SPIRowUpdate, now time.Time) error {
	type change struct {
		k rowKey
		w *inRow // Nil removes the row.
	}
	changes := make([]change, 0, len(u.GetRows()))
	var refused int
	var reason error
	for _, row := range u.GetRows() {
		k, w, err := checkRow(row, now)
		if err != nil {
			if refused++; reason == nil {
				reason = fmt.Errorf("row of sender tag %d and SPI %#x: %w", k.tag, k.spi, err)
			}
			continue
		}
		changes = append(changes, change{k, w})
	}
	if refused > 0 {
		slog.Warn("Refused SPI rows of a mesh member", "relay", s.Name(), "count", refused, "reason", reason)
	}
	r := t.r
	r.mu.Lock()
	defer r.mu.Unlock()
	in := r.in[s.name]
	if in == nil || in.sess != s {
		return rpc.Errorf(rpc.FailedPrecondition, "mesh session ended")
	}
	for _, c := range changes {
		if c.w == nil {
			delete(in.rows, c.k)
		} else {
			in.rows[c.k] = c.w
		}
	}
	return nil
}

// checkRow checks the form of one row of a member at now. It returns the key
// of the row and its data, or no data for a row that the member removed.
func checkRow(row *dp.SPIRow, now time.Time) (rowKey, *inRow, error) {
	k := rowKey{row.GetSenderTag(), row.GetSpi()}
	switch {
	case k.tag == 0 || k.tag > pspwire.MaxVNI:
		return k, nil, fmt.Errorf("sender tag is not from 1 to %d", pspwire.MaxVNI)
	case pspwire.ReservedSPI(k.spi):
		return k, nil, errors.New("SPI is reserved")
	case row.GetRemoved():
		return k, nil, nil
	}
	vpc, err := KeyOf(row.GetVpc())
	if err != nil {
		return k, nil, err
	}
	dst, err := netip.ParseAddr(row.GetDestination())
	if err != nil {
		return k, nil, fmt.Errorf("destination: %w", err)
	}
	left := row.GetExpiresIn().AsDuration()
	if row.GetExpiresIn().CheckValid() != nil || left <= 0 {
		return k, nil, errors.New("expires_in is not positive")
	}
	return k, &inRow{vpc: vpc, dst: dst.Unmap(), expires: now.Add(left)}, nil
}

// endIn ends the rows that member name gave on a session that is not cur.
func (r *Router) endIn(name string, cur *MeshSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if in := r.in[name]; in != nil && in.sess != cur {
		delete(r.in, name)
	}
}

// sweepIn removes the rows of the members that ended at their time, and the
// empty row set of a session that ended. Router.mu must be held for writing.
func (r *Router) sweepIn(now time.Time) {
	for name, in := range r.in {
		for k, w := range in.rows {
			if now.After(w.expires) {
				delete(in.rows, k)
			}
		}
		if len(in.rows) == 0 && in.sess.Context().Err() != nil {
			delete(r.in, name)
		}
	}
}

// pass sends pkt, the PSP packet of the sender tag on member home, to its
// receiver on this relay with fwd. If it drops pkt, it returns the reason.
func (r *Router) pass(home string, tag uint32, pkt []byte, fwd forwarder, now time.Time) (dropReason, bool) {
	h, err := pspwire.ParseHeader(pkt)
	if err != nil {
		return dropMalformed, false
	}
	dst, why, ok := r.receiverOf(home, tag, h.SPI, len(pkt), now)
	if !ok {
		return why, false
	}
	// The receiver gets the packet of the sender with no change.
	fwd.add(pkt, dst)
	return 0, true
}

// receiverOf returns where a PSP packet of size bytes with spi goes, for the
// sender tag on member home, and counts it. If not, it returns the drop reason.
func (r *Router) receiverOf(home string, tag, spi uint32, size int, now time.Time) (netip.AddrPort, dropReason, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var w *inRow
	in := r.in[home]
	if in != nil {
		w = in.rows[rowKey{tag, spi}]
	}
	switch {
	case w == nil:
		return netip.AddrPort{}, dropTrunkNoRow, false
	case now.After(w.expires):
		return netip.AddrPort{}, dropTrunkExpired, false
	}
	h := w.hop.Load()
	// A route, Permit or an entry of a member changed after the last checks.
	if h == nil || h.epoch != r.epoch.Load() {
		h = r.check(in, tag, w)
		w.hop.Store(h)
	}
	if h.to == nil {
		return netip.AddrPort{}, h.why, false
	}
	// The relay of the sender applied the meter of the row and the tunnel limit.
	if h.att != nil {
		h.att.count.packets.Add(1)
		h.att.count.bytes.Add(uint64(size - pspwire.Overhead))
	}
	// The row has no SA lane of the receiver, so the packet goes to the session address.
	return h.to.dst(0), 0, true
}

// check does the checks of row w of in for tag: the entry of the sender,
// Permit and the route of the destination. Router.mu must be held.
func (r *Router) check(in *inRows, tag uint32, w *inRow) *inHop {
	// The epoch is read first, so that a change during the checks ends the result.
	h := &inHop{epoch: r.epoch.Load()}
	inVPC := func(e *presenceEntry) bool { return e.vpc == w.vpc }
	from, _ := r.trunk.Load().m.pres.tagged(in.sess, tag, dropTrunkSender, inVPC)
	switch {
	case from == nil:
		h.why = dropTrunkSender
	case !r.permit(w.vpc, from.subject, w.vpc, w.dst):
		h.why = dropTrunkPermit
	default:
		// The packet came from another relay, so it goes to no other relay.
		if o := r.localOwner(w.vpc, w.dst); o.s != nil {
			h.to, h.att = o.s, o.att
		} else {
			h.why = dropTrunkNotLocal
		}
	}
	return h
}
