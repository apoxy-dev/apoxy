// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"slices"
	"sync/atomic"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// AttachmentStats is the identity and the counters of one attachment. The
// counters start at zero at the attach and do not decrease.
type AttachmentStats struct {
	// ID is the attachment ID. The Tunnel of the attachment has it as its name.
	ID string
	// Instance is the attach order number in the router.
	Instance uint64
	VPC      VPCKey
	// Network is the name of the VPC network object.
	Network string
	// Name is the name that the agent gave.
	Name string
	// Build is the build of the agent, from Hello.
	Build string
	// Since is the time of the attach.
	Since time.Time
	// RTT is the smoothed round-trip time of the relay session. Zero is no sample.
	RTT time.Duration

	// RXPackets and RXBytes count the inner packets from the agent that the
	// relay sent on. The oldest attachment of a session has all of them.
	RXPackets, RXBytes uint64
	// RXDrops counts the packets from the agent that the relay dropped.
	RXDrops uint64
	// TXPackets and TXBytes count the inner packets that the relay sent to the
	// addresses and the routes of the attachment.
	TXPackets, TXBytes uint64
}

// tally counts PSP packets and their UDP payload bytes.
type tally struct{ packets, bytes uint64 }

func (t *tally) add(o tally) {
	t.packets += o.packets
	t.bytes += o.bytes
}

// since returns t without the counts of base. A count below base gives zero.
func (t tally) since(base tally) tally {
	return tally{sub(t.packets, base.packets), sub(t.bytes, base.bytes)}
}

// inner returns the inner bytes of t. Each PSP packet has pspwire.Overhead
// bytes that are not of its inner packet.
func (t tally) inner() uint64 { return sub(t.bytes, t.packets*pspwire.Overhead) }

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// counts are the counters of AttachmentStats.
type counts struct {
	rxPackets, rxBytes, rxDrops uint64
	txPackets, txBytes          uint64
}

// attCount holds the counts of the packets to one attachment.
type attCount struct {
	// rows has the counts of the rows that ended or went to another
	// attachment. Router.mu guards it.
	rows tally
	// packets and bytes count the inner packets that the relay sent to the
	// attachment as data frames, sealed, or in the PSP packets of another relay.
	packets, bytes atomic.Uint64
	// last has the largest counters that a read returned. Router.statsMu guards it.
	last counts
}

// atLeast returns st with no counter below the last read, and keeps it. The
// counters of a row are read one after the other, so a read can be low.
func (c *attCount) atLeast(st AttachmentStats) AttachmentStats {
	l := &c.last
	l.rxPackets = max(l.rxPackets, st.RXPackets)
	l.rxBytes = max(l.rxBytes, st.RXBytes)
	l.rxDrops = max(l.rxDrops, st.RXDrops)
	l.txPackets = max(l.txPackets, st.TXPackets)
	l.txBytes = max(l.txBytes, st.TXBytes)
	st.RXPackets, st.RXBytes, st.RXDrops = l.rxPackets, l.rxBytes, l.rxDrops
	st.TXPackets, st.TXBytes = l.txPackets, l.txBytes
	return st
}

// OnAttachmentEnd sets the function that gets the last counters of each
// attachment that ends. It runs with no router lock. Set it before Serve.
func (r *Router) OnAttachmentEnd(fn func(AttachmentStats)) { r.onEnd.Store(&fn) }

func (r *Router) ended(st AttachmentStats) {
	if fn := r.onEnd.Load(); fn != nil {
		(*fn)(st)
	}
}

// AttachmentStats returns the counters of each live attachment, sorted by ID.
func (r *Router) AttachmentStats() []AttachmentStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Each live row is a row of its sender, so one pass reads each row one time.
	rx := make(map[*Session]counts, len(r.sessions))
	tx := map[*Attachment]tally{}
	for s := range r.sessions {
		rx[s] = r.rxOf(s, tx)
	}
	// The XDP rows of the members also send to the attachments.
	r.xdpFromMembers(tx)
	var out []AttachmentStats
	r.statsMu.Lock()
	for s := range r.sessions {
		for i, a := range s.attachments {
			out = append(out, a.count.atLeast(r.statsOf(s, a, i == 0, rx[s], tx[a])))
		}
	}
	r.statsMu.Unlock()
	slices.SortFunc(out, func(a, b AttachmentStats) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// total returns the counts of w with its XDP rows, and the lane meter drops of
// the XDP rows. Router.mu must be held.
func (r *Router) total(w *row) (tally, uint64) {
	x := r.xdpCountersOf(w)
	return tally{w.packets.Load() + x.packets, w.bytes.Load() + x.bytes}, x.drops
}

// rxOf returns the RX counters of s. If tx is not nil, it adds the counts of
// each live row to its attachment in tx. Router.mu must be held.
func (r *Router) rxOf(s *Session, tx map[*Attachment]tally) counts {
	rows := s.rxRows
	drops := s.dropUnknownSPI.Load() + s.dropMeter.Load() + s.dropTunnel.Load() + s.dropTrunk.Load() + s.dataDrops.Load() + r.xdpTunnelDrops(s)
	for _, w := range s.rows {
		t, d := r.total(w)
		n := t.since(w.done)
		rows.add(n)
		drops += d
		if tx != nil && w.att != nil {
			sum := tx[w.att]
			sum.add(n)
			tx[w.att] = sum
		}
	}
	return counts{
		rxPackets: rows.packets + s.framePackets.Load(),
		rxBytes:   rows.inner() + s.frameBytes.Load(),
		rxDrops:   drops,
	}
}

// statsOf returns the stats of a: the RX of s if a is its oldest attachment,
// and the counts of live for its rows. Router.mu must be held.
func (r *Router) statsOf(s *Session, a *Attachment, oldest bool, rx counts, live tally) AttachmentStats {
	t := a.count.rows
	t.add(live)
	st := AttachmentStats{
		ID:        a.ID,
		Instance:  a.seq,
		VPC:       a.VPC,
		Network:   a.Network,
		Name:      a.Name,
		Build:     s.version.GetBuild(),
		Since:     a.since,
		TXPackets: t.packets + a.count.packets.Load(),
		TXBytes:   t.inner() + a.count.bytes.Load(),
	}
	if s.rtt != nil {
		st.RTT = time.Duration(s.rtt.Load())
	}
	if oldest {
		st.RXPackets = sub(rx.rxPackets, s.rxBase.rxPackets)
		st.RXBytes = sub(rx.rxBytes, s.rxBase.rxBytes)
		st.RXDrops = sub(rx.rxDrops, s.rxBase.rxDrops)
	}
	return st
}

// last returns the final counters of a. With oldest, a had the RX of s.
// Router.mu must be held for writing, after an XDP sync.
func (r *Router) last(s *Session, a *Attachment, oldest bool) AttachmentStats {
	rx := r.rxOf(s, nil)
	var live tally
	for w := range s.inbound {
		if w.att == a {
			t, _ := r.total(w)
			live.add(t.since(w.done))
		}
	}
	in := map[*Attachment]tally{}
	r.xdpFromMembers(in)
	live.add(in[a])
	st := r.statsOf(s, a, oldest, rx, live)
	if oldest {
		s.rxBase = rx
	}
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return a.count.atLeast(st)
}

// endAttachments removes the attachments of the closed session s. It returns
// them with their last counters.
func (r *Router) endAttachments(s *Session) ([]*Attachment, []AttachmentStats) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// The sync adds the last XDP counts of the rows of s to the totals.
	r.syncXDP(time.Now())
	atts := s.attachments
	s.attachments = nil
	out := make([]AttachmentStats, len(atts))
	for i, a := range atts {
		out[i] = r.last(s, a, i == 0)
	}
	return atts, out
}

// fold gives the counts of w that no total has to the totals of its sender
// and of its attachment. Router.mu must be held for writing.
func (r *Router) fold(w *row) {
	t, _ := r.total(w)
	n := t.since(w.done)
	w.sender.rxRows.add(n)
	if w.att != nil {
		w.att.count.rows.add(n)
	}
	w.done = tally{max(t.packets, w.done.packets), max(t.bytes, w.done.bytes)}
}

// retarget sends the packets of w to o. The attachment before keeps the counts
// up to now. Router.mu must be held for writing.
func (r *Router) retarget(w *row, o target) {
	r.fold(w)
	if w.receiver != o.s {
		if w.receiver != nil {
			delete(w.receiver.inbound, w)
		}
		w.receiver = o.s
		o.s.inbound[w] = struct{}{}
		r.markXDP(w.sender)
	}
	w.att = o.att
}

type traceKey struct{}

// connTrace is what the tracer of one connection keeps for its session.
type connTrace struct {
	rtt atomic.Int64 // Smoothed RTT in nanoseconds.
	// heard is set for each packet of an agent. The liveness check clears it.
	heard atomic.Bool
}

// TraceContext gives a new connection the place for what TraceRTT keeps. It is
// the ConnContext of the QUIC transports of a relay with TraceRTT.
func TraceContext(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	return context.WithValue(ctx, traceKey{}, new(connTrace)), nil
}

// TraceRTT is the Tracer of a relay with TraceContext. It keeps the smoothed
// RTT for AttachmentStats and marks agent packets for liveness.
func TraceRTT(ctx context.Context, _ logging.Perspective, _ quic.ConnectionID) *logging.ConnectionTracer {
	tr := traceOf(ctx)
	if tr == nil {
		return nil
	}
	t := &logging.ConnectionTracer{
		UpdatedMetrics: func(s *logging.RTTStats, _, _ logging.ByteCount, _ int) {
			tr.rtt.Store(int64(s.SmoothedRTT()))
		},
	}
	// The received-packet hook costs a frame list for each packet, so only an
	// agent session gets it. Hooks of one connection run in turn.
	t.ChoseALPN = func(alpn string) {
		if alpn == dp.ALPNRelay {
			t.ReceivedShortHeaderPacket = func(*logging.ShortHeader, logging.ByteCount, logging.ECN, []logging.Frame) {
				tr.heard.Store(true)
			}
		}
	}
	return t
}

// traceOf returns what the tracer keeps for the connection of ctx, or nil.
func traceOf(ctx context.Context) *connTrace {
	tr, _ := ctx.Value(traceKey{}).(*connTrace)
	return tr
}

// rttOf returns the place for the RTT of the connection of ctx, or nil.
func rttOf(ctx context.Context) *atomic.Int64 {
	if tr := traceOf(ctx); tr != nil {
		return &tr.rtt
	}
	return nil
}
