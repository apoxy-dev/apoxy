// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// maxPairs is the most pairs of an agent.
const maxPairs = 256

// pairRec is the record of a pair in the root.
type pairRec struct {
	p    *pair
	ref  *flowRef
	flow flow
	h    *home     // The session of the own end.
	use  time.Time // The start, or the last head to a prefix that the pair holds.
	st   pairState
	// ending is set after the root sent a message that ends the pair.
	ending bool

	// From pairOpen on.
	open bool
	key  pairKey
	name string
	list []netip.Prefix
	conn connAddrs
	peer *psp.Peer // The direct peer, until removePeerMsg.
	// routes are the direct routes of peer in the binding. srcStale is set when the list changed
	// and SetDirect did not run for it yet.
	routes   []netip.Prefix
	srcStale bool
	useSent  time.Time // The last useMsg.
}

// lastUse returns the time of the last use of the pair: a head or a channel packet.
func (rec *pairRec) lastUse() time.Time {
	u := rec.use
	if n := rec.ref.used.Load(); n != 0 {
		if t := time.Unix(0, n); t.After(u) {
			u = t
		}
	}
	return u
}

// pairSnap is one pair in a snapshot.
type pairSnap struct {
	flow     flow
	open     bool
	name     string
	key      [32]byte
	inst     uint64
	dialed   bool
	prefixes []netip.Prefix // The prefixes that the pair holds, or its channel prefix before the open.
	st       pairState
	noAnswer bool // A dial got no answer while a relay route holds the peer end.
}

// pairTable is the state of the root for its pairs.
type pairTable struct {
	chans  *chanTable
	recs   map[*pair]*pairRec
	flows  map[flow]*pairRec
	byKey  map[pairKey]*pairRec
	claims map[netip.Prefix][]*pairRec // The pairs that list each prefix, in the order of their claims.

	own      *ownSet // The last own addresses of the take-out handler.
	ownB     *psp.Binding
	ownGiven *ownSet // The own addresses of the last SetOwn on ownB.
	cands    *candsVal
	lists    *revLists
	listWarn bool
	// sessEnd is set after the sessions got endMsg at the end of Run.
	sessEnd bool
}

func newPairTable(on bool) pairTable {
	return pairTable{
		chans: newChanTable(on), recs: map[*pair]*pairRec{}, flows: map[flow]*pairRec{},
		byKey: map[pairKey]*pairRec{}, claims: map[netip.Prefix][]*pairRec{},
		own: &ownSet{}, cands: &candsVal{}, lists: &revLists{},
	}
}

// storeFlows gives the take-out handler the flows of the pairs.
func (r *root) storeFlows() {
	m := make(map[flow]*flowRef, len(r.pp.flows))
	for f, rec := range r.pp.flows {
		m[f] = rec.ref
	}
	r.pp.chans.flows.Store(&m)
}

// syncPairs gives the binding, the take-out handler and the pairs the newest own list, own
// candidates and revocation lists. The root runs it after each step.
func (r *root) syncPairs() {
	pp := &r.pp
	live := r.live()
	// The list has the sessions with the oldest attach.
	slices.SortStableFunc(live, func(x, y *home) int { return x.since.Compare(y.since) })
	own := &ownSet{}
	for _, h := range live {
		base := h.st.base.Prefixes
		if len(base) == 0 {
			continue
		}
		if len(own.list) < maxList {
			own.list = append(own.list, base[0])
		} else if !pp.listWarn {
			pp.listWarn = true
			slog.Warn("Agent has more relay sessions than its list holds; the other sessions get no direct paths", "sessions", len(live), "list", maxList)
		}
		own.all = append(own.all, base...)
		for _, x := range h.held {
			own.all = append(own.all, x.at.Prefixes...)
		}
	}
	if len(own.list) > 0 {
		own.vpc = tunnet.NetworkPrefixOf(own.list[0].Addr())
	}
	if !slices.Equal(own.list, pp.own.list) || !slices.Equal(own.all, pp.own.all) || own.vpc != pp.own.vpc {
		pp.own = own
		pp.chans.own.Store(own)
	}
	if r.b != nil && (pp.ownB != r.b || pp.ownGiven != pp.own) {
		r.b.SetOwn(pp.own.list)
		pp.ownB, pp.ownGiven = r.b, pp.own
	}
	if !r.cands.equal(pp.cands.c) || !slices.Equal(pp.cands.own, pp.own.list) {
		pp.cands = &candsVal{c: r.cands, own: slices.Clone(pp.own.list)}
		for _, rec := range pp.recs {
			rec.p.mb.Send(candidatesMsg{pp.cands})
		}
	}
	var src []*revokedList
	for _, h := range r.homes {
		if h.revoked != nil {
			src = append(src, h.revoked)
		}
	}
	if !slices.Equal(src, pp.lists.src) {
		v := &revLists{src: src}
		for _, l := range src {
			v.lists = append(v.lists, l.agents)
		}
		pp.lists = v
		for _, rec := range pp.recs {
			rec.p.mb.Send(revocationsMsg{v})
		}
	}
}

// head takes a packet head on a relay route. A head from the own list to another agent of the VPC
// starts a pair, unless a pair holds its /96 or has its flow; then it is a use of that pair.
func (r *root) head(hd psp.Head, now time.Time) {
	pp := &r.pp
	own := pp.own
	if !pp.chans.on || !inPrefixes(own.list, hd.Src) || !own.vpc.Contains(hd.Dst) || inPrefixes(own.all, hd.Dst) {
		return
	}
	if rec := r.claimHolder(hd.Dst); rec != nil {
		rec.use = now
		return
	}
	p := r.primary()
	if p == nil || len(p.st.base.Prefixes) == 0 || !slices.Contains(own.list, p.st.base.Prefixes[0]) {
		return
	}
	f := flow{own: p.st.base.Address, peer: relay.OverlayAddr(netip.PrefixFrom(hd.Dst, 96).Masked())}
	if rec := pp.flows[f]; rec != nil {
		rec.use = now
		return
	}
	r.startPair(f, p, nil, now)
}

// claimHolder returns the pair that holds a prefix with a, or nil.
func (r *root) claimHolder(a netip.Addr) *pairRec {
	for pfx, recs := range r.pp.claims {
		if len(recs) > 0 && pfx.Contains(a) {
			return recs[0]
		}
	}
	return nil
}

// initial takes a QUIC Initial of no known flow: it starts a pair on the accept side.
func (r *root) initial(m initialMsg) {
	pp := &r.pp
	if r.ending || r.b == nil {
		return
	}
	if rec := pp.flows[m.flow]; rec != nil {
		rec.ref.rx.Send(m.pkt)
		return
	}
	if !inPrefixes(pp.own.list, m.flow.own) {
		return
	}
	i := slices.IndexFunc(r.live(), func(h *home) bool { return h.st.base.Address == m.flow.own })
	if i < 0 {
		return
	}
	r.startPair(m.flow, r.live()[i], &m.pkt, time.Now())
}

// startPair starts a pair on the flow f from the session h. Above maxPairs it ends the pair with
// the oldest use, and starts none: the next head or Initial starts it after the slot is free.
func (r *root) startPair(f flow, h *home, first *chanPkt, now time.Time) {
	pp := &r.pp
	if len(pp.recs) >= maxPairs {
		r.evict()
		return
	}
	ref := &flowRef{rx: proc.NewMailbox(pairRx)}
	if first != nil {
		ref.used.Store(now.UnixNano())
		ref.rx.Send(*first)
	}
	p := newPair(r.a, r.mb, pairStart{
		flow: f, inst: r.a.instance, relay: h.st.peer, b: r.b, dial: first == nil, ref: ref,
		cands: pp.cands, lists: pp.lists,
	})
	rec := &pairRec{p: p, ref: ref, flow: f, h: h, use: now}
	pp.recs[p], pp.flows[f] = rec, rec
	r.storeFlows()
	go p.run()
}

// evict ends the pair with the oldest use, unless one ends already.
func (r *root) evict() {
	var old *pairRec
	for _, rec := range r.pp.recs {
		if rec.ending {
			return
		}
		if old == nil || rec.lastUse().Before(old.lastUse()) {
			old = rec
		}
	}
	if old != nil {
		slog.Info("Agent has the most peer channels; closed the one with the oldest use", "peer", old.flow.peer, "pairs", maxPairs)
		r.endPair(old, evictMsg{})
	}
}

// endPair sends m, which ends the pair of rec, one time.
func (r *root) endPair(rec *pairRec, m any) {
	if !rec.ending {
		rec.ending = true
		rec.p.mb.Send(m)
	}
}

// pairOpen opens the channel of a pair whose Hello passed, with a direct peer in the binding.
// Two pairs with one fingerprint and instance keep the one whose connection has the lower QUIC
// client address, then the lower server address.
func (r *root) pairOpen(m pairOpen) {
	pp := &r.pp
	rec := pp.recs[m.p]
	if rec == nil || rec.ending {
		return
	}
	if o := pp.byKey[m.key]; o != nil && o != rec && !o.ending {
		if o.conn.less(m.conn) {
			r.endPair(rec, dupMsg{})
			return
		}
		r.endPair(o, dupMsg{})
	}
	// The direct peer has no address until a path passes.
	peer, err := r.b.AddDirect(netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if err == nil {
		if err = r.b.SetDirect(peer, m.list, nil); err != nil {
			r.b.RemovePeer(peer)
		}
	}
	if err != nil {
		slog.Warn("Failed to add a direct peer", "peer", m.name, "error", err)
		r.endPair(rec, endMsg{})
		return
	}
	rec.open, rec.key, rec.name, rec.conn, rec.peer = true, m.key, m.name, m.conn, peer
	pp.byKey[m.key] = rec
	r.claim(rec, m.list)
	r.held()
	m.p.mb.Send(openOK{peer})
}

// peerListMsg takes a new list of an open pair.
func (r *root) peerListMsg(m peerList) {
	rec := r.pp.recs[m.p]
	if rec == nil || !rec.open || rec.peer == nil {
		return
	}
	r.claim(rec, m.list)
	r.held()
	rec.srcStale = true
	r.directRoutes()
}

// held sends heldMsg to each pair that is not open while an open pair holds its peer end, as a
// head to a held prefix starts no pair. The root also runs it at each tick.
func (r *root) held() {
	for _, rec := range r.pp.recs {
		if rec.open || rec.ending {
			continue
		}
		// An open pair with no direct peer ends.
		if h := r.claimHolder(rec.flow.peer); h != nil && h.peer != nil && !h.ending {
			rec.p.mb.Send(heldMsg{})
		}
	}
}

// pairStatus takes the newest state of a pair. While it is direct, the direct peer sends to the
// address of the path, and the root sets its routes.
func (r *root) pairStatus(m pairStatus) {
	rec := r.pp.recs[m.p]
	if rec == nil {
		return
	}
	rec.st = m.st
	if m.st.direct && rec.peer != nil && rec.peer.Addr() != m.st.addr {
		rec.peer.SetAddr(m.st.addr)
	}
	r.directRoutes()
}

// directRoutes makes the direct routes of each pair the prefixes that it holds while it is direct.
// The routes that go out go out first, so a prefix that moves is never on two peers.
func (r *root) directRoutes() {
	want := map[*pairRec][]netip.Prefix{}
	for pfx, recs := range r.pp.claims {
		if rec := recs[0]; rec.peer != nil && rec.st.direct {
			want[rec] = append(want[rec], pfx)
		}
	}
	for _, rec := range r.pp.recs {
		if rec.peer == nil {
			continue
		}
		keep := slices.DeleteFunc(slices.Clone(rec.routes), func(p netip.Prefix) bool { return !slices.Contains(want[rec], p) })
		if len(keep) != len(rec.routes) {
			r.setDirect(rec, keep)
		}
	}
	for _, rec := range r.pp.recs {
		if rec.peer == nil {
			continue
		}
		w := want[rec]
		slices.SortFunc(w, netip.Prefix.Compare)
		if rec.srcStale || !slices.Equal(w, rec.routes) {
			r.setDirect(rec, w)
		}
	}
}

// setDirect gives the direct peer of rec the list of the peer as its sources and routes as its routes.
func (r *root) setDirect(rec *pairRec, routes []netip.Prefix) {
	if err := r.b.SetDirect(rec.peer, rec.list, routes); err != nil {
		slog.Warn("Failed to set the routes of a direct peer", "peer", rec.name, "routes", routes, "error", err)
		return
	}
	if len(routes) != len(rec.routes) {
		slog.Debug("Changed the direct routes to a peer agent", "peer", rec.name, "routes", routes)
	}
	rec.routes, rec.srcStale = routes, false
}

// useEvery is the least time between two useMsg to one pair.
const useEvery = 10 * time.Second

// uses tells each pair with a use since its last useMsg about it, at most each useEvery.
func (r *root) uses(now time.Time) {
	for _, rec := range r.pp.recs {
		if !rec.ending && rec.lastUse().After(rec.useSent) && now.Sub(rec.useSent) >= useEvery {
			rec.useSent = now
			rec.p.mb.Send(useMsg{})
		}
	}
}

// claim makes list the list of rec. A prefix stays with the pair that listed it first, until that
// pair ends or sends a list without it.
func (r *root) claim(rec *pairRec, list []netip.Prefix) {
	cl := r.pp.claims
	for _, p := range rec.list {
		if !slices.Contains(list, p) {
			if cl[p] = slices.DeleteFunc(cl[p], func(o *pairRec) bool { return o == rec }); len(cl[p]) == 0 {
				delete(cl, p)
			}
		}
	}
	for _, p := range list {
		if !slices.Contains(rec.list, p) {
			cl[p] = append(cl[p], rec)
		}
	}
	rec.list = list
}

// removeDirect takes the direct peer of a pair that ends out of the binding: its routes, then its SAs.
func (r *root) removeDirect(m removePeerMsg) {
	if rec := r.pp.recs[m.p]; rec != nil && rec.peer != nil {
		r.b.RemovePeer(rec.peer)
		rec.peer, rec.routes = nil, nil
	}
	m.p.mb.Send(peerRemoved{})
}

// pairEnded frees the slot, the flow and the prefixes of a pair.
func (r *root) pairEnded(m pairEnded) {
	pp := &r.pp
	rec := pp.recs[m.p]
	if rec == nil {
		return
	}
	delete(pp.recs, m.p)
	if pp.flows[rec.flow] == rec {
		delete(pp.flows, rec.flow)
		r.storeFlows()
	}
	if pp.byKey[rec.key] == rec {
		delete(pp.byKey, rec.key)
	}
	r.claim(rec, nil)
	// The next pair that lists a prefix of rec holds it now.
	r.directRoutes()
	if r.ending && len(pp.recs) == 0 && !pp.sessEnd {
		// The relays get the close of the last channel before the sessions end.
		r.task(func() any {
			time.Sleep(closeLinger)
			return lingerDone{}
		})
	}
}

// endPairsOf ends the pairs whose own end is on the session h.
func (r *root) endPairsOf(h *home) {
	for _, rec := range r.pp.recs {
		if rec.h == h {
			r.endPair(rec, endMsg{})
		}
	}
}

// closeLinger is the wait between the end of the last pair and the end of the sessions at the end of
// Run, so that the relays forward the close of each channel.
const closeLinger = 200 * time.Millisecond

// lingerDone is the end of the wait for the close of the channels at the end of Run.
type lingerDone struct{}

// endSessions ends the sessions at the end of Run, after the pairs ended, so that the close of
// each channel goes out on its relay session.
func (r *root) endSessions() {
	if r.pp.sessEnd || len(r.pp.recs) > 0 {
		return
	}
	r.pp.sessEnd = true
	// The end of the root context ends the sessions and the tasks of the root.
	r.cancel()
	for _, h := range r.homes {
		h.s.mb.Send(endMsg{})
	}
}

// pairOf returns the pair whose direct peer is p, or nil.
func (r *root) pairOf(p *psp.Peer) *pairRec {
	for _, rec := range r.pp.recs {
		if rec.peer == p {
			return rec
		}
	}
	return nil
}

// relayRouted reports whether a relay route of a session holds a.
func (r *root) relayRouted(a netip.Addr) bool {
	for _, h := range r.homes {
		for p := range h.routes {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// pairSnaps returns the pairs for the snapshot, by flow.
func (r *root) pairSnaps() []pairSnap {
	var out []pairSnap
	for _, rec := range r.pp.recs {
		s := pairSnap{
			flow: rec.flow, open: rec.open, name: rec.name, key: rec.key.key, inst: rec.key.inst,
			dialed: rec.open && rec.conn.client == rec.flow.own, st: rec.st,
		}
		if rec.peer == nil {
			// The direct peer of an ending pair is out of the binding, so the pair has no direct path.
			s.st.direct, s.st.probing, s.st.addr, s.st.rtt = false, false, netip.AddrPort{}, 0
		}
		if !rec.open {
			s.prefixes = []netip.Prefix{netip.PrefixFrom(rec.flow.peer, 96).Masked()}
			s.noAnswer = rec.st.noAnswer && r.relayRouted(rec.flow.peer)
		}
		for p, recs := range r.pp.claims {
			if recs[0] == rec {
				s.prefixes = append(s.prefixes, p)
			}
		}
		slices.SortFunc(s.prefixes, netip.Prefix.Compare)
		out = append(out, s)
	}
	slices.SortFunc(out, func(x, y pairSnap) int {
		return cmp.Or(x.flow.peer.Compare(y.flow.peer), x.flow.own.Compare(y.flow.own))
	})
	return out
}

// DirectState is the state of a pair.
type DirectState string

const (
	// DirectOpening is a pair whose channel is not open yet.
	DirectOpening DirectState = "opening"
	// DirectProbing is a pair with an open channel that probes the candidates of the peer or
	// tests a path.
	DirectProbing DirectState = "probing"
	// DirectDirect is a pair with a direct path: its data goes direct to the peer.
	DirectDirect DirectState = "direct"
	// DirectRelay is a pair with no direct path whose data goes on the relay route: its channel is
	// open, or its peer has no direct paths.
	DirectRelay DirectState = "relay"
)

// The reasons of a pair with no direct path.
const (
	// ReasonNoDirectPaths is the reason of a pair whose dial got no answer while the relay route
	// to the peer is in: the peer is too old, or it has direct paths off.
	ReasonNoDirectPaths = "peer has no direct paths"
	// ReasonProbeFailed is a probe run with no reply from a candidate of the peer.
	ReasonProbeFailed = "probe failed"
	// ReasonPSPTestFailed is a path whose outer probes passed and whose PSP test failed.
	ReasonPSPTestFailed = "PSP test failed"
	// ReasonNoSAs is a path whose outer probes passed while the pair had no SAs both ways.
	ReasonNoSAs = "no SAs"
)

// DirectStatus is one pair: the state of the agent for one peer agent.
type DirectStatus struct {
	Peer     string // Agent name of the peer cert. Empty before the Hello.
	Key      string // SHA-256 of the public key of the peer cert, in hex.
	Instance string // Instance of the peer process in 16 hex digits. Empty before the Hello.
	// Prefixes are the prefixes of the peer list that the pair holds, or the channel prefix of
	// the peer before the Hello. Data to a held prefix goes direct while State is direct.
	Prefixes []netip.Prefix
	State    DirectState
	// Dialed is true when this agent dialed the channel: it is the QUIC client.
	Dialed  bool
	Address netip.AddrPort // The address of the direct path while State is direct.
	RTT     time.Duration  // The time of the probe reply of Address.
	Reason  string         // Why the pair has no direct path, or empty.
}

func (s pairSnap) status() DirectStatus {
	st := DirectStatus{Peer: s.name, Prefixes: slices.Clone(s.prefixes), State: DirectOpening, Reason: s.st.reason}
	if s.open {
		st.Key, st.Instance, st.State, st.Dialed = hex.EncodeToString(s.key[:]), instanceString(s.inst), DirectRelay, s.dialed
		switch {
		case s.st.direct:
			st.State, st.Address, st.RTT = DirectDirect, s.st.addr, s.st.rtt
		case s.st.probing:
			st.State = DirectProbing
		}
	}
	if s.noAnswer {
		st.State, st.Reason = DirectRelay, ReasonNoDirectPaths
	}
	return st
}
