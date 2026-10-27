// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// vpcProc is the process V of one VPC: the only decider of its routes. It selects the candidates
// of each prefix and writes the route entries of its VPC.
type vpcProc struct {
	r      *Router
	c      *vChild
	ctx    context.Context
	cancel context.CancelFunc
	net    Network
	name   string // The VPC name in the data plane.
	trust  *trustGen

	sets    map[netip.Prefix]*routeSet
	entries map[netip.Prefix]dp.ForwardAction // The route entries in the data plane.
	holds   map[netip.Prefix]time.Time        // The next end of a hold time of each prefix.
	timer   *time.Timer
	timerAt time.Time
	as      map[uint64]*aChild
	gen     uint64

	draining bool
	alts     []*dpv1.RelayRef
	ending   bool

	// ann is the announcement set of the attachments of this relay, for the members.
	ann      map[string]*dpv1.Presence
	annDirty bool
	// members has the candidates of the records of each member, by the key of the member.
	members map[string]*vMember

	// touched has the prefixes whose candidates changed in this step. The reports of remote
	// addresses that overlap them are checked again.
	touched map[netip.Prefix]struct{}
	// reports is the number of attachments with a report of remote addresses.
	reports int

	// dirty is true when the route table changed. unsynced has the prefixes whose route entries
	// go in the next tables event. shown is the route table that the A processes have: V stores a
	// new one after the write of its route entries.
	dirty    bool
	unsynced map[netip.Prefix]struct{}
	shown    *routeTable
	w        tableWriter
	asks     map[uint64]map[uint64]struct{} // The ports that did not answer each stats ask.
	out      map[uint64][]AttachmentStats
	// final is true after the last A ended: V deletes its entries, and over is true after that.
	final bool
	over  bool
}

// vMember is the candidates of the records of one member in V.
type vMember struct {
	values *memberValues
	cands  map[string]*record // The record of each candidate, by attachment ID.
}

// aChild is the V side of one A.
type aChild struct {
	port   uint64
	tag    uint32
	l      *link
	box    *mailbox
	down   *valueMap
	up     *valueMap
	cancel context.CancelFunc
	s      session
	state  dpv1.AnnouncerState
	// cands has the candidate of each attachment of A in the selection.
	cands map[string]*candidate
	// prefixes has the prefixes of each attachment of A in the selection.
	prefixes map[string][]netip.Prefix
	// atts has the remote addresses of each attachment of A.
	atts map[string]*vAtt
}

// vAtt is what V keeps of one attachment of A for its fallback candidates.
type vAtt struct {
	cell  uint32         // The transmit cell of the attachment.
	addrs []netip.Prefix // The addresses that this relay gave it.
	// report is the last report of remote addresses of the attachment, whole.
	report []remoteAddr
	// fallback has the fallback candidate of each remote address that V accepted.
	fallback map[netip.Prefix]*announcer
	// failed is true after the write of the fallback candidates of report failed. Only a new
	// report makes candidates again.
	failed bool
	// gen counts the changes of the fallback candidates.
	gen uint64
}

// startVPC starts the V of v.
func startVPC(r *Router, c *vChild) {
	ctx, cancel := context.WithCancel(context.Background())
	v := &vpcProc{
		r:        r,
		c:        c,
		ctx:      ctx,
		cancel:   cancel,
		net:      c.net,
		name:     vpcName(c.key, c.net.ID),
		sets:     map[netip.Prefix]*routeSet{},
		entries:  map[netip.Prefix]dp.ForwardAction{},
		holds:    map[netip.Prefix]time.Time{},
		as:       map[uint64]*aChild{},
		asks:     map[uint64]map[uint64]struct{}{},
		out:      map[uint64][]AttachmentStats{},
		ann:      map[string]*dpv1.Presence{},
		members:  map[string]*vMember{},
		unsynced: map[netip.Prefix]struct{}{},
	}
	v.shown = v.table()
	v.trust = load[*trustGen](c.down, keyTrust)
	watch(ctx, c.down, func(keys []string) { c.box.send(valuesChanged{keys: keys}) })
	go v.run()
}

type holdEv struct{}

func (v *vpcProc) run() {
	for {
		for _, e := range v.c.box.take() {
			v.handle(e)
		}
		if !v.final {
			v.recheck(time.Now())
			if v.ending && len(v.as) == 0 {
				v.end()
			}
		}
		v.flush()
		if v.over {
			v.finish()
			return
		}
		<-v.c.box.sig
	}
}

// up sends msg to the root.
func (v *vpcProc) up(msg any) { v.r.box.send(fromV{v: v.c, msg: msg}) }

func (v *vpcProc) handle(e any) {
	if v.final {
		v.refuse(e)
		return
	}
	switch e := e.(type) {
	case toConn:
		v.startConn(e)
	case valuesChanged:
		v.changed(e.keys)
	case holdEv:
		v.holdsEnded(time.Now())
	case toAssigned:
		v.toA(e.port, e)
	case toKeysDone:
		v.toA(e.port, e)
	case toRekeyed:
		v.toA(e.port, e)
	case toTablesDone:
		if e.port == 0 {
			v.w.done(e.err)
		} else {
			v.toA(e.port, e)
		}
	case toPacketIn:
		v.toA(e.port, e)
	case toSlotLost:
		if a := v.as[e.port]; a == nil || !a.box.send(e) {
			close(e.done)
		}
	case toStats:
		v.stats(e.ask)
	case toDrain:
		v.drain(e)
	case toEndConn:
		for _, a := range v.as {
			a.box.send(e)
		}
	case toEnd:
		v.ending = true
		for _, a := range v.as {
			a.box.send(e)
		}
	case vAssign, vKeys, vTables, vAttachmentStart, vAttachmentEnd, vLanes:
		v.up(e)
	case aAttach:
		v.attach(e)
	case aDetach:
		v.detach(e)
	case aEnded:
		v.connEnded(e)
	case aStatsAnswer:
		v.statsAnswer(e)
	case aStateChanged:
		v.restate(e.port)
	case aRemote:
		v.remote(e)
	}
}

// toA sends a message of the root to the A of port.
func (v *vpcProc) toA(port uint64, m any) {
	if a := v.as[port]; a != nil {
		a.box.send(m)
	}
}

// startConn starts the A of a new main connection.
func (v *vpcProc) startConn(e toConn) {
	if v.ending {
		e.l.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "relay does not serve the VPC")
		e.l.streamEnd()
		e.box.close()
		v.up(vConnEnded{port: e.port})
		return
	}
	ctx, cancel := context.WithCancel(v.ctx)
	a := &aChild{
		port:     e.port,
		tag:      e.tag,
		l:        e.l,
		box:      e.box,
		down:     &valueMap{},
		up:       &valueMap{},
		cancel:   cancel,
		s:        session{agent: agentKey{id: e.l.subject, name: e.hello.GetName(), instance: e.hello.GetInstance()}, meshRoutes: !e.hello.GetLocalRoutesOnly()},
		state:    stateNormal,
		cands:    map[string]*candidate{},
		prefixes: map[string][]netip.Prefix{},
		atts:     map[string]*vAtt{},
	}
	if v.draining {
		a.state = stateDraining
	}
	v.as[a.port] = a
	n := v.net
	store(a.down, keyNetwork, &n)
	store(a.down, keyTrust, v.trust)
	store(a.down, keyRoutes, v.shown)
	if rx := load[*rxValue](v.c.down, rxKey(a.port)); rx != nil {
		store(a.down, keyRx, rx)
	}
	watch(ctx, a.up, func([]string) { v.c.box.send(aStateChanged{port: a.port}) })
	startConn(v.r, v.c.box, e, a.down, a.up, v.draining, v.alts)
}

// changed loads the values of the root that changed.
func (v *vpcProc) changed(keys []string) {
	for _, k := range keys {
		switch {
		case k == keyNetwork:
			if n := load[*Network](v.c.down, keyNetwork); n != nil {
				v.net = *n
				for _, a := range v.as {
					c := *n
					store(a.down, keyNetwork, &c)
				}
			}
		case k == keyTrust:
			if t := load[*trustGen](v.c.down, keyTrust); t != v.trust {
				v.trust = t
				for _, a := range v.as {
					store(a.down, keyTrust, t)
				}
			}
		case strings.HasPrefix(k, keyMember):
			v.memberChanged(k, time.Now())
		case strings.HasPrefix(k, keyRx+"/"):
			port, err := strconv.ParseUint(strings.TrimPrefix(k, keyRx+"/"), 10, 64)
			a := v.as[port]
			if err != nil || a == nil {
				continue
			}
			if rx := load[*rxValue](v.c.down, k); rx != nil {
				store(a.down, keyRx, rx)
			} else {
				a.down.Delete(keyRx)
			}
		}
	}
}

// nextGen returns a generation above each one before: the time in Unix milliseconds, or more.
func (v *vpcProc) nextGen(now time.Time) uint64 {
	v.gen = max(uint64(now.UnixMilli()), v.gen+1)
	return v.gen
}

// attach adds the candidates of an attachment, writes the route entries and answers A. This relay
// gives each address to one attachment.
func (v *vpcProc) attach(e aAttach) {
	a := v.as[e.port]
	if a == nil {
		return
	}
	reply := func(err error) { a.box.send(attached{id: e.att.ID, err: err}) }
	if v.ending {
		v.answer(func() { reply(rpc.Errorf(rpc.Unavailable, "relay does not serve the VPC")) })
		return
	}
	for _, p := range e.att.Addresses {
		if set := v.sets[p.Masked()]; set != nil && slices.ContainsFunc(set.entries, func(o *announcer) bool { return o.own && o.port != e.port }) {
			v.answer(func() {
				reply(rpc.Errorf(rpc.AlreadyExists, "address %s has another attachment on this relay", p.Masked()))
			})
			return
		}
	}
	now := time.Now()
	c := &candidate{agent: a.s.agent, relay: v.r.cfg.Relay.GetId(), attached: v.nextGen(now), rank: e.att.Rank, state: a.state, activeFrom: now.Add(holdTime)}
	t := target{port: e.port, cell: e.cell, origin: e.att.ID, own: true}
	ps := e.att.prefixes()
	var ann *dpv1.Presence
	if v.r.mesh != nil {
		if ann = v.announcement(a, e.att.ID, ps, c, c.attached); !fitsOneMessage(ann) {
			v.answer(func() {
				reply(rpc.Errorf(rpc.InvalidArgument, "announcement of the attachment does not fit in one message to the mesh"))
			})
			return
		}
	}
	for _, p := range ps {
		set := v.sets[p]
		if set == nil {
			set = &routeSet{}
			v.sets[p] = set
		}
		if !slices.ContainsFunc(set.entries, func(o *announcer) bool { return o.port == e.port && o.origin == e.att.ID }) {
			set.entries = append(set.entries, newAnnouncer(t, c, p))
		}
	}
	v.sync(ps, now)
	a.cands[e.att.ID], a.prefixes[e.att.ID] = c, ps
	a.atts[e.att.ID] = &vAtt{cell: e.cell, addrs: slices.Clone(e.att.Addresses), fallback: map[netip.Prefix]*announcer{}}
	if ann != nil {
		v.ann[e.att.ID], v.annDirty = ann, true
	}
	v.w.then(func(err error) {
		if err == nil {
			reply(nil)
			return
		}
		// The route entries did not go in: the attachment goes, and A gets the error after that.
		if v.as[e.port] == a && a.cands[e.att.ID] == c {
			v.drop(a, e.att.ID, time.Now())
		}
		v.answer(func() { reply(rpc.Errorf(rpc.Unavailable, "failed to write route entries: %v", err)) })
	})
}

// announcement returns the announcement of attachment id of a to the members.
func (v *vpcProc) announcement(a *aChild, id string, ps []netip.Prefix, c *candidate, gen uint64) *dpv1.Presence {
	ref := &dpv1.VPCRef{ProjectId: v.c.key.Project, VpcUid: v.c.key.UID, NetworkId: v.net.ID}
	return announcement(ref, id, ps, c, a.tag, gen)
}

// detach removes the candidates of an attachment, writes the route entries and answers A.
func (v *vpcProc) detach(e aDetach) {
	a := v.as[e.port]
	if a == nil {
		return
	}
	v.drop(a, e.id, time.Now())
	v.answer(func() { a.box.send(detached{id: e.id}) })
}

// drop removes the candidates of attachment id of a, and writes the route entries of their
// prefixes.
func (v *vpcProc) drop(a *aChild, id string, now time.Time) {
	ps := a.prefixes[id]
	if at := a.atts[id]; at != nil {
		ps = append(slices.Clone(ps), v.removeFallback(at)...)
		if len(at.report) > 0 {
			v.reports--
		}
		delete(a.atts, id)
	}
	delete(a.cands, id)
	delete(a.prefixes, id)
	if _, ok := v.ann[id]; ok {
		delete(v.ann, id)
		v.annDirty = true
	}
	v.remove(a.port, id, ps)
	v.sync(ps, now)
}

// remove removes the candidates of the attachment id on port for ps, as today's removeAnnouncer.
func (v *vpcProc) remove(port uint64, id string, ps []netip.Prefix) {
	for _, p := range ps {
		if set := v.sets[p]; set != nil {
			set.entries = slices.DeleteFunc(set.entries, func(o *announcer) bool { return o.port == port && o.origin == id })
		}
	}
}

// sync selects again for ps at now. The next tables event has their route entries: both targets of
// each prefix with candidates, and no entry for a prefix with none.
func (v *vpcProc) sync(ps []netip.Prefix, now time.Time) {
	seen := make(map[netip.Prefix]struct{}, len(ps))
	for _, p := range ps {
		if _, done := seen[p]; done {
			continue
		}
		seen[p] = struct{}{}
		if v.reports > 0 {
			if v.touched == nil {
				v.touched = map[netip.Prefix]struct{}{}
			}
			v.touched[p] = struct{}{}
		}
		v.unsynced[p] = struct{}{}
		set := v.sets[p]
		if set == nil || len(set.entries) == 0 {
			delete(v.sets, p)
			delete(v.holds, p)
			continue
		}
		set.selectAgain(now)
		v.holdUntil(p, set.nextHold(now))
	}
	v.dirty = true
}

// flush sends the changes of the route entries up when no event of V is at the root.
func (v *vpcProc) flush() {
	// An event with no updates runs its functions at once, and they can add changes.
	for !v.w.busy && (len(v.unsynced) > 0 || v.dirty || v.annDirty || len(v.w.wait) > 0) {
		v.sendTables()
	}
}

// sendTables sends the changes of the route entries up in one tables event. After a good write,
// V stores the announcement set and the route table of that time, then the answers go.
func (v *vpcProc) sendTables() {
	if v.final {
		// The last event deletes each entry that the writes before it put in.
		for p := range v.entries {
			v.unsynced[p] = struct{}{}
		}
	}
	var b batch
	want := map[netip.Prefix]dp.ForwardAction{}
	var gone []netip.Prefix
	md := "v/" + v.name
	for p := range v.unsynced {
		have, ok := v.entries[p]
		set := v.sets[p]
		if set == nil || len(set.entries) == 0 {
			if ok {
				b.remove(dp.RouteKey{VPC: v.name, Dst: p}.Entry(nil))
				gone = append(gone, p)
			}
			continue
		}
		fa := forwardOf(set)
		switch {
		case !ok:
			b.insert(dp.RouteKey{VPC: v.name, Dst: p}.Entry(fa), md)
		case have != fa:
			b.modify(dp.RouteKey{VPC: v.name, Dst: p}.Entry(fa), md)
		default:
			continue
		}
		want[p] = fa
	}
	clear(v.unsynced)
	var t *routeTable
	if v.dirty {
		v.dirty = false
		t = v.table()
	}
	var set *annSet
	if v.annDirty {
		v.annDirty = false
		set = &annSet{vpc: v.c.key, entries: maps.Clone(v.ann)}
	}
	v.w.send(b, func(err error) {
		if err != nil {
			msg := "Failed to write route entries"
			if v.final {
				msg = "Failed to delete route entries"
			}
			slog.Error(msg, "vpc", v.c.key.UID, "error", err)
			if !v.final {
				// The next event stores the values of the selection after the functions of this
				// event, as after a good write. The answers of this event wait for it.
				v.dirty = v.dirty || t != nil
				v.annDirty = v.annDirty || set != nil
				return
			}
		} else {
			for p, fa := range want {
				v.entries[p] = fa
			}
			for _, p := range gone {
				delete(v.entries, p)
			}
		}
		if set != nil {
			store(v.c.up, keyAnnounce, set)
		}
		if t != nil {
			v.shown = t
			for _, a := range v.as {
				store(a.down, keyRoutes, t)
			}
		}
	}, func(b batch) { v.up(vTables{b: b}) })
}

// forwardOf returns the route action of set: the winner, and the best local candidate.
func forwardOf(set *routeSet) dp.ForwardAction {
	var fa dp.ForwardAction
	w := set.order[0]
	fa.Port, fa.Cell = w.port, w.cell
	if l := set.local; l != nil {
		fa.LocalPort, fa.LocalCell = l.port, l.cell
	}
	return fa
}

// holdUntil keeps the next end of a hold time of p, and sets the timer to the first end.
func (v *vpcProc) holdUntil(p netip.Prefix, at time.Time) {
	if at.IsZero() {
		delete(v.holds, p)
		return
	}
	v.holds[p] = at
	if v.timer == nil || at.Before(v.timerAt) || !v.timerAt.After(time.Now()) {
		v.arm()
	}
}

// arm sets the one timer of V to the first end of a hold time.
func (v *vpcProc) arm() {
	var first time.Time
	for _, at := range v.holds {
		if first.IsZero() || at.Before(first) {
			first = at
		}
	}
	if first.IsZero() {
		return
	}
	v.timerAt = first
	d := time.Until(first)
	if v.timer == nil {
		v.timer = time.AfterFunc(d, func() { v.c.box.send(holdEv{}) })
		return
	}
	v.timer.Reset(d)
}

// holdsEnded selects again for each prefix whose hold time ended.
func (v *vpcProc) holdsEnded(now time.Time) {
	var ps []netip.Prefix
	for p, at := range v.holds {
		if !at.After(now) {
			ps = append(ps, p)
			delete(v.holds, p)
		}
	}
	v.sync(ps, now)
	v.timerAt = time.Time{}
	v.arm()
}

// restate gives the candidates of an A the state that it stored, and selects again. Normal starts
// a new hold time.
func (v *vpcProc) restate(port uint64) {
	a := v.as[port]
	if a == nil {
		return
	}
	sv := load[*stateValue](a.up, keyState)
	if sv == nil {
		return
	}
	v.setState(a, sv.state, sv.reason, time.Now())
}

func (v *vpcProc) setState(a *aChild, state dpv1.AnnouncerState, reason string, now time.Time) {
	if a.state == state {
		return
	}
	a.state = state
	var ps []netip.Prefix
	for id, c := range a.cands {
		c.restate(state, now)
		ps = append(ps, a.prefixes[id]...)
		if at := a.atts[id]; at != nil {
			for p := range at.fallback {
				ps = append(ps, p)
			}
		}
		if v.r.mesh != nil {
			v.ann[id], v.annDirty = v.announcement(a, id, a.prefixes[id], c, v.nextGen(now)), true
		}
	}
	if len(ps) == 0 {
		return
	}
	v.sync(ps, now)
	v.r.stateChanges[state].Add(1)
	slog.Info("Changed the state of an agent connection", "vpc", v.c.key.UID, "agent", a.s.agent.name,
		"relay", v.r.cfg.Relay.GetId(), "state", stateLabel(state), "reason", reason)
}

// drain gives each A the draining state, unless it is suspect, then tells each A to send Drain.
func (v *vpcProc) drain(e toDrain) {
	v.draining, v.alts = true, e.alternates
	now := time.Now()
	for _, a := range v.as {
		if a.state != stateSuspect {
			v.setState(a, stateDraining, "relay drains", now)
		}
		a.box.send(e)
	}
}

// connEnded removes the candidates of an A that ended, and tells the root.
func (v *vpcProc) connEnded(e aEnded) {
	a := v.as[e.port]
	if a == nil {
		return
	}
	now := time.Now()
	for id := range a.prefixes {
		v.drop(a, id, now)
	}
	a.cancel()
	delete(v.as, e.port)
	for ask, wait := range v.asks {
		delete(wait, e.port)
		v.answerAsk(ask)
	}
	// The root takes the tag back after the set with no announcement of A goes to the members.
	v.answer(func() { v.up(vConnEnded{port: e.port, ends: e.ends}) })
}

func (v *vpcProc) stats(ask uint64) {
	wait := map[uint64]struct{}{}
	for port, a := range v.as {
		if a.box.send(toStats{ask: ask}) {
			wait[port] = struct{}{}
		}
	}
	v.asks[ask] = wait
	v.answerAsk(ask)
}

func (v *vpcProc) statsAnswer(e aStatsAnswer) {
	wait := v.asks[e.ask]
	if wait == nil {
		return
	}
	delete(wait, e.port)
	v.out[e.ask] = append(v.out[e.ask], e.stats...)
	v.answerAsk(e.ask)
}

// answerAsk answers an ask when each A answered or ended.
func (v *vpcProc) answerAsk(ask uint64) {
	if wait, ok := v.asks[ask]; !ok || len(wait) > 0 {
		return
	}
	v.up(vStatsAnswer{ask: ask, stats: v.out[ask]})
	delete(v.asks, ask)
	delete(v.out, ask)
}

// answer queues an answer that needs the new values: it goes after the next tables event that
// stores them. After a failed write, it waits for the next event.
func (v *vpcProc) answer(fn func()) {
	v.w.then(func(err error) {
		if err != nil && !v.final {
			v.answer(fn)
			return
		}
		fn()
	})
}

// table returns the route table of the selection now.
func (v *vpcProc) table() *routeTable {
	t := &routeTable{
		vpc:     &dpv1.VPCRef{ProjectId: v.c.key.Project, VpcUid: v.c.key.UID, NetworkId: v.net.ID},
		network: networkOf(v.net.ID),
		self:    v.r.cfg.Relay,
		orders:  make(map[netip.Prefix][]viewEntry, len(v.sets)),
	}
	// A fallback candidate names the relay that the agent reports, with the reference of the
	// member of that ID when there is one.
	var refs map[string]*dpv1.RelayRef
	for p, set := range v.sets {
		order := make([]viewEntry, len(set.order))
		for i, e := range set.order {
			order[i] = viewEntry{agent: e.agent, origin: e.origin, relay: e.relay, own: e.own, ref: e.ref}
			if e.far != "" {
				if refs == nil {
					refs = v.memberRefs()
				}
				order[i].relay, order[i].ref = e.far, refs[e.far]
			}
		}
		t.orders[p] = order
	}
	return t
}

// memberRefs returns the reference of each member with values, by its relay ID.
func (v *vpcProc) memberRefs() map[string]*dpv1.RelayRef {
	refs := make(map[string]*dpv1.RelayRef, len(v.members))
	for _, vm := range v.members {
		if vm.values != nil && vm.values.ref.GetId() != "" {
			refs[vm.values.ref.GetId()] = vm.values.ref
		}
	}
	return refs
}

// end deletes the route entries that are left and stores an empty announcement set. V refuses
// new events from here, and ends after that write.
func (v *vpcProc) end() {
	v.final = true
	clear(v.sets)
	if v.r.mesh != nil {
		clear(v.ann)
		v.annDirty = true
	}
	v.w.then(func(error) { v.over = true })
}

// finish tells the root that V ended.
func (v *vpcProc) finish() {
	if v.timer != nil {
		v.timer.Stop()
	}
	v.cancel()
	for _, e := range v.c.box.close() {
		v.refuse(e)
	}
	v.up(vEnded{})
}

// refuse answers an event that comes after the last A ended.
func (v *vpcProc) refuse(e any) {
	switch e := e.(type) {
	case toConn:
		e.l.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "relay does not serve the VPC")
		e.l.streamEnd()
		e.box.close()
		v.up(vConnEnded{port: e.port})
	case toSlotLost:
		close(e.done)
	case toStats:
		v.up(vStatsAnswer{ask: e.ask})
	case toTablesDone:
		if e.port == 0 {
			v.w.done(e.err)
		}
	}
}

// memberChanged makes the candidates of the member of key k match the records of its part:
// candidates on its trunk port, after its trunk is up. Only a record with the network ID of the
// VPC is a candidate.
func (v *vpcProc) memberChanged(k string, now time.Time) {
	view := load[*memberView](v.c.down, k)
	var vals *memberValues
	var want map[string]*record
	if view != nil && view.values != nil && view.part != nil {
		vals, want = view.values, view.part.recs
	}
	vm := v.members[k]
	if vm == nil {
		if vals == nil {
			return
		}
		vm = &vMember{cands: map[string]*record{}}
		v.members[k] = vm
	}
	// New trunk values change each candidate.
	again := vm.values == nil || vals == nil || vm.values.port != vals.port || vm.values.cell != vals.cell || vm.values.ref != vals.ref
	var ps []netip.Prefix
	for id, rec := range vm.cands {
		if again || want[id] != rec {
			v.remove(vm.values.port, id, rec.prefixes)
			ps = append(ps, rec.prefixes...)
			delete(vm.cands, id)
		}
	}
	vm.values = vals
	for id, rec := range want {
		if vm.cands[id] != nil || rec.networkID != v.net.ID {
			continue
		}
		c := &candidate{
			agent:    agentKey{id: rec.subject, name: rec.agent, instance: rec.instance},
			relay:    vals.ref.GetId(),
			attached: rec.attached, rank: rec.rank, state: rec.state, activeFrom: rec.activeFrom,
		}
		t := target{port: vals.port, cell: vals.cell, origin: id, ref: vals.ref}
		for _, p := range rec.prefixes {
			set := v.sets[p]
			if set == nil {
				set = &routeSet{}
				v.sets[p] = set
			}
			set.entries = append(set.entries, newAnnouncer(t, c, p))
		}
		ps = append(ps, rec.prefixes...)
		vm.cands[id] = rec
	}
	if vals == nil {
		delete(v.members, k)
	}
	v.sync(ps, now)
}
