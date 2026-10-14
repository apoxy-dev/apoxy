// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// presenceRevision is the first revision with the Presence call of the mesh.
	presenceRevision = 4
	// maxPresenceEntries is the most entries of one PresenceUpdate.
	maxPresenceEntries = 256
	// maxAttachmentID is the most bytes of an attachment ID from a member.
	maxAttachmentID = 128
	// maxMemberEntries is the most entries that the relay keeps of one member.
	maxMemberEntries = 1 << 16
	// maxEntryPrefixes is the most prefixes of one entry of a member.
	maxEntryPrefixes = 64
	// presenceFullSetTime is the time that a new session of a member has for its
	// full set. Then the entries that it did not send again go.
	presenceFullSetTime = 10 * time.Second
)

// newTag returns a trunk tag that no session has, or 0 if none is free. A tag
// comes again only after all the others. Router.mu must be held.
func (r *Router) newTag() uint32 {
	// A tag goes in the VNI field of a trunk packet, and 0 there is no tag.
	if len(r.tags) >= pspwire.MaxVNI {
		return 0
	}
	for {
		r.tag = r.tag%pspwire.MaxVNI + 1
		if _, used := r.tags[r.tag]; !used {
			r.tags[r.tag] = struct{}{}
			return r.tag
		}
	}
}

// nextGen returns the generation of a change at now: the Unix time in ms, or
// the last generation plus 1 if the time is not above it. Router.mu must be held.
func (r *Router) nextGen(now time.Time) uint64 {
	r.gen = max(uint64(now.UnixMilli()), r.gen+1)
	return r.gen
}

// announce gives the entry of the attachment a of s to the mesh: after the
// attach, and after each state change. Router.mu must be held.
func (r *Router) announce(s *Session, a *Attachment) {
	if r.presence != nil {
		r.presence(presenceOf(s, a))
	}
}

// withdraw gives a gone entry for a, which ends, to the mesh. A second call
// for a does nothing. Router.mu must be held.
func (r *Router) withdraw(a *Attachment) {
	if a.gen == 0 {
		return
	}
	a.gen = 0
	gen := r.nextGen(time.Now())
	if r.presence != nil {
		r.presence(&dp.Presence{Vpc: vpcRef(a), AttachmentId: a.ID, Generation: gen, Gone: true})
	}
}

func vpcRef(a *Attachment) *dp.VPCRef {
	return &dp.VPCRef{ProjectId: a.VPC.Project, VpcUid: a.VPC.UID, NetworkId: a.NetworkID}
}

// presenceOf returns the entry of the live attachment a of s. Router.mu must
// be held.
func presenceOf(s *Session, a *Attachment) *dp.Presence {
	e := &dp.Presence{
		Vpc:          vpcRef(a),
		AttachmentId: a.ID,
		Generation:   a.gen,
		Subject:      s.id.ID,
		AgentName:    s.name,
		SenderTag:    s.tag,
		Instance:     s.instance,
		State:        s.state,
		Rank:         a.Rank,
		Attached:     a.cand.attached,
		ActiveFrom:   timestamppb.New(a.cand.activeFrom),
	}
	for _, p := range slices.Concat(a.Addresses, a.Routes) {
		e.Prefixes = append(e.Prefixes, p.Masked().String())
	}
	return e
}

// presence sends the attachments of a router to the members of a mesh, and
// gives the router the attachments that the members send.
type presence struct {
	m *Mesh

	// mu guards the fields below. Take it after Router.mu and after Mesh.mu.
	// A path that needs Mesh.mu and Router.mu takes Mesh.mu first.
	mu   sync.Mutex
	r    *Router // Router of SetRouter. Nil sends nothing and makes no routes.
	outs map[*presenceOut]struct{}
	in   map[string]*presenceIn // By relay name of the member.
}

// presenceOut is the Presence call to one member. presence.mu guards it.
type presenceOut struct {
	sess    *MeshSession
	wake    chan struct{}           // Has room for 1: waiting or full changed.
	waiting map[string]*dp.Presence // Last entry of each attachment to send.
	full    bool                    // The end of the full set is not sent.
}

// presenceIn has the attachments that one member sent.
type presenceIn struct {
	sess    *MeshSession                // Session of the last Presence call.
	full    bool                        // The full set of sess is complete.
	entries map[string]*presenceEntry   // By attachment ID.
	tags    map[uint32][]*presenceEntry // The same entries, by sender tag.
	stale   int                         // Entries that sess did not send.
	// lostTimer drops the entries when the member is still down memberLostTime
	// after its last loss. It is nil when the member has a session again.
	lostTimer *time.Timer
}

// stopLost stops the timer of the last loss of the member. presence.mu must
// be held.
func (in *presenceIn) stopLost() {
	if in.lostTimer != nil {
		in.lostTimer.Stop()
		in.lostTimer = nil
	}
}

// add keeps the entry e, which sess sent. presence.mu must be held.
func (in *presenceIn) add(e *presenceEntry) {
	in.entries[e.id] = e
	in.tags[e.tag] = append(in.tags[e.tag], e)
}

// confirm tells that the session s of the last call sent the entry e, which in
// has. presence.mu must be held.
func (in *presenceIn) confirm(e *presenceEntry, s *MeshSession) {
	if e.sess != s {
		e.sess = s
		in.stale--
	}
}

// remove forgets the entry e. presence.mu must be held.
func (in *presenceIn) remove(e *presenceEntry) {
	if e.sess != in.sess {
		in.stale--
	}
	delete(in.entries, e.id)
	left := slices.DeleteFunc(in.tags[e.tag], func(o *presenceEntry) bool { return o == e })
	if len(left) == 0 {
		delete(in.tags, e.tag)
	} else {
		in.tags[e.tag] = left
	}
}

// drop forgets each entry that the session s did not send, and returns them.
// With no s it forgets all the entries. presence.mu must be held.
func (in *presenceIn) drop(s *MeshSession) []*presenceEntry {
	if in.sess == s && in.stale == 0 {
		return nil
	}
	var gone []*presenceEntry
	for id, e := range in.entries {
		if e.sess != s {
			delete(in.entries, id)
			gone = append(gone, e)
		}
	}
	// One pass makes the entries by tag again: a tag can have many entries.
	clear(in.tags)
	for _, e := range in.entries {
		in.tags[e.tag] = append(in.tags[e.tag], e)
	}
	// Only the session of the last call has entries that stay.
	in.stale = 0
	return gone
}

// presenceEntry is one attachment of a member.
type presenceEntry struct {
	vpc       VPCKey
	networkID uint32
	id        string
	gen       uint64
	attached  uint64 // Generation at the attach, or 0 from a member before the field.
	subject   string
	agent     string // Agent name from Hello, or empty.
	instance  uint64 // Agent instance from Hello. Zero from a member before revision 16.
	rank      uint32 // Order of the connection among those of its agent.
	state     dp.AnnouncerState
	// activeFrom is the end of the hold time, or the zero time from a member
	// that sends none.
	activeFrom time.Time
	tag        uint32 // Trunk tag of the session of the agent on the member.
	prefixes   []netip.Prefix
	sess       *MeshSession // Last session that sent the entry.
	// lost is true from the loss of the member until a session of the member
	// sends the entry again. The entry is then suspect on this relay only.
	lost bool
	// cand is the record that the route entries of the attachment read. Only
	// claim and restateClaim write it, from the fields above.
	cand candidate
}

func newPresence(m *Mesh) *presence {
	return &presence{m: m, outs: map[*presenceOut]struct{}{}, in: map[string]*presenceIn{}}
}

// SetRouter makes the mesh send the attachments and the peer frames of r, give r
// routes, and exchange trunk keys. Call it after r.PacketHandler, before Run.
func (m *Mesh) SetRouter(r *Router) {
	p := m.pres
	p.mu.Lock()
	p.r = r
	p.mu.Unlock()
	r.mu.Lock()
	r.presence = p.changed
	r.name = m.name
	r.mu.Unlock()
	m.OnDatagram(func(s *MeshSession, b []byte) { p.datagram(r, s, b) })
	m.setTrunk(r)
}

// router returns the router of SetRouter, or nil.
func (p *presence) router() *Router {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.r
}

// attachments returns the IDs of the attachments of the session k of a member,
// in the order of their attach.
func (p *presence) attachments(k remoteKey) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[k.home]
	if in == nil {
		return nil
	}
	var es []*presenceEntry
	for _, e := range in.tags[k.tag] {
		// A tag names one session, but an entry of an older session can have it.
		if e.session() == k {
			es = append(es, e)
		}
	}
	slices.SortFunc(es, func(a, b *presenceEntry) int {
		return cmp.Or(cmp.Compare(a.attachedAt(), b.attachedAt()), cmp.Compare(a.id, b.id))
	})
	ids := make([]string, len(es))
	for i, e := range es {
		ids[i] = e.id
	}
	return ids
}

// opened starts the Presence call on the new session s, and the time limit of
// the full set of its member. A member from before the call gets no call.
func (p *presence) opened(s *MeshSession) {
	time.AfterFunc(presenceFullSetTime, func() { p.expire(s) })
	p.mu.Lock()
	// The member is back, so the time of its last loss ends nothing.
	if in := p.in[s.name]; in != nil {
		in.stopLost()
	}
	p.mu.Unlock()
	r := p.router()
	if r == nil || s.Version().GetRevision() < presenceRevision {
		return
	}
	o := &presenceOut{sess: s, wake: make(chan struct{}, 1), waiting: map[string]*dp.Presence{}, full: true}
	// The first message goes also when the relay has no attachment.
	o.wake <- struct{}{}
	// The read lock keeps each change out until o has the full set and gets
	// the changes.
	r.mu.RLock()
	p.mu.Lock()
	for rs := range r.sessions {
		for _, a := range rs.attachments {
			o.waiting[a.ID] = presenceOf(rs, a)
		}
	}
	p.outs[o] = struct{}{}
	p.mu.Unlock()
	r.mu.RUnlock()
	p.m.wg.Go(func() { p.send(o) })
}

// changed gives the entry e of a new or gone attachment, or of an attachment
// with a new state, to each open call. The router calls it with Router.mu held.
func (p *presence) changed(e *dp.Presence) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for o := range p.outs {
		// A later entry of an attachment replaces the entry that waits.
		o.waiting[e.GetAttachmentId()] = e
		select {
		case o.wake <- struct{}{}:
		default:
		}
	}
}

// take returns the messages for the entries that wait, lowest generation
// first. The last message of the first call ends the full set.
func (p *presence) take(o *presenceOut) []*dp.PresenceUpdate {
	p.mu.Lock()
	entries := slices.Collect(maps.Values(o.waiting))
	o.waiting = map[string]*dp.Presence{}
	full := o.full
	o.full = false
	p.mu.Unlock()
	slices.SortFunc(entries, func(a, b *dp.Presence) int {
		return cmp.Or(cmp.Compare(a.GetGeneration(), b.GetGeneration()), cmp.Compare(a.GetAttachmentId(), b.GetAttachmentId()))
	})
	var msgs []*dp.PresenceUpdate
	for part := range slices.Chunk(entries, maxPresenceEntries) {
		msgs = append(msgs, &dp.PresenceUpdate{Entries: part})
	}
	if full {
		if len(msgs) == 0 {
			msgs = append(msgs, &dp.PresenceUpdate{})
		}
		msgs[len(msgs)-1].EndOfFullSet = true
	}
	return msgs
}

// send runs the Presence call of o until its session ends. If the call fails
// first, the member gets no more entries on this session.
func (p *presence) send(o *presenceOut) {
	defer func() {
		p.mu.Lock()
		delete(p.outs, o)
		p.mu.Unlock()
	}()
	ctx := o.sess.Context()
	st, err := o.sess.Client().Presence(ctx)
	for err == nil {
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		}
		for _, u := range p.take(o) {
			if err = st.Send(u); err != nil {
				// The answer of the member has the cause.
				if _, cerr := st.CloseAndRecv(); cerr != nil {
					err = cerr
				}
				break
			}
		}
	}
	if ctx.Err() == nil {
		slog.Warn("Failed to send attachments to a mesh member", "relay", o.sess.Name(), "error", err)
	}
}

// Presence keeps the attachments that the calling relay sends. A session has
// one Presence call, and an entry that fails a check does not end it.
func (m *Mesh) Presence(ctx context.Context, st rpc.ClientStreamServer[dp.PresenceUpdate]) (*emptypb.Empty, error) {
	s, err := m.SessionOf(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.pres.accept(s); err != nil {
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
		if err := m.pres.apply(s, u); err != nil {
			return nil, err
		}
	}
}

// accept makes s the session whose Presence call changes the entries of its
// member. The entries of the sessions before stay until its full set ends.
func (p *presence) accept(s *MeshSession) error {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	if mem := p.m.members[s.name]; mem == nil || mem.sess != s {
		return rpc.Errorf(rpc.FailedPrecondition, "mesh session ended")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[s.name]
	if in == nil {
		in = &presenceIn{entries: map[string]*presenceEntry{}, tags: map[uint32][]*presenceEntry{}}
		p.in[s.name] = in
	}
	if in.sess == s {
		return rpc.Errorf(rpc.FailedPrecondition, "session already has a Presence call")
	}
	in.sess, in.full, in.stale = s, false, len(in.entries)
	if p.r != nil {
		// The entries of the sessions before name no sender from now.
		p.r.newEpoch()
	}
	return nil
}

// presenceChange is one checked entry of a member.
type presenceChange struct {
	*presenceEntry
	gone bool
}

// apply checks the entries of u, from the Presence call of s, and keeps them.
// The refused entries of u get one warning.
func (p *presence) apply(s *MeshSession, u *dp.PresenceUpdate) error {
	changes := make([]presenceChange, 0, len(u.GetEntries()))
	var refused int
	var reason error
	refuse := func(id string, err error) {
		if refused++; reason == nil {
			reason = fmt.Errorf("attachment %.64q: %w", id, err)
		}
	}
	for _, e := range u.GetEntries() {
		pe, err := checkPresence(e)
		if err != nil {
			refuse(e.GetAttachmentId(), err)
			continue
		}
		pe.sess = s
		changes = append(changes, presenceChange{pe, e.GetGone()})
	}
	err := p.keep(s, changes, u.GetEndOfFullSet(), refuse)
	if refused > 0 {
		slog.Warn("Refused attachments of a mesh member", "relay", s.Name(), "count", refused, "reason", reason)
	}
	return err
}

// keep applies the checked changes of the Presence call of s; the higher
// generation wins. An entry with only a new state changes in place.
func (p *presence) keep(s *MeshSession, changes []presenceChange, full bool, refuse func(id string, err error)) error {
	// The router lock keeps the routes in the order of the entries.
	r := p.router()
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[s.name]
	if in == nil || in.sess != s {
		return rpc.Errorf(rpc.FailedPrecondition, "mesh session ended")
	}
	restated := map[remoteKey]dp.AnnouncerState{}
	for _, c := range changes {
		old := in.entries[c.id]
		switch {
		case old != nil && c.gen < old.gen:
			continue
		case old != nil && !c.gone && (c.gen == old.gen || old.sameRoutes(c.presenceEntry)):
			// The member sent the entry again in the full set of a new session,
			// or sent it with a new state.
			in.confirm(old, s)
			if old.take(c.presenceEntry) && r != nil {
				r.restateClaim(old)
				restated[old.session()] = old.routeState()
			}
			continue
		}
		if old != nil {
			in.remove(old)
			if r != nil {
				r.unclaim(old)
			}
		}
		if c.gone {
			continue
		}
		// At the limit, the entries of older sessions make room for those of s.
		if len(in.entries) >= maxMemberEntries && p.sweep(r, in, s, "limit of attachments") == 0 {
			refuse(c.id, fmt.Errorf("the member has %d attachments, which is the limit", maxMemberEntries))
			continue
		}
		in.add(c.presenceEntry)
		if r != nil {
			if err := r.claim(c.presenceEntry); err != nil {
				refuse(c.id, err)
			}
		}
	}
	if full {
		in.full = true
		p.sweep(r, in, s, "end of the full set")
	}
	if r != nil {
		r.newEpoch()
	}
	for k, state := range restated {
		slog.Info("Changed the state of an agent session", "vpc", k.id.VPC.UID, "agent", k.agent,
			"relay", k.home, "state", stateLabel(state), "reason", "state from its relay")
	}
	return nil
}

// sameRoutes reports whether c is the attachment e with the same session and
// the same prefixes, so that c can differ from e only in its state.
func (e *presenceEntry) sameRoutes(c *presenceEntry) bool {
	return e.vpc == c.vpc && e.networkID == c.networkID && e.subject == c.subject && e.agent == c.agent &&
		e.instance == c.instance && e.tag == c.tag && e.rank == c.rank && e.attachedAt() == c.attachedAt() &&
		slices.Equal(e.prefixes, c.prefixes)
}

// take gives e the generation, the state and the hold time of c. It reports
// whether the route entries of e must change. presence.mu must be held.
func (e *presenceEntry) take(c *presenceEntry) bool {
	state, from := e.routeState(), e.activeFrom
	e.lost = false
	if c.gen > e.gen {
		// The generation of the attach stays when the first entry did not have it.
		e.attached = e.attachedAt()
		e.gen, e.state, e.activeFrom = c.gen, c.state, c.activeFrom
	}
	return e.routeState() != state || !e.activeFrom.Equal(from)
}

// sweep removes the entries of in, and their routes, that the session s of the
// member did not send. Router.mu, if r is not nil, and presence.mu must be held.
func (p *presence) sweep(r *Router, in *presenceIn, s *MeshSession, reason string) int {
	gone := in.drop(s)
	for _, e := range gone {
		if r != nil {
			r.unclaim(e)
		}
	}
	if len(gone) > 0 {
		slog.Info("Removed attachments of a mesh member", "relay", gone[0].sess.Name(), "count", len(gone), "reason", reason)
	}
	return len(gone)
}

// expire removes the entries that s did not send, if s is still the session of
// its member. It runs when the time for the full set of s ends.
func (p *presence) expire(s *MeshSession) {
	r := p.router()
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	if mem := p.m.members[s.name]; mem == nil || mem.sess != s {
		return
	}
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[s.name]
	if in == nil {
		return
	}
	p.sweep(r, in, s, "no full set in time")
	// With no Presence call on s, nothing of the call before is left.
	if in.sess != s {
		delete(p.in, s.name)
	}
	if r != nil {
		r.newEpoch()
	}
}

// checkPresence checks the form of one entry of a member and returns its
// data. A gone entry has only the attachment ID and the generation.
func checkPresence(e *dp.Presence) (*presenceEntry, error) {
	pe := &presenceEntry{id: e.GetAttachmentId(), gen: e.GetGeneration()}
	switch {
	case pe.id == "" || len(pe.id) > maxAttachmentID:
		return nil, fmt.Errorf("attachment ID has %d bytes", len(pe.id))
	case pe.gen == 0:
		return nil, errors.New("no generation")
	case e.GetGone():
		return pe, nil
	case len(e.GetPrefixes()) > maxEntryPrefixes:
		return nil, fmt.Errorf("%d prefixes, which is more than the limit %d", len(e.GetPrefixes()), maxEntryPrefixes)
	}
	var err error
	if pe.vpc, err = KeyOf(e.GetVpc()); err != nil {
		return nil, err
	}
	if pe.networkID = e.GetVpc().GetNetworkId(); pe.networkID > pspwire.MaxVNI {
		return nil, fmt.Errorf("network ID %d is above %d", pe.networkID, pspwire.MaxVNI)
	}
	// The subject names its VPC, so an entry cannot put an agent in another VPC.
	id, err := identity.ParseID(e.GetSubject())
	if err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	if id.Project != pe.vpc.Project || id.VPC != pe.vpc.UID {
		return nil, fmt.Errorf("subject %q is not in VPC %s/%s", e.GetSubject(), pe.vpc.Project, pe.vpc.UID)
	}
	pe.subject, pe.agent, pe.instance, pe.rank = e.GetSubject(), e.GetAgentName(), e.GetInstance(), e.GetRank()
	// A state that this build does not know stays: it ranks after the known ones.
	pe.state = e.GetState()
	if pe.attached = e.GetAttached(); pe.attached > pe.gen {
		return nil, fmt.Errorf("attach generation %d is above the generation %d", pe.attached, pe.gen)
	}
	if t := e.GetActiveFrom(); t != nil {
		if err := t.CheckValid(); err != nil {
			return nil, fmt.Errorf("active_from: %w", err)
		}
		pe.activeFrom = t.AsTime()
	}
	if pe.tag = e.GetSenderTag(); pe.tag == 0 || pe.tag > pspwire.MaxVNI {
		return nil, fmt.Errorf("sender tag %d is not from 1 to %d", pe.tag, pspwire.MaxVNI)
	}
	for _, t := range e.GetPrefixes() {
		px, err := netip.ParsePrefix(t)
		if err != nil {
			return nil, fmt.Errorf("prefix: %w", err)
		}
		pe.prefixes = append(pe.prefixes, px.Masked())
	}
	return pe, nil
}

// down makes the entries of a lost member suspect on this relay, and drops the
// entries and the routes of a member that stopped on purpose or left the set.
func (p *presence) down(c MeshChange) {
	switch c.Down {
	case MeshLost:
		p.lost(c.Name)
	case MeshRestart, MeshRemoved:
		p.forget(c.Name, c.Down.String(), nil)
	}
}

// lost makes each entry of the lost member name suspect on this relay only, and
// starts memberLostTime. An entry of the session that the member has now stays.
func (p *presence) lost(name string) {
	r := p.router()
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	mem := p.m.members[name]
	if mem == nil {
		return
	}
	ends := mem.ends
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[name]
	if in == nil {
		return
	}
	// The member has one timer: that of its last loss.
	in.stopLost()
	in.lostTimer = time.AfterFunc(memberLostTime, func() {
		p.forget(name, "lost for "+memberLostTime.String(), func(cur *meshMember) bool {
			return cur == mem && mem.sess == nil && mem.ends == ends
		})
	})
	sessions := map[remoteKey]struct{}{}
	for _, e := range in.entries {
		if e.lost || e.sess == mem.sess {
			continue
		}
		e.lost = true
		sessions[e.session()] = struct{}{}
		if r != nil {
			r.restateClaim(e)
		}
	}
	if len(sessions) > 0 {
		slog.Info("Changed the state of the agent sessions of a mesh member", "relay", name, "count", len(sessions),
			"state", stateLabel(stateSuspect), "reason", "mesh member lost")
	}
}

// forget drops the entries and the routes of the member name. With when, it
// does so only if when is true for the member of that name now, which can be nil.
func (p *presence) forget(name, reason string, when func(mem *meshMember) bool) {
	r := p.router()
	// Mesh.mu keeps a new session out until the entries are dropped.
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	mem := p.m.members[name]
	if when != nil && !when(mem) {
		return
	}
	var cur *MeshSession
	if mem != nil {
		cur = mem.sess
	}
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[name]
	if in == nil {
		return
	}
	// A session with no Presence call has no entries, so all of them go.
	if cur == nil || in.sess != cur {
		cur = nil
		in.stopLost()
		delete(p.in, name)
	}
	p.sweep(r, in, cur, reason)
	if r != nil {
		r.newEpoch()
	}
}
