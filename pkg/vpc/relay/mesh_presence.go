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

// announce gives the new attachment a of s to the mesh. Router.mu must be held.
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
	sess    *MeshSession              // Session of the last Presence call.
	full    bool                      // The full set of sess is complete.
	entries map[string]*presenceEntry // By attachment ID.
}

// presenceEntry is one attachment of a member.
type presenceEntry struct {
	vpc       VPCKey
	networkID uint32
	id        string
	gen       uint64
	subject   string
	agent     string // Agent name from Hello, or empty.
	tag       uint32 // Trunk tag of the session of the agent on the member.
	prefixes  []netip.Prefix
	sess      *MeshSession // Last session that sent the entry.
}

func newPresence(m *Mesh) *presence {
	return &presence{m: m, outs: map[*presenceOut]struct{}{}, in: map[string]*presenceIn{}}
}

// SetRouter makes the mesh send the attachments of r, give r the routes of the
// members, and exchange trunk keys. Call it after r.PacketHandler, before Run.
func (m *Mesh) SetRouter(r *Router) {
	p := m.pres
	p.mu.Lock()
	p.r = r
	p.mu.Unlock()
	r.mu.Lock()
	r.presence = p.changed
	r.mu.Unlock()
	m.setTrunk(r)
}

// router returns the router of SetRouter, or nil.
func (p *presence) router() *Router {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.r
}

// opened starts the Presence call on the new session s. A member from before
// the call gets none, and its session stays.
func (p *presence) opened(s *MeshSession) {
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

// changed gives the entry e of a new or gone attachment to each open call.
// The router calls it with Router.mu held.
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
// member. The entries of the sessions before stay.
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
		in = &presenceIn{entries: map[string]*presenceEntry{}}
		p.in[s.name] = in
	}
	if in.sess == s {
		return rpc.Errorf(rpc.FailedPrecondition, "session already has a Presence call")
	}
	in.sess, in.full = s, false
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

// keep applies the checked changes of the Presence call of s, where the higher
// generation of an attachment wins. refuse gets each entry with no routes.
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
	for _, c := range changes {
		old := in.entries[c.id]
		switch {
		case old != nil && c.gen < old.gen:
			continue
		case old != nil && !c.gone && c.gen == old.gen:
			// The member sent the entry again in the full set of a new session.
			old.sess = s
			continue
		}
		if old != nil {
			delete(in.entries, c.id)
			if r != nil {
				r.unclaim(old)
			}
		}
		if c.gone {
			continue
		}
		in.entries[c.id] = c.presenceEntry
		if r != nil {
			if err := r.claim(c.presenceEntry); err != nil {
				refuse(c.id, err)
			}
		}
	}
	if full {
		in.full = true
	}
	return nil
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
	pe.subject, pe.agent = e.GetSubject(), e.GetAgentName()
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

// down drops the entries and the routes of a member that stopped on purpose
// or left the member set. The entries of the session that it has now stay.
func (p *presence) down(c MeshChange) {
	if c.Down != MeshRestart && c.Down != MeshRemoved {
		return
	}
	r := p.router()
	// Mesh.mu keeps a new session out until the entries are dropped.
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	var cur *MeshSession
	if mem := p.m.members[c.Name]; mem != nil {
		cur = mem.sess
	}
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	in := p.in[c.Name]
	if in == nil {
		return
	}
	all := cur == nil || in.sess != cur
	for id, e := range in.entries {
		if all || e.sess != cur {
			delete(in.entries, id)
			if r != nil {
				r.unclaim(e)
			}
		}
	}
	if all {
		delete(p.in, c.Name)
	}
}
