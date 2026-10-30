// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	stateNormal   = dpv1.AnnouncerState_ANNOUNCER_STATE_NORMAL
	stateDraining = dpv1.AnnouncerState_ANNOUNCER_STATE_DRAINING
	stateSuspect  = dpv1.AnnouncerState_ANNOUNCER_STATE_SUSPECT
	// numAnnouncerStates is the number of states that this build sets.
	numAnnouncerStates = 3
	// holdTime is the time after an attach, or after a return to the normal state, in which an
	// entry does not replace a live active announcer.
	holdTime = 30 * time.Second
)

// agentKey names one agent process: the SPIFFE ID, the name from Hello, and the instance from
// Hello. One agent process can have attachments on more than one relay.
type agentKey struct {
	id, name string
	instance uint64
}

// target is where the packets for a prefix go: the port of an attachment and its transmit cell.
type target struct {
	port uint64
	cell uint32
	// origin is the ID of the attachment.
	origin string
	// own is true for an attachment of this relay.
	own bool
	// ref is the relay of an attachment of a member, from its Open.
	ref *dpv1.RelayRef
}

// candidate is what the selection reads of one attachment.
type candidate struct {
	agent agentKey
	// relay is the ID of the relay with the attachment.
	relay string
	// attached is the generation at the attach. A later state does not change it, so it tells
	// which attachment of a connection is newer.
	attached uint64
	// rank is the order that the agent gives to its own connections. The lower one is first.
	rank  uint32
	state dpv1.AnnouncerState // The lower state is selected first.
	// activeFrom is the end of the hold time. The zero time is no hold time.
	activeFrom time.Time
}

// restate gives c the state. A return to the normal state starts a new hold time at now.
func (c *candidate) restate(state dpv1.AnnouncerState, now time.Time) {
	c.state = state
	if state == stateNormal {
		c.activeFrom = now.Add(holdTime)
	}
}

// announcer is one candidate of a prefix. Each connection of an agent to a relay is its own
// announcer.
type announcer struct {
	target
	*candidate
	// hash is a hash of the agent and the prefix. The lower one is selected first, so each prefix
	// has its own order of the agents.
	hash [sha256.Size]byte
}

// newAnnouncer returns the announcer of the attachment of t for p, with the record c.
func newAnnouncer(t target, c *candidate, p netip.Prefix) *announcer {
	// A SPIFFE ID and an agent name have no zero byte, so the parts stay apart.
	var buf [256]byte
	b := append(buf[:0], c.agent.id...)
	b = append(b, 0)
	b = append(b, c.agent.name...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, c.agent.instance)
	return &announcer{target: t, candidate: c, hash: sha256.Sum256(p.AppendTo(b))}
}

// sameConn reports whether e and o are entries of one agent process on one relay: a reconnect to
// that relay, or two attachments of one connection.
func (e *announcer) sameConn(o *announcer) bool {
	return e.agent == o.agent && e.relay == o.relay
}

// newer reports whether e comes in the place of o in the selection, when sameConn is true: the
// later attach, then the lower attachment ID.
func (e *announcer) newer(o *announcer) bool {
	return cmp.Or(cmp.Compare(o.attached, e.attached), cmp.Compare(e.origin, o.origin)) < 0
}

// held returns 1 if e is in its hold time at now, and 0 if not. Only a normal entry has a hold
// time.
func (e *announcer) held(now time.Time) int {
	if e.state == stateNormal && now.Before(e.activeFrom) {
		return 1
	}
	return 0
}

// selectOrder returns the active announcer, then the standby ones: by state, hold time and agent
// hash, then rank. Only the set and now decide.
func selectOrder(entries []*announcer, now time.Time) []*announcer {
	order := make([]*announcer, 0, len(entries))
	for _, e := range entries {
		i := slices.IndexFunc(order, e.sameConn)
		switch {
		case i < 0:
			order = append(order, e)
		case e.newer(order[i]):
			order[i] = e
		}
	}
	// When each normal entry is in its hold time, the one whose hold time ends first is active,
	// and it stays active at that end.
	allHeld := !slices.ContainsFunc(order, func(e *announcer) bool {
		return e.state == stateNormal && e.held(now) == 0
	})
	slices.SortFunc(order, func(a, b *announcer) int {
		byEnd := 0
		if allHeld && a.held(now)+b.held(now) == 2 {
			byEnd = a.activeFrom.Compare(b.activeFrom)
		}
		return cmp.Or(
			cmp.Compare(a.state, b.state),
			cmp.Compare(a.held(now), b.held(now)),
			byEnd,
			bytes.Compare(a.hash[:], b.hash[:]),
			cmp.Compare(a.rank, b.rank),
			cmp.Compare(a.relay, b.relay),
			cmp.Compare(a.origin, b.origin),
		)
	})
	return order
}

// routeSet has the candidates of one prefix and the result of the selection.
type routeSet struct {
	entries []*announcer // Each candidate of the prefix, in no order.
	order   []*announcer // Result of selectOrder for entries.
	// local is the first entry of order on a port of this relay, or nil.
	local *announcer
}

// selectAgain runs the selection at now, after a change of entries or at the end of a hold time.
func (set *routeSet) selectAgain(now time.Time) {
	set.order = selectOrder(set.entries, now)
	set.local = nil
	if i := slices.IndexFunc(set.order, func(e *announcer) bool { return e.own }); i >= 0 {
		set.local = set.order[i]
	}
}

// nextHold returns the first end of a hold time in set after now, or the zero time, also for a
// set with one candidate.
func (set *routeSet) nextHold(now time.Time) time.Time {
	var next time.Time
	if len(set.order) < 2 {
		return next
	}
	for _, e := range set.entries {
		if e.held(now) == 1 && (next.IsZero() || e.activeFrom.Before(next)) {
			next = e.activeFrom
		}
	}
	return next
}

// viewEntry is what an agent can learn of one candidate.
type viewEntry struct {
	agent  agentKey
	origin string
	relay  string
	own    bool
	ref    *dpv1.RelayRef // The relay of a candidate of a member.
}

// routeTable is the route table of a VPC that V gives to its A: the selection of each prefix. It
// is immutable.
type routeTable struct {
	vpc *dpv1.VPCRef
	// network is the /72 of the VPC. A /96 in it is an address of a slot.
	network netip.Prefix
	self    *dpv1.RelayRef
	orders  map[netip.Prefix][]viewEntry
}

// session is what the routes of one agent connection depend on.
type session struct {
	agent agentKey
	// meshRoutes is true when the agent takes the routes of the attachments of other relays.
	meshRoutes bool
}

// sees returns the candidate of order that s gets, or nil: never its own agent, another relay
// only with meshRoutes.
func (s session) sees(order []viewEntry) *viewEntry {
	if len(order) == 0 || slices.ContainsFunc(order, func(e viewEntry) bool { return e.agent == s.agent }) {
		return nil
	}
	if active := &order[0]; active.own || s.meshRoutes {
		return active
	}
	return nil
}

// standby returns the IDs of the standby candidates of order that s can reach, in the order of
// selection.
func (s session) standby(order []viewEntry) []string {
	var ids []string
	for i, e := range order {
		if i > 0 && (e.own || s.meshRoutes) {
			ids = append(ids, e.origin)
		}
	}
	return ids
}

// gets reports whether s gets the slot Route that e names: an own candidate gives the slot to
// each session, another one only to a session with meshRoutes.
func (s session) gets(e *viewEntry) bool { return e != nil && (e.own || s.meshRoutes) }

// ref returns the relay of e: this relay, or the member of the candidate.
func (t *routeTable) ref(e *viewEntry) *dpv1.RelayRef {
	if e.own {
		return t.self
	}
	if e.ref != nil {
		return e.ref
	}
	return &dpv1.RelayRef{Id: e.relay}
}

// slotOf returns the slot of p: the /88 of a /96 in the network of the VPC.
func (t *routeTable) slotOf(p netip.Prefix) (netip.Prefix, bool) {
	if !t.network.IsValid() || p.Bits() != 96 || !t.network.Contains(p.Addr()) {
		return netip.Prefix{}, false
	}
	return ipalloc.SlotPrefixOf(p.Addr()), true
}

// holderFirst orders the candidates that can name a slot: an own one first, then the lower relay
// ID, then the lower origin.
func holderFirst(a, b *viewEntry) bool {
	if a.own != b.own {
		return a.own
	}
	return cmp.Or(cmp.Compare(a.relay, b.relay), cmp.Compare(a.origin, b.origin)) < 0
}

// view returns the routes that s gets, by prefix: one Route for each prefix that it sees, and
// one Route for each slot, in place of the /96s of the slot.
func (t *routeTable) view(s session) map[netip.Prefix]*dpv1.Route {
	out := map[netip.Prefix]*dpv1.Route{}
	if t == nil {
		return out
	}
	holders := map[netip.Prefix]*viewEntry{}
	for p, order := range t.orders {
		if slot, ok := t.slotOf(p); ok {
			for i := range order {
				if h := holders[slot]; h == nil || holderFirst(&order[i], h) {
					holders[slot] = &order[i]
				}
			}
			continue
		}
		if e := s.sees(order); e != nil {
			out[p] = &dpv1.Route{Vpc: t.vpc, Prefix: p.String(), Origin: e.origin, Standby: s.standby(order), Relay: t.ref(e)}
		}
	}
	for slot, h := range holders {
		if s.gets(h) {
			out[slot] = &dpv1.Route{Vpc: t.vpc, Prefix: slot.String(), Origin: h.relay, Relay: t.ref(h)}
		}
	}
	return out
}

// networkOf returns the /72 of a network ID.
func networkOf(id uint32) netip.Prefix {
	return tunnet.NetworkPrefix(tunnet.NetworkID{byte(id >> 16), byte(id >> 8), byte(id)})
}
