// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"
)

// A fallback candidate is an address that another relay gave to the agent, on the connection of
// the agent to this relay. It has the candidate of the attachment whose report has the address.

// remote keeps the report of remote addresses of an attachment of A, and makes its fallback
// candidates again. A report replaces the last one of the attachment.
func (v *vpcProc) remote(e aRemote) {
	a := v.as[e.port]
	if a == nil {
		return
	}
	at := a.atts[e.att]
	if at == nil {
		return
	}
	if len(at.report) > 0 {
		v.reports--
	}
	at.report, at.failed = e.addrs, false
	if len(at.report) > 0 {
		v.reports++
	}
	v.reconcile(a, e.att, true, time.Now())
}

// reconcile makes the fallback candidates of attachment id of a match the addresses of its report
// that pass the checks now, and tells A the new accepted set. fresh is true for a new report.
func (v *vpcProc) reconcile(a *aChild, id string, fresh bool, now time.Time) {
	at, c := a.atts[id], a.cands[id]
	if at == nil || c == nil || at.failed {
		return
	}
	want := map[netip.Prefix]remoteAddr{}
	for _, ra := range at.report {
		if _, ok := want[ra.prefix]; ok {
			continue
		}
		if err := v.checkRemote(a, at, ra); err != nil {
			if fresh || at.fallback[ra.prefix] != nil {
				slog.Info("Refused a remote address of an agent", "vpc", v.c.key.UID, "agent", a.s.agent.name,
					"attachment", id, "address", ra.prefix, "relay", ra.relay, "reason", err.Error())
			}
			continue
		}
		want[ra.prefix] = ra
	}
	var ps []netip.Prefix
	for p, e := range at.fallback {
		if ra, ok := want[p]; ok && ra.relay == e.far && ra.origin == e.origin {
			continue
		}
		v.removeOne(p, e)
		delete(at.fallback, p)
		ps = append(ps, p)
	}
	for p, ra := range want {
		if at.fallback[p] != nil {
			continue
		}
		e := newAnnouncer(target{port: a.port, cell: at.cell, origin: ra.origin, far: ra.relay}, c, p)
		set, _ := v.sets.Get(p)
		if set == nil {
			set = &routeSet{}
			v.sets.Insert(p, set)
		}
		set.entries = append(set.entries, e)
		at.fallback[p] = e
		ps = append(ps, p)
	}
	if len(ps) == 0 {
		return
	}
	v.sync(ps, now)
	at.gen++
	gen := at.gen
	accepted := slices.SortedFunc(maps.Keys(at.fallback), netip.Prefix.Compare)
	v.w.then(func(err error) {
		if err == nil {
			a.box.send(remoteAccepted{att: id, addrs: accepted})
			return
		}
		if v.as[a.port] == a && a.atts[id] == at {
			if at.gen != gen {
				// The candidates of a later change go in the next event, and its function answers A.
				v.sync(slices.Collect(maps.Keys(at.fallback)), time.Now())
				return
			}
			// The route entries did not go in: the fallback candidates go, and A gets the set after that.
			at.failed = true
			v.sync(v.removeFallback(at), time.Now())
		}
		accepted := slices.SortedFunc(maps.Keys(at.fallback), netip.Prefix.Compare)
		v.answer(func() { a.box.send(remoteAccepted{att: id, addrs: accepted}) })
	})
}

// checkRemote checks a remote address of attachment at of a: in the VPC network, the length of an
// address of this relay, and no overlap with an attachment of this relay or another agent.
func (v *vpcProc) checkRemote(a *aChild, at *vAtt, ra remoteAddr) error {
	p, network := ra.prefix, networkOf(v.net.ID)
	switch {
	case ra.relay == "" || ra.relay == v.r.cfg.Relay.GetId():
		return errors.New("address names no other relay")
	case !network.Contains(p.Addr()) || p.Bits() < network.Bits():
		return errors.New("address is not in the network of the VPC")
	case p != p.Masked() || !slices.ContainsFunc(at.addrs, func(o netip.Prefix) bool { return o.Bits() == p.Bits() }):
		return errors.New("address does not have the length of an address of this relay")
	}
	// The prefixes that have p, then the prefixes in p. Both walks give p itself.
	for q, set := range v.sets.Supernets(p) {
		if err := overlapErr(a, q, set); err != nil {
			return err
		}
	}
	for q, set := range v.sets.Subnets(p) {
		if q == p {
			continue // Supernets gave it.
		}
		if err := overlapErr(a, q, set); err != nil {
			return err
		}
	}
	return nil
}

// overlapErr returns an error when set, of a prefix q that overlaps a remote address of a, has a
// candidate of an attachment of this relay or of another agent.
func overlapErr(a *aChild, q netip.Prefix, set *routeSet) error {
	for _, o := range set.entries {
		switch {
		case o.own:
			return fmt.Errorf("address overlaps %s of an attachment of this relay", q)
		case o.agent != a.s.agent:
			return fmt.Errorf("address overlaps %s of another agent", q)
		}
	}
	return nil
}

// removeOne removes the candidate e of p.
func (v *vpcProc) removeOne(p netip.Prefix, e *announcer) {
	if set, _ := v.sets.Get(p); set != nil {
		set.entries = slices.DeleteFunc(set.entries, func(o *announcer) bool { return o == e })
	}
}

// removeFallback removes each fallback candidate of at, and returns their prefixes.
func (v *vpcProc) removeFallback(at *vAtt) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(at.fallback))
	for p, e := range at.fallback {
		v.removeOne(p, e)
		ps = append(ps, p)
	}
	clear(at.fallback)
	return ps
}

// recheck checks the reports that overlap a changed prefix again, until no fallback candidate
// changes. A new candidate can refuse an address, and a removed one can let it in.
func (v *vpcProc) recheck(now time.Time) {
	for range v.reports + 1 {
		if v.touched == nil {
			return
		}
		touched := v.touched
		v.touched = nil
		for _, a := range v.as {
			for id, at := range a.atts {
				if slices.ContainsFunc(at.report, func(ra remoteAddr) bool { return touched.OverlapsPrefix(ra.prefix) }) {
					v.reconcile(a, id, false, now)
				}
			}
		}
	}
	v.touched = nil
}
