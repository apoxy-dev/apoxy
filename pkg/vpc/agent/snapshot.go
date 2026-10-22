// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// snapshot is the state that the public reads see. The root makes a new one
// after each change; a snapshot does not change after the root stores it.
type snapshot struct {
	running bool
	// conns are the attached and the draining home sessions in rank order.
	conns []*connSnap
	// specs are the extra attachments to keep, by name. They stay after Run.
	specs map[string]*AttachmentSpec
	// visits are the routes of the visits.
	visits []Route
}

// connSnap is one home session in a snapshot.
type connSnap struct {
	relay, name    string
	rank           uint32
	draining       bool
	mode           dp.Mode
	reason         dp.FallbackReason
	connect, setup time.Duration
	rtt            *atomic.Int64 // Written by the QUIC tracer.
	base           Attachment
	extras         []Attachment // By name.
	dnsServers     []string
	dnsSearch      []string
}

// primary returns the session with the default address: the attached one with
// the lowest rank, else the draining one with the lowest rank, or nil.
func (s *snapshot) primary() *connSnap {
	var best *connSnap
	for _, c := range s.conns {
		if best == nil || best.draining && !c.draining {
			best = c
		}
	}
	return best
}

// liveRTT returns the smoothed round-trip time of the session.
func (c *connSnap) liveRTT() time.Duration {
	if c.rtt == nil {
		return 0
	}
	return time.Duration(c.rtt.Load())
}

// Attachments returns the attachment of Config on each relay session in rank
// order, then the extras by name. One with no session has no address.
func (a *Agent) Attachments() []Attachment {
	s := a.snap.Load()
	var out []Attachment
	for _, c := range s.conns {
		out = append(out, c.base)
	}
	if len(s.conns) == 0 {
		out = append(out, a.baseSpec())
	}
	n := len(out)
	for _, sp := range s.specs {
		on := false
		for _, c := range s.conns {
			if i := slices.IndexFunc(c.extras, func(at Attachment) bool { return at.Name == sp.Name }); i >= 0 {
				out, on = append(out, c.extras[i]), true
			}
		}
		if !on {
			out = append(out, sp.attachment())
		}
	}
	slices.SortStableFunc(out[n:], func(x, y Attachment) int { return cmp.Compare(x.Name, y.Name) })
	return out
}

// baseSpec returns the attachment of Config with no relay session.
func (a *Agent) baseSpec() Attachment {
	cfg := &a.cfg
	return Attachment{Name: cfg.Name, Labels: maps.Clone(cfg.Labels), Routes: slices.Clone(cfg.Routes), Base: true}
}
