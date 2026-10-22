// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// maxInFlight is the most Attach calls of extra attachments that run at once
// on one relay session.
const maxInFlight = 128

var (
	// ErrInvalidAttachment is the error for an AttachmentSpec that is not valid.
	ErrInvalidAttachment = errors.New("attachment is not valid")
	// ErrAttachmentExists is the error for a name that is in use.
	ErrAttachmentExists = errors.New("attachment name is in use")
	// ErrNoAttachment is the error for a name that is not in use.
	ErrNoAttachment = errors.New("no attachment has this name")
	// ErrBaseAttachment is the error for a Detach of the attachment of Config.
	ErrBaseAttachment = errors.New("the attachment of Config cannot be detached")
)

// AttachmentSpec is an attachment that the agent keeps in addition to the
// attachment of Config.
type AttachmentSpec struct {
	// Name is a DNS-1123 subdomain. Each attachment of the agent has its own name.
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	// Routes are the prefixes that the attachment advertises into the VPC.
	Routes []netip.Prefix `json:"routes,omitempty"`
}

// Attachment is an attachment of the agent on one relay session. The agent
// has each attachment on each attached session, with an address for each.
type Attachment struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Routes []netip.Prefix    `json:"routes,omitempty"`
	// ID is the relay attachment ID. It changes at each attach. It is empty
	// while the attachment waits for a relay session.
	ID       string         `json:"id"`
	Address  netip.Addr     `json:"address"` // Overlay address.
	Prefixes []netip.Prefix `json:"prefixes,omitempty"`
	// Base is true for the attachment of Config.
	Base bool `json:"base"`
	// Relay is the address of the relay of the session.
	Relay string `json:"relay,omitempty"`
}

func (s *AttachmentSpec) validate() error {
	if err := relay.ValidateAttachment(s.Name, s.Labels); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAttachment, err)
	}
	for _, p := range s.Routes {
		if !p.IsValid() {
			return fmt.Errorf("%w: route is not a valid prefix", ErrInvalidAttachment)
		}
	}
	return nil
}

// attachment returns s as an attachment with no relay session.
func (s *AttachmentSpec) attachment() Attachment {
	return Attachment{Name: s.Name, Labels: maps.Clone(s.Labels), Routes: slices.Clone(s.Routes)}
}

// Attach adds an attachment on each relay session until Detach. It returns the
// one on the lowest-rank session that took it. ctx limits the wait for a free
// Attach call; a call that started runs to its end.
func (a *Agent) Attach(ctx context.Context, s AttachmentSpec) (Attachment, error) {
	if err := s.validate(); err != nil {
		return Attachment{}, err
	}
	sp := &AttachmentSpec{Name: s.Name, Labels: maps.Clone(s.Labels), Routes: slices.Clone(s.Routes)}
	for {
		snap := a.snap.Load()
		if !snap.running {
			if s.Name == a.cfg.Name || snap.specs[s.Name] != nil {
				return Attachment{}, fmt.Errorf("%w: %s", ErrAttachmentExists, s.Name)
			}
			return Attachment{}, errNoRelay
		}
		ref := a.run.Load()
		if ref == nil {
			continue
		}
		reply := make(chan attachReply, 1)
		ref.mb.send(attachReqMsg{sp, ctx, reply})
		done := ctx.Done()
	wait:
		for {
			select {
			case r := <-reply:
				return r.at, r.err
			case <-ref.stopped:
				select {
				case r := <-reply:
					return r.at, r.err
				default:
				}
				break wait
			case <-done:
				ref.mb.send(cancelReqMsg{sp})
				done = nil
			}
		}
	}
}

// Detach removes the extra attachment name from the relay sessions, then runs
// OnDetach for each session.
func (a *Agent) Detach(ctx context.Context, name string) error {
	for {
		snap := a.snap.Load()
		if !snap.running {
			switch {
			case name == a.cfg.Name:
				return ErrBaseAttachment
			case snap.specs[name] == nil:
				return fmt.Errorf("%w: %s", ErrNoAttachment, name)
			}
			n := *snap
			n.specs = maps.Clone(snap.specs)
			delete(n.specs, name)
			if a.snap.CompareAndSwap(snap, &n) {
				return nil
			}
			continue
		}
		ref := a.run.Load()
		if ref == nil {
			continue
		}
		reply := make(chan error, 1)
		ref.mb.send(detachReqMsg{name, ctx, reply})
		select {
		case err := <-reply:
			return err
		case <-ref.stopped:
			select {
			case err := <-reply:
				return err
			default:
			}
		}
	}
}

// attachReq is a public Attach that waits in the root.
type attachReq struct {
	spec  *AttachmentSpec
	reply chan attachReply
	// wait are the sessions whose answer is not in yet, rank their rank.
	wait  map[*session]bool
	rank  map[*session]uint32
	ok    map[*session]Attachment
	errs  []error
	stale bool // Detach forgot the spec during the call.
	// rollback is set after no session took the spec: rolling are the
	// sessions whose detach is not done yet.
	rollback bool
	rolling  map[*session]bool
	lastSeq  uint64 // The last callback of this request.
}

// detachReq is a public Detach that waits in the root.
type detachReq struct {
	spec    *AttachmentSpec
	reply   chan error
	wait    map[*session]bool
	lastSeq uint64
}

func (r *root) attachRequest(m attachReqMsg) {
	name := m.spec.Name
	if r.ending {
		m.reply <- attachReply{err: errNoRelay}
		return
	}
	if name == r.a.cfg.Name || r.specs[name] != nil {
		m.reply <- attachReply{err: fmt.Errorf("%w: %s", ErrAttachmentExists, name)}
		return
	}
	hs := r.attachedHomes()
	if len(hs) == 0 {
		m.reply <- attachReply{err: errNoRelay}
		return
	}
	r.specs[name] = m.spec
	q := &attachReq{
		spec: m.spec, reply: m.reply,
		wait: map[*session]bool{}, rank: map[*session]uint32{}, ok: map[*session]Attachment{},
	}
	for _, h := range hs {
		h.pending[name] = m.spec
		h.s.mb.send(attachX{m.spec, m.ctx})
		q.wait[h.s], q.rank[h.s] = true, h.rank
	}
	r.attaches[m.spec] = q
}

func (r *root) cancelRequest(m cancelReqMsg) {
	if q := r.attaches[m.spec]; q != nil {
		for s := range q.wait {
			s.mb.send(cancelX{m.spec})
		}
	}
}

func (r *root) detachRequest(m detachReqMsg) {
	if r.ending {
		m.reply <- errNoRelay
		return
	}
	spec := r.specs[m.name]
	switch {
	case m.name == r.a.cfg.Name:
		m.reply <- ErrBaseAttachment
		return
	case spec == nil:
		m.reply <- fmt.Errorf("%w: %s", ErrNoAttachment, m.name)
		return
	}
	if q := r.attaches[spec]; q != nil {
		q.stale = true
	}
	q := &detachReq{spec: spec, reply: m.reply, wait: r.forget(spec, m.ctx), lastSeq: r.seq}
	if !r.detachProgress(q) {
		r.detaches = append(r.detaches, q)
	}
}

// forget removes spec from the wanted set, sends detachX to each session that
// has it or attaches it, and queues OnDetach for each session that has it. It
// returns the sessions that got detachX.
func (r *root) forget(spec *AttachmentSpec, ctx context.Context) map[*session]bool {
	name := spec.Name
	if r.specs[name] == spec {
		delete(r.specs, name)
	}
	out := map[*session]bool{}
	for _, h := range r.homes {
		if x, ok := h.held[name]; ok && x.spec == spec {
			delete(h.held, name)
			if f := r.a.cfg.OnDetach; f != nil {
				r.queue(func() { f(x.at) })
			}
		} else if h.pending[name] == spec {
			delete(h.pending, name)
		} else {
			continue
		}
		h.s.mb.send(detachX{spec, ctx})
		out[h.s] = true
	}
	return out
}

// attached takes the result of an attachX.
func (r *root) attached(m attachedX) {
	name := m.spec.Name
	h := r.homeOf(m.s)
	if h != nil && h.pending[name] == m.spec {
		delete(h.pending, name)
	}
	wanted := r.specs[name] == m.spec
	err := m.err
	switch {
	case err == nil && (!wanted || h == nil || r.ending):
		// The spec was forgotten during the call; the session got its detachX.
		err = fmt.Errorf("%w: %s", ErrNoAttachment, name)
	case err == nil:
		h.held[name] = heldX{m.spec, m.at}
		if f := r.a.cfg.OnAttachment; f != nil {
			r.queue(func() { f(m.at) })
		}
		if f := r.a.cfg.OnDeprecated; f != nil && h.deprecated {
			r.queue(func() { f(m.at) })
		}
		r.retryWait = minBackoff
	case wanted && h != nil && !r.ending:
		slog.Warn("Failed to attach an extra attachment", "relay", h.ep.addr, "name", name, "error", err)
		r.armRetry()
	}
	q := r.attaches[m.spec]
	if q == nil || !q.wait[m.s] {
		return
	}
	delete(q.wait, m.s)
	if err == nil {
		q.ok[m.s] = m.at
		q.lastSeq = r.seq
	} else {
		q.errs = append(q.errs, err)
	}
	r.attachProgress(q)
}

// detached takes the end of a detachX.
func (r *root) detached(m detachedX) {
	for _, q := range r.attaches {
		if q.spec == m.spec && q.rolling[m.s] {
			delete(q.rolling, m.s)
			r.attachProgress(q)
		}
	}
	r.detaches = slices.DeleteFunc(r.detaches, func(q *detachReq) bool {
		if q.spec == m.spec {
			delete(q.wait, m.s)
		}
		return r.detachProgress(q)
	})
}

// sessEnded counts the end of s as the failed answer of s.
func (q *attachReq) sessEnded(s *session) {
	if q.wait[s] {
		delete(q.wait, s)
		q.errs = append(q.errs, errSessionClosed)
	}
	delete(q.rolling, s)
}

// attachProgress replies to q when each session answered and the callbacks of
// q ran: the attachment on the lowest rank, or the errors after the rollback.
func (r *root) attachProgress(q *attachReq) {
	if r.attaches[q.spec] != q || len(q.wait) > 0 {
		return
	}
	if len(q.ok) == 0 && !q.stale && !q.rollback {
		q.rollback = true
		q.rolling = r.forget(q.spec, nil)
		q.lastSeq = r.seq
	}
	if len(q.rolling) > 0 || r.done < q.lastSeq {
		return
	}
	delete(r.attaches, q.spec)
	if len(q.ok) == 0 {
		q.reply <- attachReply{err: errors.Join(q.errs...)}
		return
	}
	best := slices.MinFunc(slices.Collect(maps.Keys(q.ok)), func(x, y *session) int { return cmp.Compare(q.rank[x], q.rank[y]) })
	q.reply <- attachReply{at: q.ok[best]}
	// The sessions that failed get the spec again.
	r.attachMissing()
}

// detachProgress replies nil to q when each session detached and the
// callbacks of q ran. It reports whether it replied.
func (r *root) detachProgress(q *detachReq) bool {
	if len(q.wait) > 0 || r.done < q.lastSeq {
		return false
	}
	q.reply <- nil
	return true
}

// attachMissing sends attachX for each wanted extra attachment that an
// attached session does not have and does not attach now.
func (r *root) attachMissing() {
	if r.ending {
		return
	}
	for _, h := range r.attachedHomes() {
		for name, spec := range r.specs {
			if _, ok := h.held[name]; ok || h.pending[name] != nil {
				continue
			}
			h.pending[name] = spec
			h.s.mb.send(attachX{spec: spec})
		}
	}
}

// armRetry starts the wait for the next attachMissing after a failure.
func (r *root) armRetry() {
	if r.attachRetry != nil {
		return
	}
	r.attachRetry = time.NewTimer(rand.N(r.retryWait) + 1)
	r.retryWait = min(2*r.retryWait, maxBackoff)
}
