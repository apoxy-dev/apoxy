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
	"sync"
	"sync/atomic"
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

// attachmentOf returns the extra attachment x of rc.
func (rc *relayConn) attachmentOf(x *extra) Attachment {
	at := x.spec.attachment()
	at.ID, at.Address, at.Prefixes, at.Relay = x.id, overlayAddr(x.prefixes), slices.Clone(x.prefixes), rc.addr
	return at
}

// base returns the attachment of Config on the attached session rc.
func (rc *relayConn) base() Attachment {
	cfg := &rc.a.cfg
	return Attachment{
		Name: cfg.Name, Labels: maps.Clone(cfg.Labels), Routes: slices.Clone(cfg.Routes),
		ID: rc.attachmentID, Address: rc.self, Prefixes: slices.Clone(rc.prefixes), Base: true, Relay: rc.addr,
	}
}

// attachments returns the attachment of Config on rc, then the extra
// attachments of rc by name. Agent.attMu must be held.
func (rc *relayConn) attachments() []Attachment {
	out := []Attachment{rc.base()}
	for _, x := range rc.extras {
		out = append(out, rc.attachmentOf(x))
	}
	slices.SortFunc(out[1:], func(x, y Attachment) int { return cmp.Compare(x.Name, y.Name) })
	return out
}

// Attach adds an attachment on each relay session until Detach. It returns the
// one on the lowest-rank session that took it. ctx limits the wait.
func (a *Agent) Attach(ctx context.Context, s AttachmentSpec) (Attachment, error) {
	if err := s.validate(); err != nil {
		return Attachment{}, err
	}
	sp := &AttachmentSpec{Name: s.Name, Labels: maps.Clone(s.Labels), Routes: slices.Clone(s.Routes)}
	a.attMu.Lock()
	rcs := a.sessions(connAttached)
	switch {
	case s.Name == a.cfg.Name || a.specs[s.Name] != nil:
		a.attMu.Unlock()
		return Attachment{}, fmt.Errorf("%w: %s", ErrAttachmentExists, s.Name)
	case len(rcs) == 0:
		a.attMu.Unlock()
		return Attachment{}, errNoRelay
	}
	a.specs[s.Name] = sp
	// A new spec is on no session yet, so claim marks it.
	for _, rc := range rcs {
		a.claim(rc, []*AttachmentSpec{sp})
	}
	a.attMu.Unlock()

	xs, errs := make([]*extra, len(rcs)), make([]error, len(rcs))
	var wg sync.WaitGroup
	for i, rc := range rcs {
		wg.Go(func() { xs[i], errs[i] = a.attachOne(ctx, rc, sp) })
	}
	wg.Wait()
	i := slices.IndexFunc(xs, func(x *extra) bool { return x != nil })
	if i < 0 {
		a.attMu.Lock()
		gone := a.forget(sp)
		a.attMu.Unlock()
		a.detachRelay(context.WithoutCancel(ctx), gone)
		a.deliver()
		return Attachment{}, errors.Join(errs...)
	}
	a.deliver()
	// keepAttachments attaches it on the sessions that failed.
	a.wakeAttach()
	return rcs[i].attachmentOf(xs[i]), nil
}

// Detach removes the extra attachment name from the relay sessions and from
// the peers, then runs OnDetach for each session.
func (a *Agent) Detach(ctx context.Context, name string) error {
	a.attMu.Lock()
	s := a.specs[name]
	switch {
	case name == a.cfg.Name:
		a.attMu.Unlock()
		return ErrBaseAttachment
	case s == nil:
		a.attMu.Unlock()
		return fmt.Errorf("%w: %s", ErrNoAttachment, name)
	}
	gone := a.forget(s)
	a.attMu.Unlock()
	a.detachRelay(ctx, gone)
	a.deliver()
	return nil
}

// Attachments returns the attachment of Config on each relay session in rank
// order, then the extras by name. One with no session has no address.
func (a *Agent) Attachments() []Attachment {
	a.attMu.Lock()
	defer a.attMu.Unlock()
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	rcs := a.sessions(connAttached, connDraining)
	var out []Attachment
	for _, rc := range rcs {
		out = append(out, rc.base())
	}
	if len(rcs) == 0 {
		out = append(out, Attachment{Name: a.cfg.Name, Labels: maps.Clone(a.cfg.Labels), Routes: slices.Clone(a.cfg.Routes), Base: true})
	}
	n := len(out)
	for _, s := range a.specs {
		on := false
		for _, rc := range rcs {
			if x := rc.named(s.Name); x != nil {
				out, on = append(out, rc.attachmentOf(x)), true
			}
		}
		if !on {
			out = append(out, s.attachment())
		}
	}
	slices.SortStableFunc(out[n:], func(x, y Attachment) int { return cmp.Compare(x.Name, y.Name) })
	return out
}

// claim returns the specs that rc does not have and does not attach now, and
// marks them as attaching on rc. attMu must be held.
func (a *Agent) claim(rc *relayConn, specs []*AttachmentSpec) []*AttachmentSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	has := make(map[string]bool, len(rc.extras))
	for _, x := range rc.extras {
		has[x.spec.Name] = true
	}
	if rc.attaching == nil {
		rc.attaching = map[*AttachmentSpec]bool{}
	}
	var out []*AttachmentSpec
	for _, s := range specs {
		if !has[s.Name] && !rc.attaching[s] {
			rc.attaching[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (a *Agent) unclaim(rc *relayConn, specs ...*AttachmentSpec) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range specs {
		delete(rc.attaching, s)
	}
}

// acquire waits for a free Attach call on rc.
func (rc *relayConn) acquire(ctx context.Context) error {
	select {
	case rc.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-rc.ctx.Done():
		return errors.New("relay session closed")
	}
}

func (rc *relayConn) release() { <-rc.sem }

// attachOne attaches s, which the caller claimed on rc, when an Attach call
// is free. ctx limits the wait for it.
func (a *Agent) attachOne(ctx context.Context, rc *relayConn, s *AttachmentSpec) (*extra, error) {
	if err := rc.acquire(ctx); err != nil {
		a.unclaim(rc, s)
		return nil, err
	}
	defer rc.release()
	return a.attachClaimed(rc, s)
}

// attachClaimed attaches s, which the caller claimed, on rc. If Detach removed
// s while the call ran, it detaches the attachment again.
func (a *Agent) attachClaimed(rc *relayConn, s *AttachmentSpec) (*extra, error) {
	ctx, cancel := context.WithTimeout(rc.ctx, openTimeout)
	defer cancel()
	x, err := rc.attachExtra(ctx, s)
	a.attMu.Lock()
	a.unclaim(rc, s)
	a.mu.Lock()
	if err == nil && !rc.live() {
		// The session ended, and the relay removed the attachment with it.
		x, err = nil, errors.New("relay session closed")
	}
	a.mu.Unlock()
	stale := err == nil && a.specs[s.Name] != s
	var visitors []*relayConn
	if err == nil && !stale {
		a.addExtra(rc, x)
		visitors = a.visitorsOf(rc)
		a.queueAttached(rc, x)
	}
	a.attMu.Unlock()
	if stale {
		a.detachRelay(ctx, []placed{{rc, x}})
		return nil, fmt.Errorf("%w: %s", ErrNoAttachment, s.Name)
	}
	// The peers of each visit of rc reach the new attachment too.
	for _, v := range visitors {
		if err := a.joinVisit(ctx, v, x); err != nil {
			slog.Warn("Failed to put an attachment in a visit; the peers of the visit do not reach it",
				"relay", v.addr, "name", s.Name, "error", err)
		}
	}
	return x, err
}

// attachAll attaches the claimed specs on rc, at most maxInFlight at a time. It
// returns the count that failed or did not start, and one error.
func (a *Agent) attachAll(ctx context.Context, rc *relayConn, specs []*AttachmentSpec) (int, error) {
	var (
		mu     sync.Mutex
		failed int
		first  error
		wg     sync.WaitGroup
	)
	fail := func(n int, err error) {
		mu.Lock()
		defer mu.Unlock()
		failed += n
		if first == nil {
			first = err
		}
	}
	for i, s := range specs {
		if err := rc.acquire(ctx); err != nil {
			a.unclaim(rc, specs[i:]...)
			fail(len(specs)-i, err)
			break
		}
		wg.Go(func() {
			_, err := a.attachClaimed(rc, s)
			rc.release()
			if err != nil && !errors.Is(err, ErrNoAttachment) {
				fail(1, err)
			}
			a.deliver()
		})
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	return failed, first
}

// wanted returns the extra attachments to keep. attMu must be held.
func (a *Agent) wanted() []*AttachmentSpec {
	return slices.Collect(maps.Values(a.specs))
}

func (a *Agent) wakeAttach() {
	select {
	case a.attachWake <- struct{}{}:
	default:
	}
}

// keepAttachments attaches the extra attachments that an attached relay session
// does not have: after each attach, and with backoff after a failure.
func (a *Agent) keepAttachments(ctx context.Context) {
	retry := time.NewTimer(maxBackoff)
	retry.Stop()
	defer retry.Stop()
	backoff := minBackoff
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.attachWake:
		case <-retry.C:
		}
		if a.attachMissing(ctx) {
			backoff = minBackoff
			continue
		}
		retry.Reset(rand.N(backoff) + 1)
		backoff = min(2*backoff, maxBackoff)
	}
}

// attachMissing attaches on each attached session the extra attachments that
// it does not have. It reports false when one failed on a session that is open.
func (a *Agent) attachMissing(ctx context.Context) bool {
	var wg sync.WaitGroup
	var failed atomic.Bool
	for _, rc := range a.sessions(connAttached) {
		a.attMu.Lock()
		specs := a.claim(rc, a.wanted())
		a.attMu.Unlock()
		if len(specs) == 0 {
			continue
		}
		wg.Go(func() {
			n, err := a.attachAll(ctx, rc, specs)
			if n > 0 && ctx.Err() == nil && !rc.ended() {
				failed.Store(true)
				slog.Warn("Failed to attach extra attachments", "relay", rc.addr, "failed", n, "error", err)
			}
		})
	}
	wg.Wait()
	return !failed.Load()
}

// placed is an extra attachment on a relay session.
type placed struct {
	rc *relayConn
	x  *extra
}

// forget removes s and its attachments from the relay sessions and their peers,
// and queues OnDetach for each one. attMu must be held.
func (a *Agent) forget(s *AttachmentSpec) []placed {
	if a.specs[s.Name] == s {
		delete(a.specs, s.Name)
	}
	a.mu.Lock()
	var out []placed
	for _, rc := range a.conns {
		if x := rc.named(s.Name); x != nil {
			out = append(out, placed{rc, x})
		}
	}
	a.mu.Unlock()
	for _, p := range out {
		a.removeExtra(p.rc, p.x.id)
		if !p.rc.visitor() {
			a.queueDetached(p.rc, p.x)
		}
	}
	return out
}

// named returns the extra attachment of rc with name. The caller holds
// Agent.routeMu or Agent.mu.
func (rc *relayConn) named(name string) *extra {
	for _, x := range rc.extras {
		if x.spec.Name == name {
			return x
		}
	}
	return nil
}

// detachRelay runs Detach for the attachments on their relay sessions.
func (a *Agent) detachRelay(ctx context.Context, ps []placed) {
	for _, p := range ps {
		if p.rc.ended() {
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, openTimeout)
		err := p.rc.detachExtra(dctx, p.x.id)
		cancel()
		if err != nil && !p.rc.ended() {
			slog.Warn("Failed to detach an attachment at the relay; the relay keeps it until the session ends",
				"relay", p.rc.addr, "name", p.x.spec.Name, "error", err)
		}
	}
}

// queueAttached queues OnAttachment for x on rc, and OnDeprecated when the
// addresses of rc are deprecated. attMu must be held.
func (a *Agent) queueAttached(rc *relayConn, x *extra) {
	at := rc.attachmentOf(x)
	if f := a.cfg.OnAttachment; f != nil {
		a.events = append(a.events, func() { f(at) })
	}
	if f := a.cfg.OnDeprecated; f != nil && rc.deprecated {
		a.events = append(a.events, func() { f(at) })
	}
}

// queueDetached queues OnDetach for x on rc. attMu must be held.
func (a *Agent) queueDetached(rc *relayConn, x *extra) {
	if f := a.cfg.OnDetach; f != nil {
		at := rc.attachmentOf(x)
		a.events = append(a.events, func() { f(at) })
	}
}

// deliver runs the queued callbacks in order, one at a time. It returns after
// the callbacks that were queued before the call ran.
func (a *Agent) deliver() {
	a.cbMu.Lock()
	defer a.cbMu.Unlock()
	for {
		a.attMu.Lock()
		events := a.events
		a.events = nil
		a.attMu.Unlock()
		if len(events) == 0 {
			return
		}
		for _, f := range events {
			f()
		}
	}
}
