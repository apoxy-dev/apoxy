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
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// maxInFlight is the most Attach calls of extra attachments that run at once
// on one relay session.
const maxInFlight = 128

// moveWait limits the wait for the extra attachments on a new relay session
// before the agent moves to it. Tests change it.
var moveWait = 5 * time.Second

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

// Attachment is an attachment of the agent on its relay session.
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

func (x *extra) attachment() Attachment {
	at := x.spec.attachment()
	at.ID, at.Address, at.Prefixes = x.id, overlayAddr(x.prefixes), slices.Clone(x.prefixes)
	return at
}

// Attach adds an attachment on the relay session of the agent. It returns
// after the relay grant is verified and OnAttachment ran. The agent attaches
// it again on each new relay session until Detach. ctx limits the wait for a
// free Attach call.
func (a *Agent) Attach(ctx context.Context, s AttachmentSpec) (Attachment, error) {
	if err := s.validate(); err != nil {
		return Attachment{}, err
	}
	sp := &AttachmentSpec{Name: s.Name, Labels: maps.Clone(s.Labels), Routes: slices.Clone(s.Routes)}
	a.attMu.Lock()
	rc := a.current()
	switch {
	case s.Name == a.cfg.Name || a.specs[s.Name] != nil:
		a.attMu.Unlock()
		return Attachment{}, fmt.Errorf("%w: %s", ErrAttachmentExists, s.Name)
	case rc == nil || rc.ended():
		a.attMu.Unlock()
		return Attachment{}, errNoRelay
	}
	a.specs[s.Name] = sp
	// A new spec is not on rc yet, so claim marks it.
	a.claim(rc, []*AttachmentSpec{sp})
	a.attMu.Unlock()

	x, err := a.attachOne(ctx, rc, sp)
	a.attMu.Lock()
	// After a move, the new session can have it.
	if y := a.onCurrent(sp); y != nil {
		x, err = y, nil
	}
	var gone []placed
	if err != nil {
		gone = a.forget(sp)
	}
	a.attMu.Unlock()
	a.detachRelay(context.WithoutCancel(ctx), gone)
	a.deliver()
	if err != nil {
		return Attachment{}, err
	}
	return x.attachment(), nil
}

// onCurrent returns the attachment of s on the current relay session, or nil.
// attMu must be held.
func (a *Agent) onCurrent(s *AttachmentSpec) *extra {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rc == nil {
		return nil
	}
	if x := a.rc.named(s.Name); x != nil && x.spec == s {
		return x
	}
	return nil
}

// Detach removes the extra attachment name from the relay session and from
// the peers, then runs OnDetach.
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

// Attachments returns the attachment of Config, then the extra attachments
// by name.
func (a *Agent) Attachments() []Attachment {
	a.attMu.Lock()
	defer a.attMu.Unlock()
	a.routeMu.Lock()
	defer a.routeMu.Unlock()
	base := Attachment{Name: a.cfg.Name, Labels: maps.Clone(a.cfg.Labels), Routes: slices.Clone(a.cfg.Routes), Base: true}
	on := map[string]*extra{}
	if rc := a.current(); rc != nil && !rc.ended() {
		base.ID, base.Address, base.Prefixes = rc.attachmentID, rc.self, slices.Clone(rc.prefixes)
		for _, x := range rc.extras {
			on[x.spec.Name] = x
		}
	}
	out := []Attachment{base}
	for _, s := range a.specs {
		if x := on[s.Name]; x != nil {
			out = append(out, x.attachment())
		} else {
			out = append(out, s.attachment())
		}
	}
	slices.SortFunc(out[1:], func(x, y Attachment) int { return cmp.Compare(x.Name, y.Name) })
	return out
}

// current returns the relay session of the agent.
func (a *Agent) current() *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rc
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

// attachClaimed runs Attach on rc for s, which the caller claimed, and adds
// the attachment to rc. If Detach removed s while the call ran, it detaches
// the attachment again.
func (a *Agent) attachClaimed(rc *relayConn, s *AttachmentSpec) (*extra, error) {
	ctx, cancel := context.WithTimeout(rc.ctx, openTimeout)
	defer cancel()
	x, err := rc.attachExtra(ctx, s)
	a.attMu.Lock()
	a.unclaim(rc, s)
	stale := err == nil && a.specs[s.Name] != s
	if err == nil && !stale {
		a.addExtra(rc, x)
		if a.current() == rc {
			a.queueAttached(x)
		}
	}
	a.attMu.Unlock()
	if stale {
		a.detachRelay(ctx, []placed{{rc, x}})
		return nil, fmt.Errorf("%w: %s", ErrNoAttachment, s.Name)
	}
	return x, err
}

// attachAll attaches the specs that the caller claimed on rc, at most
// maxInFlight at a time. When ctx ends, it returns and the calls that run go
// on. It returns the number of specs that failed or did not start, and an
// error of one of them.
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

// moveExtras attaches the extra attachments on next before the agent moves
// to it from old. It waits at most moveWait, and stops when old ends. Then
// keepAttachments attaches the rest.
func (a *Agent) moveExtras(ctx context.Context, old, next *relayConn) {
	a.attMu.Lock()
	specs := a.claim(next, a.wanted())
	a.attMu.Unlock()
	if len(specs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, moveWait)
	defer cancel()
	// With old closed, the agent has no working session, so it moves at once.
	stop := context.AfterFunc(old.qc.Context(), cancel)
	defer stop()
	n, err := a.attachAll(ctx, next, specs)
	if n > 0 || ctx.Err() != nil {
		slog.Info("Moving to the new relay session before all extra attachments attach", "relay", next.addr, "failed", n, "error", err)
	}
}

func (a *Agent) wakeAttach() {
	select {
	case a.attachWake <- struct{}{}:
	default:
	}
}

// keepAttachments attaches the extra attachments that the relay session does
// not have: after a move to a new session, and with backoff after a failure.
func (a *Agent) keepAttachments(ctx context.Context) {
	retry := time.NewTimer(maxBackoff)
	retry.Stop()
	defer retry.Stop()
	backoff := minBackoff
	var last *relayConn
	var retryAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.attachWake:
		case <-retry.C:
		}
		rc := a.current()
		if rc != last {
			last, backoff, retryAt = rc, minBackoff, time.Time{}
		}
		if rc == nil || rc.ended() || time.Now().Before(retryAt) {
			continue
		}
		a.attMu.Lock()
		specs := a.claim(rc, a.wanted())
		a.attMu.Unlock()
		if len(specs) == 0 {
			continue
		}
		n, err := a.attachAll(ctx, rc, specs)
		if n == 0 || ctx.Err() != nil {
			backoff = minBackoff
			continue
		}
		slog.Warn("Failed to attach extra attachments", "relay", rc.addr, "failed", n, "error", err)
		wait := rand.N(backoff) + 1
		retryAt = time.Now().Add(wait)
		retry.Reset(wait)
		backoff = min(2*backoff, maxBackoff)
	}
}

// placed is an extra attachment on a relay session.
type placed struct {
	rc *relayConn
	x  *extra
}

// forget removes s from the attachments to keep, and its attachments from the
// relay sessions and their peers. It queues OnDetach for the attachment on the
// current session. attMu must be held.
func (a *Agent) forget(s *AttachmentSpec) []placed {
	if a.specs[s.Name] == s {
		delete(a.specs, s.Name)
	}
	a.mu.Lock()
	cur := a.rc
	var out []placed
	for rc := range a.conns {
		if x := rc.named(s.Name); x != nil {
			out = append(out, placed{rc, x})
		}
	}
	a.mu.Unlock()
	for _, p := range out {
		a.removeExtra(p.rc, p.x.id)
		if p.rc == cur {
			a.queueDetached(p.x)
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

// queueMove queues the callbacks for the extra attachments when the agent
// moves from old to rc. attMu must be held.
func (a *Agent) queueMove(old, rc *relayConn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	on := make(map[string]bool, len(rc.extras))
	for _, x := range rc.extras {
		on[x.spec.Name] = true
		a.queueAttached(x)
	}
	if old != nil {
		for _, x := range old.extras {
			if !on[x.spec.Name] {
				a.queueDetached(x)
			}
		}
	}
}

// queueAttached queues OnAttachment for x. attMu must be held.
func (a *Agent) queueAttached(x *extra) {
	if f := a.cfg.OnAttachment; f != nil {
		at := x.attachment()
		a.events = append(a.events, func() { f(at) })
	}
}

// queueDetached queues OnDetach for x. attMu must be held.
func (a *Agent) queueDetached(x *extra) {
	if f := a.cfg.OnDetach; f != nil {
		at := x.attachment()
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
