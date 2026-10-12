// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	maxSessions = 3
	// rttBand is the difference of two round-trip times that counts as equal. It
	// is above the error of one handshake sample and below the time between regions.
	rttBand = 10 * time.Millisecond
	// rttWaitMin is the shortest wait for the other relays after the first answer. A
	// relay in rttBand answers at most two times rttBand later.
	rttWaitMin = 20 * time.Millisecond
	// rttWaitMax is the longest wait. A relay that answers later than two times
	// rttBand plus 20 ms of noise cannot change the choice.
	rttWaitMax = 40 * time.Millisecond
	// rttRounds is the number of round trips of the first relay in the wait.
	rttRounds = 2
)

// Tests change these values.
var (
	// shuffleRelays orders the relays with a random seed for each agent, so
	// agents do not all dial the first relay.
	shuffleRelays = true
	// After all relays fail, the agent enrolls again for a new relay list, at
	// most once in relistMin. After a failed enroll, the wait doubles up to
	// relistMax.
	relistMin = time.Minute
	relistMax = 10 * time.Minute
)

// Run keeps an attached relay session until ctx ends: it opens one each time
// the agent has none. On a cert renew or a drain, the new session attaches
// before the old one closes. It returns an ErrUpgrade when a relay refuses the
// agent as too old and no other relay takes it. With an identity file, it
// returns an identity.ExpiredError when the cert of the file expires.
func (a *Agent) Run(ctx context.Context) error {
	if m := a.cfg.MTU; m != 0 && (m < psp.DefaultMTU || m > psp.MaxMTU) {
		return fmt.Errorf("MTU must be %d to %d, got %d", psp.DefaultMTU, psp.MaxMTU, m)
	}
	if n := a.cfg.Sessions; n < 0 || n > maxSessions {
		return fmt.Errorf("sessions must be 1 to %d, got %d", maxSessions, n)
	}
	if err := a.cfg.Identity.Start(ctx); err != nil {
		return fmt.Errorf("agent cert: %w", err)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel(nil)
		wg.Wait()
		a.close()
	}()
	wg.Go(func() { a.tick(ctx) })
	wg.Go(func() { a.keepCert(ctx) })
	wg.Go(func() { a.keepAttachments(ctx) })
	if a.cfg.Identity.FromFile() {
		// The agent cannot get a new cert. It stops when the cert of the file expires.
		wg.Go(func() {
			if err := a.cfg.Identity.Run(ctx); err != nil && ctx.Err() == nil {
				cancel(err)
			}
		})
	}

	k := keeper{a: a, backoff: minBackoff, relist: relister{wait: relistMin}}
	for ctx.Err() == nil {
		if a.hasSession() {
			select {
			case <-ctx.Done():
			case <-a.wake:
			}
			continue
		}
		if err := k.fill(ctx); err != nil {
			return err
		}
	}
	if expired := (*identity.ExpiredError)(nil); errors.As(context.Cause(ctx), &expired) {
		return expired
	}
	return nil
}

// hasSession reports whether the agent has a session that is not a visitor
// session, in each state. A replacement that dials counts, so Run waits for it.
func (a *Agent) hasSession() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.ContainsFunc(a.conns, func(rc *relayConn) bool { return !rc.visitor })
}

// keeper opens a session for Run each time the agent has none.
type keeper struct {
	a       *Agent
	backoff time.Duration
	next    int           // The relay to dial first.
	failed  int           // Relays that failed in a row.
	refused *upgradeError // A relay refused the agent as too old since the last session.
	relist  relister
	since   time.Time // Start of the last session.
}

// fill opens one attached session, and waits with backoff after a failure. It
// returns an error when Run must stop: no relay takes the agent, and one needs
// a newer agent.
func (k *keeper) fill(ctx context.Context) error {
	a := k.a
	if !k.since.IsZero() && time.Since(k.since) > stableSession {
		k.backoff = minBackoff
	}
	tried, err := k.open(ctx)
	if err == nil {
		k.failed, k.refused, k.since = 0, nil, time.Now()
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	slog.Warn("Failed to open relay session", "error", err)
	if ue := (*upgradeError)(nil); errors.As(err, &ue) {
		k.refused = ue
	}
	if certRefused(err) {
		a.renew(ctx)
	}
	k.next += tried
	if k.failed += tried; k.failed >= len(a.endpoints()) {
		// More dials do not help when a relay needs a newer agent, so Run stops.
		if k.refused != nil {
			return k.refused
		}
		k.failed = 0
		if k.relist.run(ctx, a) {
			// Dial the new relays now.
			k.backoff = minBackoff
			return nil
		}
	}
	wait := rand.N(k.backoff) + 1
	k.backoff = min(2*k.backoff, maxBackoff)
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
	return nil
}

// open dials each relay and attaches on the one with the lowest round-trip
// time that takes the attachment. The other sessions end. It returns the
// number of relays that failed.
func (k *keeper) open(ctx context.Context) (int, error) {
	a := k.a
	begin := time.Now()
	eps := a.endpoints()
	if len(eps) == 0 {
		return 0, errors.New("no relays")
	}
	i := k.next % len(eps)
	conns, failed, err := a.choose(ctx, slices.Concat(eps[i:], eps[:i]), func(ctx context.Context, e endpoint) (*relayConn, error) {
		return a.dialRelay(ctx, e, false)
	})
	attached := false
	for _, rc := range conns {
		if attached {
			a.end(rc)
			continue
		}
		if aerr := a.attach(ctx, rc, nil, begin); aerr != nil {
			failed, err = failed+1, errors.Join(err, aerr)
			continue
		}
		attached = true
	}
	if attached {
		return failed, nil
	}
	return failed, err
}

// choose dials each relay of eps at the same time, and returns the sessions in
// the order of the choice: lowest round-trip time first. It waits for the other
// relays only a short time after the first answer, and stops the late dials.
func (a *Agent) choose(ctx context.Context, eps []endpoint, dial func(context.Context, endpoint) (*relayConn, error)) ([]*relayConn, int, error) {
	type result struct {
		i   int
		rc  *relayConn
		err error
	}
	eps = oneEach(eps)
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan result, len(eps))
	for i, e := range eps {
		go func() {
			rc, err := dial(ctx, e)
			results <- result{i, rc, err}
		}()
	}
	conns := make([]*relayConn, len(eps))
	var errs []error
	var timer <-chan time.Time
	left := len(eps)
wait:
	for ; left > 0; left-- {
		select {
		case r := <-results:
			if r.err != nil {
				errs = append(errs, fmt.Errorf("relay %s: %w", eps[r.i].addr, r.err))
				continue
			}
			conns[r.i] = r.rc
			if timer == nil {
				t := time.NewTimer(a.choiceWait(r.rc))
				defer t.Stop()
				timer = t.C
			}
		case <-timer:
			break wait
		}
	}
	cancel()
	go func() {
		// A late dial can pass before it sees the stop.
		for ; left > 0; left-- {
			if r := <-results; r.err == nil {
				a.end(r.rc)
			}
		}
	}()
	order := a.rank(conns)
	if len(order) > 1 {
		slog.Info("Chose the relay with the lowest round-trip time", "relay", order[0].addr, "rtt", order[0].choiceRTT(), "relays", len(order))
	}
	return order, len(errs), errors.Join(errs...)
}

// choiceWait returns the wait for the other relays after rc answered first.
func (a *Agent) choiceWait(rc *relayConn) time.Duration {
	rtt := rc.choiceRTT()
	if rtt <= 0 {
		// A time that is not known uses the longest wait.
		return a.rttWaitMax
	}
	return min(max(rttRounds*rtt, a.rttWaitMin), a.rttWaitMax)
}

// choiceRTT returns the round-trip time of rc for the choice: the lower of the
// QUIC time and the path probe time. One late packet raises only one of them.
func (rc *relayConn) choiceRTT() time.Duration {
	rtt, probe := time.Duration(rc.rtt.Load()), time.Duration(rc.probeRTT.Load())
	if probe > 0 && (rtt <= 0 || probe < rtt) {
		return probe
	}
	return rtt
}

// rank returns the sessions in conns that are not nil, in the order of the
// choice. The first session in conns within rttBand of the lowest time is next
// each time, so the order of the relays of this agent breaks a tie.
func (a *Agent) rank(conns []*relayConn) []*relayConn {
	left := slices.DeleteFunc(slices.Clone(conns), func(rc *relayConn) bool { return rc == nil })
	// A session with no time is after each session with a time.
	rtt := func(rc *relayConn) time.Duration {
		if t := rc.choiceRTT(); t > 0 {
			return t
		}
		return time.Duration(1<<63 - 1 - int64(a.rttBand))
	}
	var order []*relayConn
	for len(left) > 0 {
		low := rtt(slices.MinFunc(left, func(x, y *relayConn) int { return cmp.Compare(rtt(x), rtt(y)) }))
		k := slices.IndexFunc(left, func(rc *relayConn) bool { return rtt(rc) <= low+a.rttBand })
		order = append(order, left[k])
		left = slices.Delete(left, k, k+1)
	}
	return order
}

// keepCert renews the agent cert before it expires, one time for all sessions.
// Then it tells each session, which opens its replacement with the new cert.
func (a *Agent) keepCert(ctx context.Context) {
	id := a.cfg.Identity
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		cred := id.Current()
		t.Reset(time.Until(cred.RenewAt()))
		if id.FromFile() {
			// The agent does not renew the cert of an identity file. It waits for a new file.
			t.Stop()
		}
		select {
		case <-ctx.Done():
			return
		case <-id.Changed():
		case <-t.C:
			if id.Current() == cred {
				if err := id.Renew(ctx); err != nil {
					slog.Warn("Failed to renew agent cert", "error", err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(renewRetry):
					}
					continue
				}
			}
		}
		a.mu.Lock()
		for _, rc := range a.conns {
			select {
			case rc.renewed <- struct{}{}:
			default:
			}
		}
		a.mu.Unlock()
	}
}

// renew gets a new agent cert after a relay refused the cert in use.
func (a *Agent) renew(ctx context.Context) {
	if err := a.cfg.Identity.Renew(ctx); err != nil {
		slog.Warn("Failed to renew agent cert", "error", err)
	}
}

// relister enrolls again for a new relay list after all relays failed. With
// an identity file, it reads the file again.
type relister struct {
	at   time.Time     // No enroll before this time.
	wait time.Duration // Doubles after a failed enroll.
}

// run enrolls again if the wait ended. It reports whether it got a new list.
func (l *relister) run(ctx context.Context, a *Agent) bool {
	if len(a.cfg.Relays) > 0 || time.Now().Before(l.at) {
		return false
	}
	old := a.cfg.Identity.Current()
	rctx, cancel := context.WithTimeout(ctx, openTimeout)
	err := a.cfg.Identity.Renew(rctx)
	cancel()
	// An identity file that did not change gives no error and no new list.
	got := err == nil && a.cfg.Identity.Current() != old
	switch {
	case err != nil:
		l.wait = min(2*l.wait, relistMax)
		slog.Warn("Failed to get a new relay list; keeping the cached list", "error", err)
	case got:
		l.wait = relistMin
		slog.Info("Got a new relay list after all relays failed", "relays", len(a.cfg.Identity.Current().Relays))
	}
	l.at = time.Now().Add(l.wait + rand.N(l.wait/2+1))
	return got
}

// endpoint is one address of a relay.
type endpoint struct {
	id   string // TLS name of the relay. Empty means the host in addr.
	addr string
}

// key identifies the relay of e.
func (e endpoint) key() string {
	return cmp.Or(e.id, e.addr)
}

// endpoints returns the addresses of the relays in the order of this agent.
// The addresses of one relay stay in their order.
func (a *Agent) endpoints() []endpoint {
	relays := a.cfg.Relays
	if len(relays) == 0 {
		if c := a.cfg.Identity.Current(); c != nil {
			relays = c.Relays
		}
	}
	var out []endpoint
	for _, r := range relays {
		for _, addr := range r.Addresses {
			out = append(out, endpoint{id: r.ID, addr: addr})
		}
	}
	if shuffleRelays {
		slices.SortStableFunc(out, func(x, y endpoint) int {
			return cmp.Compare(maphash.String(a.seed, x.key()), maphash.String(a.seed, y.key()))
		})
	}
	return out
}

// oneEach returns the first address of each relay in eps, so entries with one
// name count as one relay.
func oneEach(eps []endpoint) []endpoint {
	var out []endpoint
	for _, e := range eps {
		if !slices.ContainsFunc(out, func(o endpoint) bool { return o.key() == e.key() }) {
			out = append(out, e)
		}
	}
	return out
}
