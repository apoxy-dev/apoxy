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
	defaultSessions = 2
	maxSessions     = 3
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

// Run keeps Config.Sessions attached relay sessions, each on its own relay,
// until ctx ends: it opens one each time a session ends or its relay drains.
// It returns an ErrUpgrade when a relay refuses the agent as too old and no
// relay takes it. With an identity file, it returns an identity.ExpiredError
// when the cert of the file expired and the agent has no relay session.
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
		a.watchers.Wait()
	}()
	wg.Go(func() { a.tick(ctx) })
	wg.Go(func() { a.keepCert(ctx) })
	wg.Go(func() { a.keepAttachments(ctx) })
	if a.cfg.Identity.FromFile() {
		// The agent cannot get a new cert. After the cert of the file expires,
		// its sessions stay, and Run opens no session.
		wg.Go(func() {
			var expired *identity.ExpiredError
			if errors.As(a.cfg.Identity.Run(ctx), &expired) {
				a.expired.Store(expired)
				a.wakeRun()
			}
		})
	}

	k := keeper{a: a, backoff: minBackoff, relist: relister{wait: relistMin}}
	for ctx.Err() == nil {
		var err error
		n, eps := a.missing()
		switch expired := a.fileExpired(); {
		case expired != nil && a.primary() == nil:
			return expired
		case expired != nil:
			k.warnExpired(n)
			a.waitWake(ctx)
		case n > 0:
			err = k.fill(ctx, n, eps)
		case a.primary() == nil:
			// The agent has no session and no relay to dial.
			err = k.retry(ctx, 0, errNoRelays)
		default:
			a.waitWake(ctx)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// fileExpired returns the error of the identity file whose cert expired, or
// nil when the agent has a cert of a newer file.
func (a *Agent) fileExpired() *identity.ExpiredError {
	e := a.expired.Load()
	if e == nil || !e.At.Equal(a.cfg.Identity.Current().Cert.NotAfter) {
		return nil
	}
	return e
}

// waitWake waits until a relay session ends or starts to drain, or the relay
// list changes.
func (a *Agent) waitWake(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-a.wake:
	}
}

// missing returns the number of sessions that Run must open, and the relays for
// them: the relays on which the agent has no session. A draining session does
// not count as a session of the agent, and the alternates of its relay are
// first. An alternate is another relay than the draining one, also when the
// two have one ID.
func (a *Agent) missing() (int, []endpoint) {
	eps := a.endpoints()
	a.mu.Lock()
	defer a.mu.Unlock()
	n := cmp.Or(a.cfg.Sessions, defaultSessions)
	var alts []endpoint
	busy, live := map[string]bool{}, map[string]bool{}
	for _, rc := range a.conns {
		if rc.visitor() {
			continue
		}
		busy[rc.ep.key()] = true
		if rc.state == connDraining {
			alts = append(alts, rc.alternates...)
			continue
		}
		live[rc.ep.key()] = true
		n--
	}
	alts = slices.DeleteFunc(alts, func(e endpoint) bool { return live[e.key()] })
	eps = slices.DeleteFunc(eps, func(e endpoint) bool { return busy[e.key()] })
	free := slices.Concat(alts, eps)
	return max(min(n, len(oneEach(free))), 0), free
}

// errNoRelays is the failure of Run when it has no relay to dial.
var errNoRelays = errors.New("no relays")

// keeper opens the sessions that Run misses.
type keeper struct {
	a        *Agent
	backoff  time.Duration
	next     int           // The relay to dial first.
	rank     uint32        // Rank of the next session.
	failed   int           // Relays that failed in a row.
	refused  *upgradeError // A relay refused the agent as too old since the last session.
	relist   relister
	since    time.Time // Start of the last session.
	unfilled int       // Sessions that Run did not open because the cert expired.
}

// warnExpired logs one warning for each session that Run cannot open because
// the cert of the identity file expired. n is the number of such sessions.
func (k *keeper) warnExpired(n int) {
	if n > k.unfilled {
		slog.Warn("Cannot open a relay session because the certificate of the identity file expired; the open sessions stay",
			"missing", n, "expired_at", k.a.expired.Load().At)
	}
	k.unfilled = n
}

// fill opens n attached sessions on the relays of eps. After a failure it
// goes to retry, and returns its error.
func (k *keeper) fill(ctx context.Context, n int, eps []endpoint) error {
	if !k.since.IsZero() && time.Since(k.since) > stableSession {
		k.backoff = minBackoff
	}
	opened, tried, err := k.open(ctx, n, eps)
	if opened > 0 {
		k.failed, k.refused, k.since = 0, nil, time.Now()
	}
	if opened == n || ctx.Err() != nil {
		return nil
	}
	return k.retry(ctx, tried, err)
}

// retry waits with backoff after tried relays failed with err. When the agent
// has no session and each relay of the list failed, it gets a new relay list.
// It returns an error when Run must stop: the agent has no session, no relay
// takes it, and one needs a newer agent.
func (k *keeper) retry(ctx context.Context, tried int, err error) error {
	a := k.a
	slog.Warn("Failed to open relay session", "error", err)
	if ue := (*upgradeError)(nil); errors.As(err, &ue) {
		k.refused = ue
	}
	if certRefused(err) {
		a.renew(ctx)
	}
	k.next += tried
	if k.failed += tried; a.primary() == nil && k.failed >= len(a.endpoints()) {
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

// open dials each relay of eps and attaches on the n relays with the lowest
// round-trip times that take the attachment. The other sessions end. A relay
// that fails closes only its session. It returns the number of sessions that
// attached and the number of relays that failed.
func (k *keeper) open(ctx context.Context, n int, eps []endpoint) (opened, failed int, err error) {
	a := k.a
	begin := time.Now()
	i := k.next % len(eps)
	conns, failed, err := a.choose(ctx, slices.Concat(eps[i:], eps[:i]), func(ctx context.Context, e endpoint) (*relayConn, error) {
		return a.dialRelay(ctx, e, nil)
	})
	for _, rc := range conns {
		if opened == n {
			a.end(rc)
			continue
		}
		// The agent does not visit a relay on which it has an attached session.
		a.endVisitTo(rc.ep.key(), "agent attaches to the relay")
		if aerr := a.attach(ctx, rc, k.rank, begin); aerr != nil {
			failed, err = failed+1, errors.Join(err, aerr)
			continue
		}
		opened++
		k.rank++
	}
	return opened, failed, err
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
		slog.Info("Ordered the relays by round-trip time", "first", order[0].addr, "rtt", order[0].choiceRTT(), "relays", len(order))
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

// keepCert renews the agent cert before it expires, so that the next
// handshake has a valid one. The open sessions keep their connections.
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
		// The new cert can have a new relay list, so Run counts again.
		a.wakeRun()
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
