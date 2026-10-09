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
	"time"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
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
	// spareCheck is the interval of the spare session check.
	spareCheck = 5 * time.Second
	// upgradeRetry is the wait for the next spare dial after a relay refused the
	// agent as too old. Only a change of the relays makes that dial pass.
	upgradeRetry = 10 * time.Minute
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

func primaryHello(*relayConn) bool { return false }
func spareHello(*relayConn) bool   { return true }

// endpoint is one address of a relay.
type endpoint struct {
	id   string // TLS name of the relay. Empty means the host in addr.
	addr string
}

// key identifies the relay of e.
func (e endpoint) key() string {
	if e.id != "" {
		return e.id
	}
	return e.addr
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

func (a *Agent) sessions() int {
	if a.cfg.Sessions == 0 {
		return defaultSessions
	}
	return a.cfg.Sessions
}

// attachRelay returns an attached session: a spare, or else a new session on the
// relay that race chooses. It returns the number of relays that failed.
func (a *Agent) attachRelay(ctx context.Context, next int) (*relayConn, int, error) {
	begin := time.Now()
	if rc := a.promote(ctx, begin, nil); rc != nil {
		return rc, 0, nil
	}
	eps := a.endpoints()
	if len(eps) == 0 {
		return nil, 0, errors.New("no relays")
	}
	k := next % len(eps)
	order := slices.Concat(eps[k:], eps[:k])
	// Skip the relays of other sessions, unless no other relay is left.
	if free := a.freeEndpoints(order); len(free) > 0 {
		order = free
	}
	rc, tried, err := a.race(ctx, order)
	if err != nil {
		return nil, tried, err
	}
	if err := rc.attach(ctx, begin); err != nil {
		rc.close()
		return nil, tried + 1, fmt.Errorf("relay %s: %w", rc.addr, err)
	}
	return rc, tried, nil
}

// candidate is one relay of a race.
type candidate struct {
	ep    endpoint
	ready bool          // The session is ready for Hello, and rtt is set.
	rtt   time.Duration // Round-trip time of the session. Zero is not known.
	spare bool          // Result of the choice, set before the race closes chosen.
	done  bool          // The dial ended.
	rc    *relayConn    // Session of a dial that passed.
}

// dialFunc is dialRelay for an attached session or a spare.
type dialFunc func(ctx context.Context, e endpoint, spare func(*relayConn) bool) (*relayConn, error)

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

// race opens a session on the relay with the lowest round-trip time in eps. The
// other sessions become spares. It returns the number of relays that failed.
func (a *Agent) race(ctx context.Context, eps []endpoint) (*relayConn, int, error) {
	rc, others, failed, err := a.choose(ctx, eps, func(ctx context.Context, e endpoint, spare func(*relayConn) bool) (*relayConn, error) {
		return a.dialRelay(ctx, e, spare, false)
	})
	if err != nil {
		return nil, failed, err
	}
	go others(a.addSpare)
	return rc, failed, nil
}

// choose dials each relay of eps at the same time. Each session waits before
// Hello for the choice of rank. others gives the other sessions, best first.
func (a *Agent) choose(ctx context.Context, eps []endpoint, dial dialFunc) (won *relayConn, others func(func(*relayConn)), failed int, err error) {
	type result struct {
		i   int
		rc  *relayConn
		err error
	}
	var cands []*candidate
	for _, e := range oneEach(eps) {
		cands = append(cands, &candidate{ep: e, spare: true})
	}
	ready, results := make(chan int, len(cands)), make(chan result, len(cands))
	chosen := make(chan struct{})
	for i, c := range cands {
		go func() {
			rc, err := dial(ctx, c.ep, func(rc *relayConn) bool {
				c.rtt = time.Duration(rc.rtt.Load())
				ready <- i
				<-chosen
				return c.spare
			})
			results <- result{i, rc, err}
		}()
	}
	var errs []error
	fail := func(r result) {
		cands[r.i].done = true
		errs = append(errs, fmt.Errorf("relay %s: %w", cands[r.i].ep.addr, r.err))
	}
	// The choice is made when each relay answered or failed, or after a wait that
	// starts at the first answer.
	var timer <-chan time.Time
wait:
	for answered := 0; answered+len(errs) < len(cands); {
		select {
		case i := <-ready:
			cands[i].ready = true
			answered++
			if timer == nil {
				// A time that is not known uses the longest wait.
				wait := a.rttWaitMax
				if rtt := cands[i].rtt; rtt > 0 {
					wait = min(max(rttRounds*rtt, a.rttWaitMin), a.rttWaitMax)
				}
				t := time.NewTimer(wait)
				defer t.Stop()
				timer = t.C
			}
		case r := <-results:
			// Only a dial that failed ends before the choice.
			fail(r)
		case <-timer:
			break wait
		}
	}
	order := a.rank(cands)
	if len(order) > 0 {
		cands[order[0]].spare = false
	}
	close(chosen)
	if len(order) > 1 {
		w := cands[order[0]]
		slog.Info("Chose the relay with the lowest round-trip time", "relay", w.ep.addr, "rtt", w.rtt, "relays", len(order))
	}
	// The first session in the order that opens takes the attachment. With none,
	// the first session of a relay that answered late takes it.
	pick := func() *relayConn {
		for _, i := range order {
			if c := cands[i]; !c.done || c.rc != nil {
				return c.rc
			}
		}
		for _, c := range cands {
			if c.rc != nil {
				return c.rc
			}
		}
		return nil
	}
	left := len(cands) - len(errs)
	for ; won == nil && left > 0; left-- {
		r := <-results
		if r.err != nil {
			fail(r)
		} else {
			cands[r.i].rc = r.rc
			cands[r.i].done = true
		}
		won = pick()
	}
	if won == nil {
		return nil, nil, len(errs), errors.Join(errs...)
	}
	others = func(yield func(*relayConn)) {
		// The sessions of the order end Hello in a short time. A late session can
		// open before them, and it goes after them.
		open := func() bool {
			return slices.ContainsFunc(order, func(i int) bool { return !cands[i].done })
		}
		for ; left > 0 && open(); left-- {
			r := <-results
			cands[r.i].rc, cands[r.i].done = r.rc, true
		}
		for _, i := range order {
			if rc := cands[i].rc; rc != nil && rc != won {
				yield(rc)
			}
		}
		for _, c := range cands {
			if !c.ready && c.rc != nil && c.rc != won {
				yield(c.rc)
			}
		}
		for ; left > 0; left-- {
			if r := <-results; r.err == nil {
				yield(r.rc)
			}
		}
	}
	return won, others, len(errs), nil
}

// rank returns the relays of cands that answered, in the order of the choice.
// The first relay in cands within rttBand of the lowest time is next each time.
func (a *Agent) rank(cands []*candidate) []int {
	var left, order []int
	for i, c := range cands {
		if c.ready {
			left = append(left, i)
		}
	}
	// A session with no time is after each session with a time.
	rtt := func(i int) time.Duration {
		if cands[i].rtt <= 0 {
			return time.Duration(1<<63 - 1 - int64(a.rttBand))
		}
		return cands[i].rtt
	}
	for len(left) > 0 {
		low := rtt(slices.MinFunc(left, func(x, y int) int { return cmp.Compare(rtt(x), rtt(y)) }))
		k := slices.IndexFunc(left, func(i int) bool { return rtt(i) <= low+a.rttBand })
		order = append(order, left[k])
		left = slices.Delete(left, k, k+1)
	}
	return order
}

// move returns the session that takes the attachment from rc, which drains:
// a spare, with spares on the alternates first, or else a new session to the
// first alternate that takes it.
func (a *Agent) move(ctx context.Context, rc *relayConn, alts []*dp.RelayRef) (*relayConn, error) {
	var prefer []string
	var eps []endpoint
	for _, r := range alts {
		prefer = append(prefer, r.GetId())
		for _, addr := range r.GetAddresses() {
			eps = append(eps, endpoint{id: r.GetId(), addr: addr})
		}
	}
	if next := a.promote(ctx, time.Now(), prefer); next != nil {
		return next, nil
	}
	if len(eps) == 0 {
		// Only a replacement of the draining relay can answer here. Run dials again
		// when rc ends, so this open stops then.
		return a.openNext(ctx, rc, rc.ep)
	}
	// Run can have no endpoint for an alternate, so these opens continue when rc ends.
	var errs []error
	for _, e := range eps {
		next, err := a.open(ctx, e)
		if err == nil {
			return next, nil
		}
		errs = append(errs, fmt.Errorf("relay %s: %w", e.addr, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// promote attaches on a spare session and returns it, or nil when no spare
// attaches. Spares on the relays in prefer go first.
func (a *Agent) promote(ctx context.Context, begin time.Time, prefer []string) *relayConn {
	for ctx.Err() == nil {
		rc := a.takeSpare(prefer)
		if rc == nil {
			return nil
		}
		if err := rc.attach(ctx, begin); err != nil {
			if ctx.Err() == nil {
				slog.Warn("Failed to attach on a spare relay session", "relay", rc.addr, "error", err)
			}
			rc.close()
			continue
		}
		slog.Info("Moved the attachment to a spare relay session", "relay", rc.addr)
		return rc
	}
	return nil
}

// takeSpare removes a spare session from the spares and returns it.
func (a *Agent) takeSpare(prefer []string) *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	best := -1
	for i, rc := range a.spares {
		if rc.ended() {
			continue
		}
		if best < 0 || slices.Contains(prefer, rc.ep.id) && !slices.Contains(prefer, a.spares[best].ep.id) {
			best = i
		}
	}
	if best < 0 {
		return nil
	}
	rc := a.spares[best]
	a.spares = slices.Delete(a.spares, best, best+1)
	close(rc.spareDone)
	return rc
}

// takeSpareOn removes the spare session on the relay with key from the spares
// and returns it, or nil.
func (a *Agent) takeSpareOn(key string) *relayConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := slices.IndexFunc(a.spares, func(rc *relayConn) bool { return rc.ep.key() == key })
	if i < 0 {
		return nil
	}
	rc := a.spares[i]
	a.spares = slices.Delete(a.spares, i, i+1)
	close(rc.spareDone)
	return rc
}

// usesRelay reports whether a session of the agent other than self is open,
// or opens, on the relay with key. A relay gives the agent address to the
// newest session, so the agent keeps one session per relay. a.mu is held.
func (a *Agent) usesRelay(key string, self *relayConn) bool {
	if a.dialing[key] > 0 {
		return true
	}
	for rc := range a.conns {
		if rc != self && rc.ep.key() == key && !rc.ended() {
			return true
		}
	}
	return false
}

// freeEndpoints returns the endpoints in eps on relays that no session of the
// agent uses.
func (a *Agent) freeEndpoints(eps []endpoint) []endpoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(eps), func(e endpoint) bool { return a.usesRelay(e.key(), nil) })
}

// addSpare keeps rc as a spare session. It closes rc when the agent has
// enough spares or a session on the same relay.
func (a *Agent) addSpare(rc *relayConn) {
	a.mu.Lock()
	keep := !a.stopped && len(a.spares) < a.sessions()-1 && !a.usesRelay(rc.ep.key(), rc)
	if keep {
		a.spares = append(a.spares, rc)
	}
	a.mu.Unlock()
	if !keep {
		rc.close()
		return
	}
	slog.Info("Opened a spare relay session", "relay", rc.addr, "transport", transportName(rc.mode))
	go a.watchSpare(rc)
}

// watchSpare closes the spare session rc when it ends or its relay drains,
// until the agent takes it.
func (a *Agent) watchSpare(rc *relayConn) {
	var alts []*dp.RelayRef
	drained := false
	select {
	case <-rc.spareDone:
		return
	case <-rc.qc.Context().Done():
	case alts = <-rc.drain:
		drained = true
	}
	a.mu.Lock()
	i := slices.Index(a.spares, rc)
	if i >= 0 {
		a.spares = slices.Delete(a.spares, i, i+1)
	}
	a.mu.Unlock()
	if i < 0 {
		// The agent took rc as the drain came. Its serve loop gets the drain.
		if drained {
			select {
			case rc.drain <- alts:
			default:
			}
		}
		return
	}
	slog.Info("Closed a spare relay session", "relay", rc.addr, "drained", drained)
	rc.close()
	a.wakeSpares()
}

func (a *Agent) wakeSpares() {
	select {
	case a.spareWake <- struct{}{}:
	default:
	}
}

// keepSpares keeps Sessions-1 spare sessions on other relays while the agent
// is attached. It replaces spares with an old cert, one at a time.
func (a *Agent) keepSpares(ctx context.Context) {
	t := time.NewTicker(spareCheck)
	defer t.Stop()
	backoff := minBackoff
	var retryAt time.Time
	next := 0 // The relay to try next.
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.spareWake:
		}
		if time.Now().Before(retryAt) {
			continue
		}
		changed, err := a.fillSpare(ctx, &next)
		switch {
		case errors.Is(err, ErrUpgrade):
			// The attached session stays. The spare dials continue at a low rate, so
			// that the spares come back after a relay rollback.
			slog.Warn("Failed to open a spare relay session: the relay needs a newer agent; upgrade this agent", "error", err)
			retryAt = time.Now().Add(upgradeRetry)
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			slog.Warn("Failed to open a spare relay session", "error", err)
			retryAt = time.Now().Add(rand.N(backoff) + 1)
			backoff = min(2*backoff, maxBackoff)
		case changed:
			backoff = minBackoff
			a.wakeSpares()
		}
	}
}

// fillSpare replaces one spare that has an old cert, or adds one spare. It
// reports whether the spares changed.
func (a *Agent) fillSpare(ctx context.Context, next *int) (bool, error) {
	cred := a.cfg.Identity.Current()
	a.mu.Lock()
	attached := a.rc != nil && !a.rc.ended()
	n := len(a.spares)
	var stale *relayConn
	for _, rc := range a.spares {
		if rc.cred != cred {
			stale = rc
			break
		}
	}
	a.mu.Unlock()
	if !attached {
		return false, nil
	}
	if stale != nil {
		rc, err := a.dialRelay(ctx, stale.ep, spareHello, false)
		if err != nil {
			return false, fmt.Errorf("relay %s: %w", stale.addr, err)
		}
		a.replaceSpare(stale, rc)
		return true, nil
	}
	if n >= a.sessions()-1 {
		return false, nil
	}
	e, ok := a.spareEndpoint(next)
	if !ok {
		return false, nil
	}
	rc, err := a.dialRelay(ctx, e, spareHello, false)
	if err != nil {
		*next++
		return false, fmt.Errorf("relay %s: %w", e.addr, err)
	}
	a.addSpare(rc)
	return true, nil
}

// replaceSpare puts rc in the place of the spare old and closes old. When
// old is no longer a spare, rc becomes a new spare.
func (a *Agent) replaceSpare(old, rc *relayConn) {
	a.mu.Lock()
	i := slices.Index(a.spares, old)
	if i >= 0 && !a.stopped {
		a.spares[i] = rc
		close(old.spareDone)
	}
	a.mu.Unlock()
	if i < 0 {
		a.addSpare(rc)
		return
	}
	slog.Info("Replaced a spare relay session for the new cert", "relay", rc.addr)
	old.close()
	go a.watchSpare(rc)
}

// spareEndpoint returns the first relay address from index *next that no
// session uses, and moves *next to it.
func (a *Agent) spareEndpoint(next *int) (endpoint, bool) {
	eps := a.endpoints()
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range eps {
		k := (*next + i) % len(eps)
		if !a.usesRelay(eps[k].key(), nil) {
			*next = k
			return eps[k], true
		}
	}
	return endpoint{}, false
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
