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
	"sync/atomic"
	"time"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	defaultSessions = 2
	maxSessions     = 3
	// raceDelay is the wait for a session before the agent dials a second relay.
	raceDelay = 150 * time.Millisecond
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

func primaryHello() bool { return false }
func spareHello() bool   { return true }

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

// attachRelay returns an attached session: a spare, or else a new session from
// the relays from index next. It returns the number of relays that failed.
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

// race dials eps[0]. When it has no session after raceDelay, or fails, the
// agent also dials the next relay. The first session wins, and a later one
// becomes a spare. It returns the number of relays that failed.
func (a *Agent) race(ctx context.Context, eps []endpoint) (*relayConn, int, error) {
	type result struct {
		rc  *relayConn
		err error
		ep  endpoint
	}
	results := make(chan result, 2)
	var won atomic.Bool
	dial := func(e endpoint) {
		go func() {
			rc, err := a.dialRelay(ctx, e, won.Load, false)
			results <- result{rc, err, e}
		}()
	}
	second := slices.IndexFunc(eps, func(e endpoint) bool { return e.key() != eps[0].key() })
	dialSecond := func() {
		if second > 0 {
			dial(eps[second])
			second = -1
		}
	}
	dial(eps[0])
	started := 1
	timer := time.NewTimer(raceDelay)
	defer timer.Stop()
	var errs []error
	for done := 0; done < started; {
		select {
		case <-timer.C:
			if second > 0 {
				dialSecond()
				started++
			}
		case r := <-results:
			done++
			if r.err != nil {
				errs = append(errs, fmt.Errorf("relay %s: %w", r.ep.addr, r.err))
				if second > 0 {
					dialSecond()
					started++
				}
				continue
			}
			won.Store(true)
			if done < started {
				go func() {
					if r := <-results; r.err == nil {
						a.addSpare(r.rc)
					}
				}()
			}
			return r.rc, len(errs), nil
		}
	}
	return nil, len(errs), errors.Join(errs...)
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
