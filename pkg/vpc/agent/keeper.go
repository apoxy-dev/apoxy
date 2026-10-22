// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"maps"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

const (
	defaultSessions = 2
	maxSessions     = 3
	// defaultRTTBand is the difference of two round-trip times that counts as equal. It
	// is above the error of one handshake sample and below the time between regions.
	defaultRTTBand = 10 * time.Millisecond
	// defaultRTTWaitMin is the shortest wait for the other relays after the first answer. A
	// relay in the band answers at most two times the band later.
	defaultRTTWaitMin = 20 * time.Millisecond
	// defaultRTTWaitMax is the longest wait. A relay that answers later than two times
	// the band plus 20 ms of noise cannot change the choice.
	defaultRTTWaitMax = 40 * time.Millisecond
	// rttRounds is the number of round trips of the first relay in the wait.
	rttRounds = 2
	// After all relays fail, the agent enrolls again for a new relay list each
	// defaultRelistMin. A failed enroll doubles the wait up to defaultRelistMax.
	defaultRelistMin = time.Minute
	defaultRelistMax = 10 * time.Minute
)

// errNoRelays is the failure of Run when it has no relay to dial.
var errNoRelays = errors.New("no relays")

// keeper is the dial plan of the root: it opens the sessions that the agent
// misses, on the configured relays and on the wanted relays, with a backoff
// for each relay after its failures.
type keeper struct {
	backoff  time.Duration // The wait after no relay was there to dial.
	next     int           // The relay to dial first.
	rank     uint32        // Rank of the next session.
	failed   int           // Relays that failed one after the other.
	refused  *upgradeError // A relay refused the agent as too old since the last session.
	unfilled int           // Sessions that the root did not open because the cert expired.

	round   *dialRound
	wait    *time.Timer // The next plan after no relay was there to dial. Nil when none waits.
	relist  relister
	listing bool // The relist task runs.

	waits   map[string]*relayWait // Backoff of each relay key after failed dials.
	wake    *time.Timer           // The end of the first backoff that a dial waits for.
	dialing map[string]bool       // Wanted relays with a dial task, by relay ID.
}

// relayWait is the backoff of one relay.
type relayWait struct {
	wait  time.Duration // The longest wait after the next failure.
	until time.Time     // No dial before this time.
}

// dialRound dials the relays of eps at the same time and chooses the ones with
// the lowest round-trip times.
type dialRound struct {
	n      int
	eps    []endpoint
	keys   map[string]bool // The relay keys of eps.
	ctx    context.Context
	cancel context.CancelFunc
	got    []*dialed
	errs   []error
	failed []string // The keys of the relays of errs.
	left   int
	choice *time.Timer // Set at the first answer.
}

// dialResult is the result of one dial of a round.
type dialResult struct {
	round *dialRound
	i     int
	d     *dialed
	err   error
}

// relister enrolls again for a new relay list after all relays failed. With
// an identity file, it reads the file again.
type relister struct {
	at   time.Time     // No enroll before this time.
	wait time.Duration // Doubles after a failed enroll.
}

// relisted is the result of the relist task.
type relisted struct {
	got bool
	err error
}

// warnExpired logs one warning for each session that the root cannot open
// because the cert of the identity file expired. n is the number of such sessions.
func (k *keeper) warnExpired(n int, at time.Time) {
	if n > k.unfilled {
		slog.Warn("Cannot open a relay session because the certificate of the identity file expired; the open sessions stay",
			"missing", n, "expired_at", at)
	}
	k.unfilled = n
}

// missing returns the count of sessions to open on the configured relays and
// the configured relays with no session and no dial of the wanted set. A
// draining session does not count, and its alternates are first. A session on
// a wanted relay counts only when its relay is configured.
func (r *root) missing() (int, []endpoint) {
	eps := r.endpoints()
	configured := map[string]bool{}
	for _, e := range eps {
		configured[r.keyOf(e)] = true
	}
	n := cmp.Or(r.a.cfg.Sessions, defaultSessions)
	var alts []endpoint
	busy, live := map[string]bool{}, map[string]bool{}
	for _, h := range r.homes {
		busy[h.id] = true
		if h.draining {
			alts = append(alts, h.alternates...)
			continue
		}
		live[h.id] = true
		if !h.wanted || configured[h.id] {
			n--
		}
	}
	for id := range r.keep.dialing {
		busy[id] = true
	}
	alts = slices.DeleteFunc(alts, func(e endpoint) bool { return live[r.keyOf(e)] })
	eps = slices.DeleteFunc(eps, func(e endpoint) bool { return busy[r.keyOf(e)] })
	free := slices.Concat(alts, eps)
	return max(min(n, len(r.oneEach(free))), 0), free
}

// plan dials the wanted relays and starts the next dial round when the agent
// misses sessions on the configured relays, or ends Run when the cert expired
// and no session is left. A relay waits for the end of its backoff.
func (r *root) plan() {
	k := &r.keep
	if r.ending || k.listing {
		return
	}
	wanted := r.wantedSet()
	r.keepAddrs(wanted)
	none := r.primary() == nil
	if exp := r.fileExpired(); exp != nil {
		if none && !r.renewing {
			r.stop(exp)
			return
		}
		n, _ := r.missing()
		k.warnExpired(n, exp.At)
		return
	}
	now := time.Now()
	var next time.Time
	// The dials of the wanted relays come first, so a configured relay with a
	// wanted dial is not dialed twice.
	r.dialWanted(wanted, now, &next)
	n, eps := r.missing()
	if k.round == nil && n > 0 {
		ready := slices.DeleteFunc(slices.Clone(eps), func(e endpoint) bool { return r.waiting(r.keyOf(e), now, &next) })
		if m := min(n, len(r.oneEach(ready))); m > 0 {
			r.startRound(m, ready)
		}
	}
	if k.round == nil && k.wait == nil && none && len(r.homes) == 0 && len(eps) == 0 && len(k.dialing) == 0 && len(wanted) == 0 {
		// The agent has no session and no relay to dial.
		r.retry(nil, errNoRelays)
	}
	if k.wake != nil {
		k.wake.Stop()
		k.wake = nil
	}
	if !next.IsZero() {
		k.wake = time.NewTimer(time.Until(next))
	}
}

// waiting reports whether the relay key waits for the end of its backoff at
// now, and moves next to that end when it is earlier.
func (r *root) waiting(key string, now time.Time, next *time.Time) bool {
	w := r.keep.waits[key]
	if w == nil || !now.Before(w.until) {
		return false
	}
	if next.IsZero() || w.until.Before(*next) {
		*next = w.until
	}
	return true
}

// failRelay starts the next backoff of the relay key: a random wait up to the
// last one doubled, at most maxBackoff.
func (r *root) failRelay(key string) {
	k := &r.keep
	if k.waits == nil {
		k.waits = map[string]*relayWait{}
	}
	w := k.waits[key]
	if w == nil {
		w = &relayWait{wait: minBackoff}
		k.waits[key] = w
	}
	w.until = time.Now().Add(rand.N(w.wait) + 1)
	w.wait = min(2*w.wait, maxBackoff)
}

// startRound dials eps for n sessions.
func (r *root) startRound(n int, eps []endpoint) {
	k := &r.keep
	i := k.next % len(eps)
	eps = r.oneEach(slices.Concat(eps[i:], eps[:i]))
	ctx, cancel := context.WithCancel(r.ctx)
	rd := &dialRound{n: n, eps: eps, keys: map[string]bool{}, ctx: ctx, cancel: cancel, got: make([]*dialed, len(eps)), left: len(eps)}
	for _, e := range eps {
		rd.keys[r.keyOf(e)] = true
	}
	k.round = rd
	cred := r.a.cfg.Identity.Current()
	for i, e := range eps {
		r.task(func() any {
			d, err := r.a.dial(ctx, e, r.a.relayRoots(cred))
			return dialResult{round: rd, i: i, d: d, err: err}
		})
	}
}

// dialDone takes the result of one dial. A result of a closed round closes
// its connection.
func (r *root) dialDone(m dialResult) {
	rd := r.keep.round
	if m.d != nil {
		r.welcome[m.d.ep.addr] = m.d.relayID
	}
	if rd != m.round {
		if m.d != nil {
			m.d.close("relay was not chosen")
		}
		return
	}
	rd.left--
	if m.err != nil {
		e := rd.eps[m.i]
		rd.errs = append(rd.errs, fmt.Errorf("relay %s: %w", e.addr, m.err))
		rd.failed = append(rd.failed, r.keyOf(e))
	} else {
		rd.got[m.i] = m.d
		if rd.choice == nil {
			rd.choice = time.NewTimer(r.choiceWait(m.d))
		}
	}
	if rd.left == 0 {
		r.closeRound()
	}
}

// closeRound starts a session on each of the n relays with the lowest
// round-trip times, and closes the other connections.
func (r *root) closeRound() {
	k := &r.keep
	rd := k.round
	k.round = nil
	rd.cancel()
	if rd.choice != nil {
		rd.choice.Stop()
	}
	order := r.rankDialed(rd.got)
	if len(order) > 1 {
		slog.Info("Ordered the relays by round-trip time", "first", order[0].ep.addr, "rtt", order[0].choiceRTT(), "relays", len(order))
	}
	started := 0
	for _, d := range order {
		if started == rd.n || r.ending {
			d.close("relay was not chosen")
			continue
		}
		if r.take(d, false) {
			started++
		}
	}
	if started < rd.n && len(rd.errs) > 0 {
		r.retry(rd.failed, errors.Join(rd.errs...))
	}
	// Relays that answered after the choice get the next round at once.
	r.plan()
}

// wantedSet returns the relay IDs that the reported routes name, and the
// relay of the last primary, without the relay of the live primary.
func (r *root) wantedSet() map[string]bool {
	w := map[string]bool{}
	for id := range r.relayRefs {
		w[id] = true
	}
	if r.primaryID != "" {
		w[r.primaryID] = true
	}
	if p := r.primary(); p != nil {
		delete(w, p.id)
	}
	for id := range w {
		if !r.wanted[id] {
			slog.Info("A route names a relay of the agent", "relay", id, "addresses", r.addrsOf(id))
		}
	}
	for id := range r.wanted {
		if !w[id] {
			slog.Info("No route names a relay of the agent; the agent dials it no more", "relay", id)
		}
	}
	r.wanted = w
	return w
}

// keepAddrs forgets the addresses of each relay that is not wanted, that no
// session holds and that no dial uses, and the Welcome of each address that
// is not an address to dial.
func (r *root) keepAddrs(wanted map[string]bool) {
	maps.DeleteFunc(r.relayAddrs, func(id string, _ []string) bool {
		return !wanted[id] && r.holder(id) == nil && !r.keep.dialing[id]
	})
	addrs := map[string]bool{}
	for _, e := range r.endpoints() {
		addrs[e.addr] = true
	}
	for _, h := range r.homes {
		addrs[h.ep.addr] = true
		for _, e := range h.alternates {
			addrs[e.addr] = true
		}
	}
	for id := range wanted {
		for _, a := range r.addrsOf(id) {
			addrs[a] = true
		}
	}
	maps.DeleteFunc(r.welcome, func(addr, _ string) bool { return !addrs[addr] })
}

// addrsOf returns the addresses to dial for the wanted relay id: the newest
// addresses that a route gave, else the address of the last primary.
func (r *root) addrsOf(id string) []string {
	if a := r.relayAddrs[id]; len(a) > 0 {
		return a
	}
	if id == r.primaryID && r.primaryAddr != "" {
		return []string{r.primaryAddr}
	}
	return nil
}

// wantDialed is the result of the dial of a wanted relay.
type wantDialed struct {
	id  string
	d   *dialed
	err error
}

// dialWanted starts a dial task for each wanted relay that no session holds,
// that no dial uses, whose backoff ended and that has an address. The task
// dials the addresses in order.
func (r *root) dialWanted(wanted map[string]bool, now time.Time, next *time.Time) {
	k := &r.keep
	for _, id := range slices.Sorted(maps.Keys(wanted)) {
		addrs := r.addrsOf(id)
		if r.holder(id) != nil || k.dialing[id] || k.round != nil && k.round.keys[id] || len(addrs) == 0 || r.waiting(id, now, next) {
			continue
		}
		if k.dialing == nil {
			k.dialing = map[string]bool{}
		}
		k.dialing[id] = true
		a, ctx, roots := r.a, r.ctx, r.a.relayRoots(r.a.cfg.Identity.Current())
		r.task(func() any {
			var errs []error
			for _, addr := range addrs {
				d, err := a.dial(ctx, endpoint{id: id, addr: addr}, roots)
				if err == nil {
					return wantDialed{id: id, d: d}
				}
				errs = append(errs, fmt.Errorf("relay %s at %s: %w", id, addr, err))
			}
			return wantDialed{id: id, err: errors.Join(errs...)}
		})
	}
}

// wantDone takes the result of the dial of a wanted relay. The session starts
// also when the relay left the wanted set during the dial.
func (r *root) wantDone(m wantDialed) {
	delete(r.keep.dialing, m.id)
	if r.ending {
		if m.d != nil {
			m.d.close("agent stopped")
		}
		return
	}
	switch {
	case m.err != nil:
		slog.Warn("Failed to open relay session", "relay", m.id, "error", m.err)
		if certRefused(m.err) {
			r.renew()
		}
		r.failRelay(m.id)
	default:
		r.welcome[m.d.ep.addr] = m.d.relayID
		if m.d.relayID != m.id {
			// Another relay has the address now. The connection holds the ID of
			// its Welcome, and the wanted relay waits for its backoff.
			slog.Warn("A wanted relay address has another relay", "relay", m.id, "address", m.d.ep.addr, "other_relay", m.d.relayID)
			r.failRelay(m.id)
		}
		r.take(m.d, true)
	}
	r.plan()
}

// choiceTimer returns the channel of the wait for the other relays of the round, or nil.
func (k *keeper) choiceTimer() <-chan time.Time {
	if k.round == nil || k.round.choice == nil {
		return nil
	}
	return k.round.choice.C
}

// waitTimer returns the channel of the backoff wait, or nil.
func (k *keeper) waitTimer() <-chan time.Time {
	if k.wait == nil {
		return nil
	}
	return k.wait.C
}

// retry starts the backoff of each relay key that failed, and gets a new relay
// list when the agent has no session and each relay failed. With no key, it
// waits before the next plan.
func (r *root) retry(keys []string, err error) {
	k := &r.keep
	slog.Warn("Failed to open relay session", "error", err)
	if ue := (*upgradeError)(nil); errors.As(err, &ue) {
		k.refused = ue
	}
	if certRefused(err) {
		r.renew()
	}
	for _, key := range keys {
		r.failRelay(key)
	}
	k.next += len(keys)
	if k.failed += len(keys); r.primary() == nil && k.failed >= len(r.endpoints()) {
		// More dials do not help when a relay needs a newer agent, so Run stops.
		if k.refused != nil {
			r.stop(k.refused)
			return
		}
		k.failed = 0
		if len(r.a.cfg.Relays) == 0 && !time.Now().Before(k.relist.at) && !k.listing {
			r.relist()
			return
		}
	}
	if len(keys) == 0 {
		r.backoff()
	}
}

// backoff arms the wait for the next plan.
func (r *root) backoff() {
	k := &r.keep
	if k.wait != nil {
		k.wait.Stop()
	}
	k.wait = time.NewTimer(rand.N(k.backoff) + 1)
	k.backoff = min(2*k.backoff, maxBackoff)
}

// relist starts the relist task: it enrolls again for a new relay list.
func (r *root) relist() {
	r.keep.listing = true
	id := r.a.cfg.Identity
	r.task(func() any {
		old := id.Current()
		ctx, cancel := context.WithTimeout(r.ctx, openTimeout)
		defer cancel()
		err := id.Renew(ctx)
		// An identity file that did not change gives no error and no new list.
		return relisted{got: err == nil && id.Current() != old, err: err}
	})
}

// relistDone takes the result of the relist task. With a new list the root
// dials at once, else after the backoff.
func (r *root) relistDone(m relisted) {
	k := &r.keep
	k.listing = false
	if k.relist.wait == 0 {
		k.relist.wait = r.a.relistMin
	}
	switch {
	case m.err != nil:
		k.relist.wait = min(2*k.relist.wait, r.a.relistMax)
		slog.Warn("Failed to get a new relay list; keeping the cached list", "error", m.err)
	case m.got:
		k.relist.wait = r.a.relistMin
		slog.Info("Got a new relay list after all relays failed", "relays", len(r.a.cfg.Identity.Current().Relays))
	}
	k.relist.at = time.Now().Add(k.relist.wait + rand.N(k.relist.wait/2+1))
	if m.got {
		k.backoff = minBackoff
		clear(k.waits)
		return
	}
	if len(r.endpoints()) == 0 {
		r.backoff()
	}
}

// fileExpired returns the error of the identity file whose cert expired, or
// nil when the agent has a cert of a newer file.
func (r *root) fileExpired() *identity.ExpiredError {
	e := r.expired
	if e == nil || !e.At.Equal(r.a.cfg.Identity.Current().Cert.NotAfter) {
		return nil
	}
	return e
}

// renew starts the renew task, or runs it once more after the one that runs.
func (r *root) renew() {
	if r.renewing {
		r.renewAgain = true
		return
	}
	r.renewing = true
	id := r.a.cfg.Identity
	r.task(func() any { return renewed{err: id.Renew(r.ctx)} })
}

// renewed is the result of the renew task.
type renewed struct{ err error }

func (r *root) renewDone(m renewed) {
	r.renewing = false
	if m.err != nil {
		slog.Warn("Failed to renew agent cert", "error", m.err)
	}
	if r.renewAgain && !r.ending {
		r.renewAgain = false
		r.renew()
	}
}

// choiceWait returns the wait for the other relays after d answered first.
func (r *root) choiceWait(d *dialed) time.Duration {
	a := r.a
	rtt := d.choiceRTT()
	if rtt <= 0 {
		// A time that is not known uses the longest wait.
		return a.rttWaitMax
	}
	return min(max(rttRounds*rtt, a.rttWaitMin), a.rttWaitMax)
}

// rankDialed returns the connections of got in the order of the choice. Within
// the band of the lowest time, the relay order of the agent decides.
func (r *root) rankDialed(got []*dialed) []*dialed {
	band := r.a.rttBand
	left := slices.DeleteFunc(slices.Clone(got), func(d *dialed) bool { return d == nil })
	// A connection with no time is after each connection with a time.
	rtt := func(d *dialed) time.Duration {
		if t := d.choiceRTT(); t > 0 {
			return t
		}
		return time.Duration(1<<63 - 1 - int64(band))
	}
	var order []*dialed
	for len(left) > 0 {
		low := rtt(slices.MinFunc(left, func(x, y *dialed) int { return cmp.Compare(rtt(x), rtt(y)) }))
		k := slices.IndexFunc(left, func(d *dialed) bool { return rtt(d) <= low+band })
		order = append(order, left[k])
		left = slices.Delete(left, k, k+1)
	}
	return order
}

// endpoint is one address of a relay.
type endpoint struct {
	id   string // TLS name of the relay. Empty means the host in addr.
	addr string
}

// key identifies the relay of e before a Welcome.
func (e endpoint) key() string {
	return cmp.Or(e.id, e.addr)
}

// keyOf identifies the relay of e: the relay ID of the newest Welcome at its
// address, else its configured ID, else its address.
func (r *root) keyOf(e endpoint) string {
	if id := r.welcome[e.addr]; id != "" {
		return id
	}
	return e.key()
}

// endpoints returns the addresses of the relays in the order of this agent.
// The addresses of one relay stay in their order.
func (r *root) endpoints() []endpoint {
	a := r.a
	relays := a.cfg.Relays
	if len(relays) == 0 {
		if c := a.cfg.Identity.Current(); c != nil {
			relays = c.Relays
		}
	}
	var out []endpoint
	for _, rl := range relays {
		for _, addr := range rl.Addresses {
			out = append(out, endpoint{id: rl.ID, addr: addr})
		}
	}
	// Agents do not all dial the first relay.
	slices.SortStableFunc(out, func(x, y endpoint) int {
		return cmp.Compare(maphash.String(a.seed, x.key()), maphash.String(a.seed, y.key()))
	})
	return out
}

// oneEach returns the first address of each relay in eps, so entries with one
// key count as one relay.
func (r *root) oneEach(eps []endpoint) []endpoint {
	var out []endpoint
	seen := map[string]bool{}
	for _, e := range eps {
		if key := r.keyOf(e); !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}
