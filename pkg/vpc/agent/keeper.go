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

// keeper is the dial plan of the root: it opens the home sessions that the
// agent misses, with backoff after failures.
type keeper struct {
	backoff  time.Duration
	next     int           // The relay to dial first.
	rank     uint32        // Rank of the next session.
	failed   int           // Relays that failed one after the other.
	refused  *upgradeError // A relay refused the agent as too old since the last session.
	since    time.Time     // Start of the last session.
	unfilled int           // Sessions that the root did not open because the cert expired.

	round   *dialRound
	wait    *time.Timer // The next round after a failure. Nil when none waits.
	relist  relister
	listing bool // The relist task runs.
}

// dialRound dials the relays of eps at the same time and chooses the ones with
// the lowest round-trip times.
type dialRound struct {
	n      int
	eps    []endpoint
	ctx    context.Context
	cancel context.CancelFunc
	got    []*dialed
	errs   []error
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

// missing returns the count of home sessions to open and the relays with no
// session. A draining session does not count, and its alternates are first.
func (r *root) missing() (int, []endpoint) {
	eps := r.endpoints()
	n := cmp.Or(r.a.cfg.Sessions, defaultSessions)
	var alts []endpoint
	busy, live := map[string]bool{}, map[string]bool{}
	for _, h := range r.homes {
		busy[h.ep.key()] = true
		if h.draining {
			alts = append(alts, h.alternates...)
			continue
		}
		live[h.ep.key()] = true
		n--
	}
	alts = slices.DeleteFunc(alts, func(e endpoint) bool { return live[e.key()] })
	eps = slices.DeleteFunc(eps, func(e endpoint) bool { return busy[e.key()] })
	free := slices.Concat(alts, eps)
	return max(min(n, len(oneEach(free))), 0), free
}

// plan starts the next dial round when the agent misses sessions, or ends Run
// when the cert expired and no session is left.
func (r *root) plan() {
	k := &r.keep
	if r.ending || k.round != nil || k.wait != nil || k.listing {
		return
	}
	n, eps := r.missing()
	none := r.primary() == nil
	switch exp := r.fileExpired(); {
	case exp != nil && none && !r.renewing:
		r.stop(exp)
	case exp != nil:
		k.warnExpired(n, exp.At)
	case n > 0:
		r.startRound(n, eps)
	case none && len(r.homes) == 0:
		// The agent has no session and no relay to dial.
		r.retry(0, errNoRelays)
	}
}

// startRound dials eps for n sessions.
func (r *root) startRound(n int, eps []endpoint) {
	k := &r.keep
	if !k.since.IsZero() && time.Since(k.since) > stableSession {
		k.backoff = minBackoff
	}
	i := k.next % len(eps)
	eps = oneEach(slices.Concat(eps[i:], eps[:i]))
	ctx, cancel := context.WithCancel(r.ctx)
	rd := &dialRound{n: n, eps: eps, ctx: ctx, cancel: cancel, got: make([]*dialed, len(eps)), left: len(eps)}
	k.round = rd
	cred := r.a.cfg.Identity.Current()
	for i, e := range eps {
		r.task(func() any {
			d, err := r.a.dial(ctx, e, r.a.relayRoots(cred), false)
			return dialResult{round: rd, i: i, d: d, err: err}
		})
	}
}

// dialDone takes the result of one dial. A result of a closed round closes
// its connection.
func (r *root) dialDone(m dialResult) {
	rd := r.keep.round
	if rd != m.round {
		if m.d != nil {
			m.d.close("relay was not chosen")
		}
		return
	}
	rd.left--
	if m.err != nil {
		rd.errs = append(rd.errs, fmt.Errorf("relay %s: %w", rd.eps[m.i].addr, m.err))
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

// closeRound starts a home session on each of the n relays with the lowest
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
		r.startHome(d, k.rank)
		k.rank++
		started++
	}
	if started < rd.n && len(rd.errs) > 0 {
		r.retry(len(rd.errs), errors.Join(rd.errs...))
	}
	// Relays that answered after the choice get the next round at once.
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

// retry waits with backoff after tried relays failed, and gets a new relay
// list when the agent has no session and each relay failed.
func (r *root) retry(tried int, err error) {
	k := &r.keep
	slog.Warn("Failed to open relay session", "error", err)
	if ue := (*upgradeError)(nil); errors.As(err, &ue) {
		k.refused = ue
	}
	if certRefused(err) {
		r.renew()
	}
	k.next += tried
	if k.failed += tried; r.primary() == nil && k.failed >= len(r.endpoints()) {
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
	r.backoff()
}

// backoff arms the wait for the next round.
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
		return
	}
	r.backoff()
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

// key identifies the relay of e.
func (e endpoint) key() string {
	return cmp.Or(e.id, e.addr)
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
