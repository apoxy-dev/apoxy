// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	// replyRate is the most replies to one source each second, after a burst of replyRate.
	replyRate = 10
	// maxChallenges is the most challenges that a pair starts in one challenge window.
	maxChallenges = 8
	// replayWidth is the width of the window of the request counters of the peer.
	replayWidth = 64
	// discPkts is the most probe packets that wait for discovery. A packet goes in before its
	// tag check, so a flood with the SID of the pair drops here.
	discPkts = 64
	// maxReplySources is the most sources that have a reply limit at one time.
	maxReplySources = 64
	// maxProbeSize is the largest outer probe: a PSP packet with an inner packet of the VPC MTU.
	maxProbeSize = psp.MaxMTU + pspwire.Overhead
	// innerHdr is the IPv6 and UDP header of an inner probe.
	innerHdr = header.IPv6MinimumSize + header.UDPMinimumSize
)

// discTimes are the timers of discovery. A zero value takes its default.
type discTimes struct {
	// first is the first wait between two probes of a run; each next wait is two times longer.
	first time.Duration
	// run is the length of a probe run and the time that a TxID stays in the table.
	run time.Duration
	// again is the time between two runs while the pair has a use and no direct path.
	again time.Duration
	// backoff is the first wait before a run after a direct path was lost.
	backoff time.Duration
	// challenge is the least time between two challenges of one source.
	challenge time.Duration
	// window is the time in which a pair starts at most maxChallenges challenges.
	window time.Duration
}

func (t discTimes) withDefaults() discTimes {
	t.first = cmp.Or(t.first, probeInterval)
	t.run = cmp.Or(t.run, 5*time.Second)
	t.again = cmp.Or(t.again, time.Minute)
	t.backoff = cmp.Or(t.backoff, time.Second)
	t.challenge = cmp.Or(t.challenge, 5*time.Second)
	t.window = cmp.Or(t.window, 10*time.Second)
	return t
}

// probeRole is the probe keys of one side of a channel: tx tags the packets that this side
// sends, and rx checks the packets of the other side.
type probeRole struct {
	sid    [8]byte
	tx, rx [32]byte
}

// newProbeRole returns the keys of the QUIC client of a connection, or of its server.
func newProbeRole(k p2p.ProbeKeys, client bool) probeRole {
	if client {
		return probeRole{sid: k.SID, tx: k.Dialer, rx: k.Listener}
	}
	return probeRole{sid: k.SID, tx: k.Listener, rx: k.Dialer}
}

// mtuSource gives the clamp and the device MTU of the binding.
type mtuSource interface {
	ClampMTU() int
	DeviceMTU() int
}

// probeMTU returns the inner size of the largest PSP packet that the agent sends on b: the
// clamp when it is on, else the device MTU.
func probeMTU(b mtuSource) func() int {
	return func() int { return cmp.Or(b.ClampMTU(), b.DeviceMTU()) }
}

// probeSize returns the size of an outer probe for an inner MTU of mtu B.
func probeSize(mtu int) int { return min(mtu+pspwire.Overhead, maxProbeSize) }

// probeable reports whether the agent can send a probe to a: not an overlay address, and not an
// address that a peer cannot use.
func probeable(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && usable(a.Addr()) && !tunnet.ULAPrefix().Contains(a.Addr())
}

// discIO is how discovery sends its probes.
type discIO struct {
	// sock is the agent socket.
	sock interface {
		WriteTo([]byte, net.Addr) (int, error)
	}
	// inner sends payload as an inner UDP packet between the two ends of the channel through
	// the direct peer p to the outer address to (SendVia). It must not block on the relay.
	inner func(p *psp.Peer, payload []byte, to netip.AddrPort) error
	// mtu is the inner size of the largest PSP packet that the agent sends.
	mtu func() int
}

// Messages from the pair to discovery.
type (
	// discRound is a Candidates round of the peer.
	discRound struct {
		round uint32
		addrs []netip.AddrPort
	}
	// discUse tells discovery that the pair had a use.
	discUse struct{}
	// discDirect tells discovery whether the pair has a direct path. A change to false is a loss.
	discDirect struct{ on bool }
	// discTest starts the PSP test of addr: an inner probe through the direct peer.
	discTest struct {
		peer *psp.Peer
		addr netip.AddrPort
	}
	// discPkt is a probe packet of the SID with its outer source. via is the SA identity of an
	// inner probe, else nil.
	discPkt struct {
		pkt  []byte
		from netip.AddrPort
		via  *psp.Peer
	}
)

// Messages from discovery to the pair.
type (
	// discPassed tells that a reply to a full-size outer probe to addr passed the table check.
	discPassed struct {
		d     *discovery
		addr  netip.AddrPort
		round uint32
		rtt   time.Duration
	}
	// discSeen is a new address of the agent socket that the peer saw in an outer reply.
	discSeen struct {
		d    *discovery
		addr netip.AddrPort
	}
	// discReflexive is a new peer-reflexive address: the source of a valid request of the peer
	// that is not a candidate of its round.
	discReflexive struct {
		d    *discovery
		addr netip.AddrPort
	}
	// discProbing tells that the discovery started or stopped to probe: a run of a round or a
	// challenge runs.
	discProbing struct {
		d  *discovery
		on bool
	}
	// discRunEnded tells that the probe run of a round ended; passed tells whether an address
	// passed in it. stopped is true when a new round with no addresses stopped the run.
	discRunEnded struct {
		d       *discovery
		round   uint32
		passed  bool
		stopped bool
	}
	// discTested is the result of a PSP test.
	discTested struct {
		d    *discovery
		peer *psp.Peer
		addr netip.AddrPort
		ok   bool
		rtt  time.Duration
	}
	// discBFD is a BFD packet of the peer with a valid tag, for the check of the pair.
	discBFD struct {
		d   *discovery
		pkt []byte
	}
	// discEnded is the last message of discovery.
	discEnded struct{ d *discovery }
)

// runKind is the purpose of a probe run.
type runKind int

const (
	runRound     runKind = iota // The candidates of a round of the peer.
	runChallenge                // One peer-reflexive address.
	runTest                     // The PSP test of one address.
)

// discRun sends probes to its addresses at once, then after first x 2^n, until its end.
type discRun struct {
	kind  runKind
	round uint32
	addrs []netip.AddrPort
	peer  *psp.Peer // The direct peer of a PSP test.
	done  map[netip.AddrPort]bool
	next  time.Time
	wait  time.Duration
	end   time.Time
}

// pending returns the addresses of r that did not pass yet.
func (r *discRun) pending() []netip.AddrPort {
	return slices.DeleteFunc(slices.Clone(r.addrs), func(a netip.AddrPort) bool { return r.done[a] })
}

// txEntry is one probe that was sent: a reply counts only when it matches it.
type txEntry struct {
	run   *discRun
	to    netip.AddrPort // The outer destination.
	peer  *psp.Peer      // The direct peer of an inner probe, else nil.
	round uint32
	size  int
	sent  time.Time
}

// replayWin is the window of the request counters of the peer: the highest counter accepted, and
// a mask of it and the counters below it (bit n is top - n).
type replayWin struct{ top, mask uint64 }

// accept reports whether the counter c is new and in the window, and marks it.
func (w *replayWin) accept(c uint64) bool {
	switch {
	case c == 0:
		return false
	case c > w.top:
		if d := c - w.top; d >= replayWidth {
			w.mask = 1
		} else {
			w.mask = w.mask<<d | 1
		}
		w.top = c
		return true
	case w.top-c >= replayWidth:
		return false
	}
	bit := uint64(1) << (w.top - c)
	if w.mask&bit != 0 {
		return false
	}
	w.mask |= bit
	return true
}

// discovery finds the direct paths of a pair, as a child process of the pair. It is the one taker
// of the SID of the pair: it answers the probes of the peer and gives the BFD packets to the pair.
type discovery struct {
	mb   *proc.Mailbox // From the pair.
	pkts *proc.Mailbox // Probe packets from the socket read path and from the pair.
	up   *proc.Mailbox // The pair.
	role probeRole
	io   discIO
	t    discTimes

	counter uint64 // The last request counter sent.
	win     replayWin
	txs     map[[12]byte]txEntry

	round     uint32           // The newest round of the peer.
	cands     []netip.AddrPort // The addresses of that round.
	reflexive []netip.AddrPort // The peer-reflexive addresses, the oldest first.
	seen      netip.AddrPort   // The last address that the peer saw.

	main  *discRun // The run of the round, or nil.
	runs  []*discRun
	limit map[netip.AddrPort]*rate.Limiter
	chal  map[netip.AddrPort]time.Time // The last challenge of each source.
	chals []time.Time                  // The challenges of the last window.

	direct   bool
	probing  bool // The last value that the pair got in discProbing.
	lastUse  time.Time
	wait     time.Duration // The next backoff after a loss, or 0.
	againAt  time.Time     // The next run while the pair has no direct path.
	againDue bool          // A run waits for the next use.
}

func newDiscovery(up *proc.Mailbox, role probeRole, io discIO, t discTimes) *discovery {
	return &discovery{
		mb: proc.NewMailbox(0), pkts: proc.NewMailbox(discPkts), up: up, role: role, io: io,
		t: t.withDefaults(), txs: map[[12]byte]txEntry{}, limit: map[netip.AddrPort]*rate.Limiter{},
		chal: map[netip.AddrPort]time.Time{}, lastUse: time.Now(),
	}
}

// take gives an outer probe packet to discovery. It runs on the socket read path and must not
// block.
func (d *discovery) take(pkt []byte, from netip.AddrPort) {
	d.pkts.Send(discPkt{pkt: bytes.Clone(pkt), from: from})
}

// takeInner gives an inner probe packet to discovery: the UDP payload, the SA identity and the
// outer source. It must not block.
func (d *discovery) takeInner(payload []byte, via *psp.Peer, from netip.AddrPort) {
	d.pkts.Send(discPkt{pkt: bytes.Clone(payload), from: from, via: via})
}

// run takes the probes of the SID from probes until the pair ends discovery.
func (d *discovery) run(probes *probeRegistry) {
	reg := probes.add(d.role.sid, d.take)
	defer func() {
		probes.remove(d.role.sid, reg)
		d.mb.Close()
		d.pkts.Close()
		d.up.Send(discEnded{d})
	}()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		d.report()
		if due, ok := d.due(); ok {
			timer.Reset(time.Until(due))
		} else {
			timer.Stop()
		}
		select {
		case <-d.mb.Wake():
			for _, m := range d.mb.Take() {
				if _, ok := m.(endMsg); ok {
					return
				}
				d.handle(m, time.Now())
			}
		case <-d.pkts.Wake():
			for _, m := range d.pkts.Take() {
				d.packet(m.(discPkt), time.Now())
			}
		case now := <-timer.C:
			d.tick(now)
		}
	}
}

// report tells the pair when the discovery starts or stops to probe.
func (d *discovery) report() {
	on := slices.ContainsFunc(d.runs, func(r *discRun) bool { return r.kind != runTest })
	if on != d.probing {
		d.probing = on
		d.up.Send(discProbing{d: d, on: on})
	}
}

func (d *discovery) handle(m any, now time.Time) {
	switch m := m.(type) {
	case discRound:
		d.newRound(m, now)
	case discUse:
		d.lastUse = now
		if d.againDue {
			d.againDue = false
			d.startMain(now)
		}
	case discDirect:
		d.setDirect(m.on, now)
	case discTest:
		d.startTest(m, now)
	}
}

// due returns the time of the next timer event.
func (d *discovery) due() (time.Time, bool) {
	var due time.Time
	at := func(t time.Time) {
		if !t.IsZero() && (due.IsZero() || t.Before(due)) {
			due = t
		}
	}
	for _, r := range d.runs {
		if r.next.Before(r.end) {
			at(r.next)
		}
		at(r.end)
	}
	at(d.againAt)
	for _, e := range d.txs {
		at(e.sent.Add(d.t.run))
	}
	return due, !due.IsZero()
}

// tick sends the probes that are due, ends the runs at their end and removes old state.
func (d *discovery) tick(now time.Time) {
	d.prune(now)
	for _, r := range slices.Clone(d.runs) {
		for !r.next.After(now) && r.next.Before(r.end) {
			d.send(r, now)
			r.next = r.next.Add(r.wait)
			r.wait *= 2
		}
		if !now.Before(r.end) {
			d.endRun(r, now)
		}
	}
	if !d.againAt.IsZero() && !now.Before(d.againAt) {
		d.againAt = time.Time{}
		if now.Sub(d.lastUse) <= d.t.again {
			d.startMain(now)
		} else {
			d.againDue = true
		}
	}
}

// prune removes the TxIDs, the reply limits and the challenges that are older than their time.
func (d *discovery) prune(now time.Time) {
	for id, e := range d.txs {
		if now.Sub(e.sent) >= d.t.run {
			delete(d.txs, id)
		}
	}
	for a, l := range d.limit {
		// A full limiter is the same as a new one.
		if l.TokensAt(now) >= replyRate {
			delete(d.limit, a)
		}
	}
	for a, t := range d.chal {
		if now.Sub(t) >= d.t.challenge {
			delete(d.chal, a)
		}
	}
	d.chals = slices.DeleteFunc(d.chals, func(t time.Time) bool { return now.Sub(t) >= d.t.window })
}

// newRound takes a Candidates round of the peer. An older round is ignored. A pair with a direct
// path keeps the addresses for a later run.
func (d *discovery) newRound(m discRound, now time.Time) {
	if m.round <= d.round {
		return
	}
	d.round = m.round
	d.cands = d.cands[:0:0]
	for _, a := range m.addrs {
		a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
		if probeable(a) && !slices.Contains(d.cands, a) && len(d.cands) < maxRound {
			d.cands = append(d.cands, a)
		}
	}
	d.reflexive = slices.DeleteFunc(d.reflexive, func(a netip.AddrPort) bool { return slices.Contains(d.cands, a) })
	if !d.direct {
		d.startMain(now)
	}
}

// startMain starts the run of the round on the candidates and the peer-reflexive addresses. It
// replaces the run that runs.
func (d *discovery) startMain(now time.Time) {
	d.againAt, d.againDue = time.Time{}, false
	old := d.main
	if old != nil {
		d.removeRun(old)
		d.main = nil
	}
	addrs := append(slices.Clone(d.cands), d.reflexive...)
	if len(addrs) == 0 {
		if old != nil {
			d.up.Send(discRunEnded{d: d, round: old.round, stopped: true})
		}
		return
	}
	d.main = d.startRun(&discRun{kind: runRound, addrs: addrs}, now)
}

// startRun sends the first probes of r and adds it to the runs.
func (d *discovery) startRun(r *discRun, now time.Time) *discRun {
	r.round, r.done = d.round, map[netip.AddrPort]bool{}
	r.next, r.wait, r.end = now, d.t.first, now.Add(d.t.run)
	d.runs = append(d.runs, r)
	d.send(r, now)
	r.next = r.next.Add(r.wait)
	r.wait *= 2
	return r
}

func (d *discovery) removeRun(r *discRun) {
	d.runs = slices.DeleteFunc(d.runs, func(x *discRun) bool { return x == r })
}

// endRun ends r at its end.
func (d *discovery) endRun(r *discRun, now time.Time) {
	d.removeRun(r)
	switch r.kind {
	case runRound:
		if r != d.main {
			return
		}
		d.main = nil
		d.up.Send(discRunEnded{d: d, round: r.round, passed: len(r.done) > 0})
		d.scheduleAgain(now)
	case runTest:
		if len(r.done) == 0 {
			d.up.Send(discTested{d: d, peer: r.peer, addr: r.addrs[0]})
		}
	}
}

// scheduleAgain sets the time of the next run of a pair with no direct path: the backoff after a
// loss, else the again time.
func (d *discovery) scheduleAgain(now time.Time) {
	if d.direct || d.main != nil {
		return
	}
	wait := d.t.again
	if d.wait > 0 {
		wait = d.wait
		d.wait = min(2*d.wait, d.t.again)
	}
	d.againAt = now.Add(wait)
}

func (d *discovery) setDirect(on bool, now time.Time) {
	lost := d.direct && !on
	d.direct = on
	switch {
	case on:
		d.wait, d.againAt, d.againDue = 0, time.Time{}, false
	case lost:
		d.wait = d.t.backoff
		d.scheduleAgain(now)
	}
}

// startTest starts the PSP test of an address, unless one runs for it.
func (d *discovery) startTest(m discTest, now time.Time) {
	if m.peer == nil || !m.addr.IsValid() || slices.ContainsFunc(d.runs, func(r *discRun) bool {
		return r.kind == runTest && r.peer == m.peer && r.addrs[0] == m.addr
	}) {
		return
	}
	d.startRun(&discRun{kind: runTest, addrs: []netip.AddrPort{m.addr}, peer: m.peer}, now)
}

// send sends one probe with a new TxID to each address of r that did not pass yet. Each probe has
// the size of the largest PSP packet that the agent sends at this time.
func (d *discovery) send(r *discRun, now time.Time) {
	mtu := d.io.mtu()
	for _, to := range r.pending() {
		size := probeSize(mtu)
		if r.kind == runTest {
			size = mtu - innerHdr
		}
		var id [12]byte
		for {
			_, _ = rand.Read(id[:])
			if _, ok := d.txs[id]; !ok {
				break
			}
		}
		d.counter++
		pkt := p2p.AppendProbe(nil, p2p.Probe{SID: d.role.sid, TxID: id, Round: r.round, Counter: d.counter}, size, &d.role.tx)
		d.txs[id] = txEntry{run: r, to: to, peer: r.peer, round: r.round, size: len(pkt), sent: now}
		var err error
		if r.kind == runTest {
			err = d.io.inner(r.peer, pkt, to)
		} else {
			_, err = d.io.sock.WriteTo(pkt, net.UDPAddrFromAddrPort(to))
		}
		if err != nil {
			slog.Debug("Failed to send a path probe to a peer", "address", to, "error", err)
		}
	}
}

// packet takes a probe packet of the SID. A packet with no valid tag drops.
func (d *discovery) packet(m discPkt, now time.Time) {
	p, err := p2p.OpenProbe(m.pkt, &d.role.rx)
	switch {
	case err != nil:
	case p.BFD != nil:
		// The check of the pair takes it; the reply logic never echoes it.
		if m.via == nil {
			d.up.Send(discBFD{d: d, pkt: m.pkt})
		}
	case p.Reply:
		d.replyIn(p, m, now)
	default:
		d.requestIn(p, m, now)
	}
}

// requestIn answers a request of the peer. A request outside the counter window or seen before
// gets no reply and starts no challenge.
func (d *discovery) requestIn(p p2p.Probe, m discPkt, now time.Time) {
	if !probeable(m.from) || !d.win.accept(p.Counter) {
		return
	}
	// No timer removes the old limits when no run is due, so remove them before their use.
	d.prune(now)
	if d.allowReply(m.from, now) {
		r := p2p.Probe{Reply: true, SID: d.role.sid, TxID: p.TxID, Round: p.Round, Counter: p.Counter}
		var err error
		if m.via == nil {
			r.Seen = m.from
			_, err = d.io.sock.WriteTo(p2p.AppendProbe(nil, r, len(m.pkt), &d.role.tx), net.UDPAddrFromAddrPort(m.from))
		} else {
			err = d.io.inner(m.via, p2p.AppendProbe(nil, r, len(m.pkt), &d.role.tx), m.from)
		}
		if err != nil {
			slog.Debug("Failed to send a path probe reply to a peer", "address", m.from, "error", err)
		}
	}
	if m.via == nil {
		d.learn(m.from, now)
	}
}

// allowReply reports whether a reply to from can go at now: a burst of replyRate, then replyRate each second.
func (d *discovery) allowReply(from netip.AddrPort, now time.Time) bool {
	l := d.limit[from]
	if l == nil {
		if len(d.limit) >= maxReplySources {
			return false
		}
		l = rate.NewLimiter(replyRate, replyRate)
		d.limit[from] = l
	}
	return l.AllowN(now, 1)
}

// learn takes the source of a valid outer request. A source that is not a candidate of the round
// is a peer-reflexive candidate, and it gets a challenge: a run to that address alone.
func (d *discovery) learn(from netip.AddrPort, now time.Time) {
	if slices.Contains(d.cands, from) {
		return
	}
	if !slices.Contains(d.reflexive, from) {
		if len(d.reflexive) == maxRound {
			d.reflexive = d.reflexive[1:]
		}
		d.reflexive = append(d.reflexive, from)
		d.up.Send(discReflexive{d: d, addr: from})
	}
	_, recent := d.chal[from]
	probing := slices.ContainsFunc(d.runs, func(r *discRun) bool {
		return r.kind != runTest && (r.done[from] || slices.Contains(r.addrs, from))
	})
	if d.direct || recent || probing || len(d.chals) >= maxChallenges {
		return
	}
	d.chal[from] = now
	d.chals = append(d.chals, now)
	d.startRun(&discRun{kind: runChallenge, addrs: []netip.AddrPort{from}}, now)
}

// replyIn takes a reply. It counts only when its TxID is in the table, it came the way that the
// table says, and it has the size and the round of the request.
func (d *discovery) replyIn(p p2p.Probe, m discPkt, now time.Time) {
	e, ok := d.txs[p.TxID]
	if !ok || now.Sub(e.sent) >= d.t.run || len(m.pkt) != e.size || p.Round != e.round || m.via != e.peer {
		return
	}
	if e.peer == nil && m.from != e.to {
		return
	}
	delete(d.txs, p.TxID)
	r, rtt := e.run, now.Sub(e.sent)
	if r.done[e.to] {
		return
	}
	r.done[e.to] = true
	if r.kind == runTest {
		d.removeRun(r)
		d.up.Send(discTested{d: d, peer: e.peer, addr: e.to, ok: true, rtt: rtt})
		return
	}
	if p.Seen.IsValid() && p.Seen != d.seen {
		d.seen = p.Seen
		d.up.Send(discSeen{d: d, addr: p.Seen})
	}
	d.up.Send(discPassed{d: d, addr: e.to, round: e.round, rtt: rtt})
	if r.kind == runChallenge {
		d.removeRun(r)
	}
}
