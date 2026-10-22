// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/apoxy-dev/softpsp/keys"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// pspAttempt is one attempt of a session to change from QUIC mode to PSP mode.
// It starts after the connectivity probes passed. Its number is the generation
// of its Rekey calls; the relay copies it into its Offer.
type pspAttempt struct {
	n       uint64
	timer   *time.Timer // keysTimeout over the whole attempt.
	mtu     int         // The path MTU for the clamp.
	rekeys  int         // Rekey calls.
	keysOK  bool        // The relay took the receive SAs.
	offerOK bool        // The Offer of the relay applied.
	lanes   bool        // The lanes step started.
	lanesOK bool
	clamp   bool // The root got clampMsg.
}

// probeDone is the result of a probe task. mtu is set for the device-MTU
// probe of an attempt.
type probeDone struct {
	id      uint64
	attempt uint64
	mtu     bool
	res     probeResult
}

// rekeyDone is the result of a Rekey call. Attempt 0 is a renewal.
type rekeyDone struct {
	attempt uint64
	spis    []uint32
	err     error
}

// lanesDone is the result of the lanes task.
type lanesDone struct {
	attempt uint64
	lanes   int
	receive bool
}

// attTimer returns the channel of the timer of the attempt, or nil.
func (s *session) attTimer() <-chan time.Time {
	if s.att == nil {
		return nil
	}
	return s.att.timer.C
}

// changeMTU returns the inner packet size of the probes before the change to
// PSP mode: the largest packet of QUIC mode, so that each open connection still fits.
func (s *session) changeMTU() int {
	dev := s.a.deviceMTU(int(s.d.config.GetMtu()))
	if s.b != nil {
		dev = s.b.DeviceMTU()
	}
	return min(dev, psp.QUICMTU)
}

// startProbe starts a connectivity probe of the PSP path.
func (s *session) startProbe() {
	s.probeID++
	s.probing = true
	s.runProbe(probeDone{id: s.probeID}, s.changeMTU())
}

// runProbe starts a probe task of mtu bytes that answers m.
func (s *session) runProbe(m probeDone, mtu int) {
	a, ctx, qc, to, counter := s.a, s.ctx, s.d.qc, s.d.relayAddr, s.counter
	s.task(func() any {
		m.res = a.probe(ctx, qc, to, mtu, counter)
		return m
	})
}

// probeAgain starts the next connectivity probe after the retry wait.
func (s *session) probeAgain() {
	if s.mode != dp.Mode_MODE_QUIC || s.att != nil || s.probing {
		return
	}
	s.startProbe()
}

func (s *session) probeDone(m probeDone) {
	s.counter = max(s.counter, m.res.counter)
	if m.res.ok {
		s.seen = m.res.seen
	}
	if m.id != s.probeID {
		return
	}
	if m.mtu {
		if s.att == nil || s.att.n != m.attempt {
			return
		}
		// A path that does not carry the device MTU gets the MSS clamp.
		s.att.mtu = s.b.DeviceMTU()
		if !m.res.ok {
			s.att.mtu = s.changeMTU()
		}
		s.offer()
		return
	}
	s.probing = false
	if !s.attached {
		// The attach makes the relay peer that the attempt needs.
		s.pending = &m.res
		return
	}
	s.probed(m.res)
}

// takePending takes the probe result that came before the attach.
func (s *session) takePending() {
	if r := s.pending; r != nil {
		s.pending = nil
		s.probed(*r)
	}
}

// probed takes the result of a connectivity probe. After pspPasses probes in
// sequence passed, an attempt starts.
func (s *session) probed(r probeResult) {
	switch {
	case !r.ok:
		s.reason = dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT
		s.backoff()
		s.status()
	case s.passes+1 < pspPasses:
		s.passes++
		s.arm(s.a.retryNext)
	case s.draining:
		// A draining session starts no attempt.
	default:
		s.beginAttempt()
	}
}

// beginAttempt starts an attempt: the device-MTU probe when the device MTU is
// above the default, then the receive SAs.
func (s *session) beginAttempt() {
	s.attempt++
	s.att = &pspAttempt{n: s.attempt, timer: time.NewTimer(keysTimeout)}
	if dev := s.b.DeviceMTU(); dev > psp.DefaultMTU {
		s.probeID++
		s.runProbe(probeDone{id: s.probeID, attempt: s.attempt, mtu: true}, dev)
		return
	}
	s.att.mtu = s.b.DeviceMTU()
	s.offer()
}

// offer asks the root for the receive SAs of the attempt.
func (s *session) offer() {
	s.up.send(offerMsg{s: s, peer: s.peer, attempt: s.att.n})
}

// rekeyMsg takes receive SAs from the root: for the attempt, or a renewal.
func (s *session) rekeyMsg(m rekeyMsg) {
	if m.peer != s.peer {
		return
	}
	if m.attempt == 0 {
		if m.err != nil {
			slog.Warn("Failed to create receive SAs for the relay", "relay", s.addr(), "error", m.err)
			return
		}
		// A Rekey call changes a session in QUIC mode, so only an attempt makes it there.
		if s.mode == dp.Mode_MODE_PSP {
			s.rekey(0, m.req)
		}
		return
	}
	if s.att == nil || m.attempt != s.att.n {
		return
	}
	switch {
	case m.err != nil:
		s.failAttempt(fmt.Errorf("create receive SAs: %w", m.err))
	case s.draining && s.att.rekeys == 0:
		s.failAttempt(nil)
	default:
		s.rekey(m.attempt, m.req)
	}
}

// rekey starts a Rekey call with req. Its generation is the attempt, or the
// generation in use for a renewal.
func (s *session) rekey(attempt uint64, req keys.Request) {
	pm := keyproto.ToProto(req)
	pm.Generation = cmp.Or(attempt, s.attempt)
	if s.att != nil && attempt == s.att.n {
		s.att.rekeys++
	}
	c, ctx := s.d.client, s.ctx
	s.task(func() any {
		ctx, cancel := context.WithTimeout(ctx, keysTimeout)
		defer cancel()
		res, err := c.Rekey(ctx, pm)
		return rekeyDone{attempt, res.GetRefusedSpis(), err}
	})
}

func (s *session) rekeyDone(m rekeyDone) {
	if m.attempt == 0 {
		s.renewDone(m)
		return
	}
	if s.att == nil || m.attempt != s.att.n {
		return
	}
	switch {
	case m.err != nil:
		s.failAttempt(fmt.Errorf("give receive SAs to the relay: %w", m.err))
	case len(m.spis) > 0 && s.att.rekeys >= maxRefusals:
		s.failAttempt(errors.New("relay refused the SAs too many times"))
	case len(m.spis) > 0:
		s.up.send(refusedMsg{s: s, peer: s.peer, attempt: m.attempt, spis: m.spis})
	default:
		s.att.keysOK = true
		s.advance()
	}
}

// renewDone is the result of the Rekey call of a renewal. New SAs replace
// refused ones up to maxRefusals times.
func (s *session) renewDone(m rekeyDone) {
	switch {
	case m.err != nil:
		s.renewRefusals = 0
		slog.Warn("Failed to give receive SAs to the relay", "relay", s.addr(), "error", m.err)
	case len(m.spis) == 0:
		s.renewRefusals = 0
	case s.renewRefusals+1 >= maxRefusals:
		s.renewRefusals = 0
		slog.Warn("Failed to give receive SAs to the relay", "relay", s.addr(), "error", "relay refused the SAs too many times")
	default:
		s.renewRefusals++
		s.up.send(refusedMsg{s: s, peer: s.peer, spis: m.spis})
	}
}

// advance asks for the clamp when the attempt has its keys, the Offer of the
// relay and its lanes.
func (s *session) advance() {
	at := s.att
	if !at.keysOK || !at.offerOK {
		return
	}
	if !at.lanes {
		at.lanes = true
		if !s.registerLanes() {
			at.lanesOK = true
		}
	}
	if !at.lanesOK || at.clamp {
		return
	}
	at.clamp = true
	s.up.send(clampMsg{s: s, peer: s.peer, attempt: at.n, mtu: at.mtu})
}

// registerLanes starts the task that registers the lane ports of the binding
// at the relay. It reports false when the relay takes none or sees another
// port than the local one.
func (s *session) registerLanes() bool {
	n := min(int(s.d.maxLanes)+1, cmp.Or(s.a.cfg.Lanes, psp.TxLanes(s.d.relayAddr.Addr().Unmap())))
	if n < 2 || !s.seen.IsValid() || s.seen.Port() != s.a.localPort() {
		return false
	}
	b, c, ctx, addr, attempt := s.b, s.d.client, s.ctx, s.addr(), s.att.n
	s.task(func() any {
		res := lanesDone{attempt: attempt}
		ports := b.OpenLanes(n)
		if len(ports) == 0 {
			return res
		}
		req := &dp.RegisterLanesRequest{Ports: make([]uint32, len(ports)), Receive: true}
		for i, p := range ports {
			req.Ports[i] = uint32(p)
		}
		if err := b.ReadLanes(); err != nil {
			slog.Warn("Failed to read the lane sockets; the relay sends on one port", "relay", addr, "error", err)
			req.Receive = false
		}
		ctx, cancel := context.WithTimeout(ctx, keysTimeout)
		defer cancel()
		if _, err := c.RegisterLanes(ctx, req); err != nil {
			slog.Info("Relay refused the lane ports; the agent sends on one port", "relay", addr, "error", err)
			return res
		}
		slog.Debug("Relay took the lane ports", "relay", addr, "ports", ports, "receive", req.Receive)
		res.lanes, res.receive = len(ports)+1, req.Receive
		return res
	})
	return true
}

func (s *session) lanesDone(m lanesDone) {
	if s.att == nil || m.attempt != s.att.n {
		return
	}
	if m.lanes > 0 {
		s.lanes = m.lanes
		if m.receive && s.laneTk == nil {
			b, to := s.b, s.d.relayAddr
			s.write(func() { b.KeepLanes(to) })
			s.laneTk = time.NewTicker(relayQUIC.KeepAlivePeriod)
		}
	}
	s.att.lanesOK = true
	s.advance()
}

// stopLanes stops the lane keep-alives after the relay dropped the lane ports.
func (s *session) stopLanes() {
	if s.laneTk != nil {
		s.laneTk.Stop()
		s.laneTk = nil
	}
	if s.lanes < 2 {
		return
	}
	s.lanes = 1
	if !s.ending {
		slog.Info("Relay sees a new address of the agent; the lane ports stop", "relay", s.addr())
	}
}

// clamped commits the attempt after the root set the clamp: the check starts,
// and the relay peer sends PSP.
func (s *session) clamped(m clampedMsg) {
	if m.peer != s.peer {
		return
	}
	if s.att == nil || m.attempt != s.att.n {
		return
	}
	keys, err := p2p.NewProbeKeys(s.d.qc.ConnectionState().TLS)
	if err != nil {
		s.failAttempt(err)
		return
	}
	// The relay has the SAs of this agent and sends PSP. Now this agent sends PSP too.
	if err := s.peer.UseQUIC(nil); err != nil {
		s.failAttempt(err)
		return
	}
	c := newCheck(s.mb, keys, s.b, s.seen, s.counter)
	s.checks[c], s.chk = true, c
	go c.run(&s.a.probes)
	s.att.timer.Stop()
	s.att = nil
	s.mode = dp.Mode_MODE_PSP
	s.stopExtras()
	s.up.send(peerMode{s: s, peer: s.peer, mode: dp.Mode_MODE_PSP})
	s.status()
	slog.Info("Changed the relay session from QUIC mode to PSP mode", "relay", s.addr(), "address", s.self)
}

// failAttempt ends the attempt that runs: data stays on QUIC. A draining
// session starts no new attempt.
func (s *session) failAttempt(err error) {
	at := s.att
	if at == nil {
		return
	}
	at.timer.Stop()
	s.att = nil
	if err != nil {
		slog.Warn("Failed to change the relay session to PSP mode; data stays on QUIC", "relay", s.addr(), "error", err)
	}
	s.up.send(peerMode{s: s, peer: s.peer, mode: dp.Mode_MODE_QUIC})
	s.status()
	if !s.draining {
		s.backoff()
	}
}

// useQUIC changes the session back to QUIC mode after its PSP path check
// failed. The session and its addresses stay. The relay changes from its own
// end of the check.
func (s *session) useQUIC() {
	if err := s.peer.UseQUIC(s.pc); err != nil {
		// A session with no place for its data frames carries no data.
		slog.Warn("Failed to change the relay session to QUIC mode; closing it", "relay", s.addr(), "error", err)
		s.end(errNoDataPath)
		return
	}
	s.mode = dp.Mode_MODE_QUIC
	s.reason = dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT
	s.stopLanes()
	s.startExtras()
	s.up.send(peerMode{s: s, peer: s.peer, mode: dp.Mode_MODE_QUIC})
	s.status()
	s.wait = s.a.retryMin
	s.backoff()
	slog.Warn("PSP path to the relay stopped; changed the relay session from PSP mode to QUIC mode", "relay", s.addr(), "address", s.self)
}

// backoff arms the next probe after a probe or an attempt that failed.
func (s *session) backoff() {
	s.passes = 0
	s.arm(s.wait)
	s.wait = min(2*s.wait, s.a.retryMax)
}

// arm starts the retry timer.
func (s *session) arm(d time.Duration) {
	if s.retry != nil {
		s.retry.Stop()
	}
	s.retry = time.NewTimer(d)
}
