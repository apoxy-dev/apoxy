// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

const (
	// probeRate is the most path probes per second that one session gets replies to.
	probeRate = 10
	// The relay keeps earlyProbes probes for unknown sessions for earlyProbeAge.
	// The first probe of an agent comes before the relay adds its session.
	earlyProbes   = 16
	earlyProbeAge = time.Second
	// earlyProbeLen is the largest probe that an agent sends.
	earlyProbeLen = vpcv1alpha1.MaxMTU + pspwire.Overhead
)

// prober answers the path probes of one session.
type prober struct {
	keys  p2p.ProbeKeys
	limit *rate.Limiter
}

func newProber(tc tls.ConnectionState) (*prober, error) {
	k, err := p2p.NewProbeKeys(tc)
	if err != nil {
		return nil, err
	}
	return &prober{keys: k, limit: rate.NewLimiter(probeRate, probeRate)}, nil
}

// earlyProbe is a probe that came before its session.
type earlyProbe struct {
	tr   *quic.Transport
	sid  [8]byte
	from netip.AddrPort
	at   time.Time
	n    int // Zero means a free slot.
	buf  [earlyProbeLen]byte
}

// earlyList keeps the newest early probes.
type earlyList struct {
	mu   sync.Mutex
	next int
	list [earlyProbes]earlyProbe
}

// addProber runs with r.mu held.
func (r *Router) addProber(s *Session) {
	if s.probe != nil {
		r.probes[s.probe.keys.SID] = s
	}
}

// removeProber runs with r.mu held.
func (r *Router) removeProber(s *Session) {
	if s.probe != nil && r.probes[s.probe.keys.SID] == s {
		delete(r.probes, s.probe.keys.SID)
	}
}

// answerProbe sends a reply of the same size to a path probe that comes from
// the address of its session. It writes the reply into b. A probe for an
// unknown session waits for that session. It reports a reply or a wait.
func (r *Router) answerProbe(tr *quic.Transport, b []byte, from net.Addr) bool {
	sid, ok := p2p.ProbeSID(b)
	if !ok {
		return false
	}
	src, now := addrPort(from), time.Now()
	s, ok := r.prober(sid, src, now)
	if s == nil {
		return r.keepEarly(tr, sid, src, b, now)
	}
	return ok && s.probe.answer(tr, b, src, from, now)
}

// prober returns the session of sid, and reports whether src is its address.
func (r *Router) prober(sid [8]byte, src netip.AddrPort, now time.Time) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.probes[sid]
	return s, s != nil && (src == s.addr || (src == s.prev && now.Before(s.prevUntil)))
}

// answer sends the reply to the probe in b from src to the address to.
func (p *prober) answer(tr *quic.Transport, b []byte, src netip.AddrPort, to net.Addr, now time.Time) bool {
	if !p.limit.AllowN(now, 1) {
		return false
	}
	pr, err := p2p.OpenProbe(b, &p.keys.Dialer)
	if err != nil || pr.Reply {
		return false
	}
	pr.Reply, pr.Seen = true, src
	_, _ = tr.WriteTo(p2p.AppendProbe(b[:0], pr, len(b), &p.keys.Listener), to)
	return true
}

// keepEarly keeps the probe in b until its session opens. A kept probe that
// gets no reply counts as malformed when a newer one takes its slot.
func (r *Router) keepEarly(tr *quic.Transport, sid [8]byte, src netip.AddrPort, b []byte, now time.Time) bool {
	if len(b) > earlyProbeLen {
		return false
	}
	l := &r.early
	l.mu.Lock()
	defer l.mu.Unlock()
	// The session can open after the first look. answerEarly runs after it opens.
	if s, ok := r.prober(sid, src, now); s != nil {
		return ok && s.probe.answer(tr, b, src, net.UDPAddrFromAddrPort(src), now)
	}
	e := &l.list[l.next]
	l.next = (l.next + 1) % earlyProbes
	if e.n != 0 {
		r.drops[dropMalformed].Add(1)
	}
	e.tr, e.sid, e.from, e.at, e.n = tr, sid, src, now, copy(e.buf[:], b)
	return true
}

// answerEarly answers the early probes of s, after AddSession adds s.
func (r *Router) answerEarly(s *Session) {
	l := &r.early
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for i := range earlyProbes {
		e := &l.list[(l.next+i)%earlyProbes] // Oldest first.
		if e.n == 0 || e.sid != s.probe.keys.SID {
			continue
		}
		n := e.n
		e.n = 0
		if _, ok := r.prober(e.sid, e.from, now); !ok || now.Sub(e.at) > earlyProbeAge ||
			!s.probe.answer(e.tr, e.buf[:n], e.from, net.UDPAddrFromAddrPort(e.from), now) {
			r.drops[dropMalformed].Add(1)
		}
	}
}
