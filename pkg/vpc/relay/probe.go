// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

// probeRate is the most path probes per second that one session gets replies to.
const probeRate = 10

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

// answerProbe sends a reply of the same size to a path probe on the PSP
// socket, when the probe comes from the IP address of the QUIC connection of
// its session. It writes the reply into b. It reports a reply.
func (r *Router) answerProbe(tr *quic.Transport, b []byte, from net.Addr) bool {
	sid, ok := p2p.ProbeSID(b)
	if !ok {
		return false
	}
	r.mu.RLock()
	s := r.probes[sid]
	r.mu.RUnlock()
	src, now := addrPort(from), time.Now()
	if s == nil || s.remote().Addr() != src.Addr() {
		return false
	}
	pr, ok := s.probe.open(b, now)
	if !ok {
		return false
	}
	// The agent can call Rekey when it has the reply, so the address comes first.
	r.learnAddr(s, src, pr.Counter, now)
	pr.Reply, pr.Seen = true, src
	_, _ = tr.WriteTo(p2p.AppendProbe(b[:0], pr, len(b), &s.probe.keys.Listener), from)
	return true
}

// open returns the probe of the agent in b, within the probe rate.
func (p *prober) open(b []byte, now time.Time) (p2p.Probe, bool) {
	if !p.limit.AllowN(now, 1) {
		return p2p.Probe{}, false
	}
	pr, err := p2p.OpenProbe(b, &p.keys.Dialer)
	return pr, err == nil && !pr.Reply
}

// learnAddr makes src the PSP address of s when the probe has a larger counter
// than each probe before it. A replay of an old probe thus does not move it.
func (r *Router) learnAddr(s *Session, src netip.AddrPort, counter uint64, now time.Time) {
	if !newestProbe(&s.probeCounter, counter) {
		return
	}
	// Most probes come from the address that the session has: no write lock.
	r.mu.RLock()
	same := src == s.addr
	r.mu.RUnlock()
	if same {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// A newer probe can pass between the two locks. Only the newest one moves the address.
	if s.closed || s.shardOf != nil || counter < s.probeCounter.Load() {
		return
	}
	r.setAddr(s, src, now)
}

// newestProbe raises c to counter. It is false when c is already that large.
func newestProbe(c *atomic.Uint64, counter uint64) bool {
	for {
		old := c.Load()
		if counter <= old {
			return false
		}
		if c.CompareAndSwap(old, counter) {
			return true
		}
	}
}
