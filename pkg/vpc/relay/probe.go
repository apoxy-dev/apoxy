// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/tls"
	"net"
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

// answerProbe sends a reply of the same size to a path probe that comes from
// the address of its session. It writes the reply into b and reports a reply.
func (r *Router) answerProbe(tr *quic.Transport, b []byte, from net.Addr) bool {
	sid, ok := p2p.ProbeSID(b)
	if !ok {
		return false
	}
	src, now := addrPort(from), time.Now()
	r.mu.RLock()
	s := r.probes[sid]
	ok = s != nil && (src == s.addr || (src == s.prev && now.Before(s.prevUntil)))
	r.mu.RUnlock()
	if !ok || !s.probe.limit.AllowN(now, 1) {
		return false
	}
	p, err := p2p.OpenProbe(b, &s.probe.keys.Dialer)
	if err != nil || p.Reply {
		return false
	}
	p.Reply, p.Seen = true, src
	_, _ = tr.WriteTo(p2p.AppendProbe(b[:0], p, len(b), &s.probe.keys.Listener), from)
	return true
}
