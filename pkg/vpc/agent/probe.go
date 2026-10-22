// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

const (
	probeRounds   = 3
	probeInterval = 300 * time.Millisecond
	probeWait     = time.Second
)

// probeRegistry gives the path probe packets on the agent socket to the probe
// or check of their SID. A probe or check adds its entry before its first
// packet and removes it at its end; the packet path reads it.
type probeRegistry struct {
	mu sync.Mutex
	m  map[[8]byte]*probeTaker
}

// probeTaker gets the probe packets of one SID.
type probeTaker struct{ f func(pkt []byte) }

// add makes f the taker of sid and returns the entry for remove.
func (r *probeRegistry) add(sid [8]byte, f func([]byte)) *probeTaker {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[[8]byte]*probeTaker{}
	}
	t := &probeTaker{f}
	r.m[sid] = t
	return t
}

// remove removes the entry t of sid, if a newer one did not replace it.
func (r *probeRegistry) remove(sid [8]byte, t *probeTaker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m[sid] == t {
		delete(r.m, sid)
	}
}

// take gives a path probe packet to the taker of its SID. It must not block.
func (r *probeRegistry) take(pkt []byte, _ net.Addr) {
	sid, ok := p2p.ProbeSID(pkt)
	if !ok {
		return
	}
	r.mu.Lock()
	t := r.m[sid]
	r.mu.Unlock()
	if t != nil {
		t.f(pkt)
	}
}

// probeResult is the result of a probe task.
type probeResult struct {
	ok      bool
	seen    netip.AddrPort // The address of the agent socket that the relay saw.
	counter uint64         // The counter of the last probe packet.
}

// probe tests whether the path to the PSP socket of the relay at to carries
// PSP packets with inner packets of mtu B: true at the first reply, false
// after probeWait or when ctx or qc ends. counter is the last probe counter.
func (a *Agent) probe(ctx context.Context, qc quic.Connection, to netip.AddrPort, mtu int, counter uint64) probeResult {
	res := probeResult{counter: counter}
	keys, err := p2p.NewProbeKeys(qc.ConnectionState().TLS)
	if err != nil {
		slog.Warn("Failed to get the path probe keys", "relay", to, "error", err)
		return res
	}
	size := mtu + pspwire.Overhead
	var txid [12]byte
	_, _ = rand.Read(txid[:])
	got := make(chan netip.AddrPort, 1)
	t := a.probes.add(keys.SID, func(pkt []byte) {
		if len(pkt) != size {
			return
		}
		r, err := p2p.OpenProbe(pkt, &keys.Listener)
		if err != nil || !r.Reply || r.TxID != txid {
			return
		}
		select {
		case got <- r.Seen:
		default:
		}
	})
	defer a.probes.remove(keys.SID, t)
	ua := net.UDPAddrFromAddrPort(to)
	buf := make([]byte, 0, size)
	wait := time.NewTimer(probeWait)
	defer wait.Stop()
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for round := uint32(0); ; {
		if round < probeRounds {
			res.counter++
			buf = p2p.AppendProbe(buf[:0], p2p.Probe{SID: keys.SID, TxID: txid, Round: round, Counter: res.counter}, size, &keys.Dialer)
			if _, err := a.cfg.Transport.WriteTo(buf, ua); err != nil {
				slog.Debug("Failed to send a path probe", "relay", to, "error", err)
			}
			round++
		}
		select {
		case res.seen = <-got:
			res.ok = true
			return res
		case <-wait.C:
			return res
		case <-ctx.Done():
			return res
		case <-qc.Context().Done():
			// A relay that closed the session sends no reply.
			return res
		case <-tick.C:
		}
	}
}
