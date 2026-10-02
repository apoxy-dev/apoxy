// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net"
	"sync"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	probeRounds   = 3
	probeInterval = 300 * time.Millisecond
	probeWait     = time.Second
)

// pathProbe is one probe run on the path to the relay.
type pathProbe struct {
	keys p2p.ProbeKeys
	txid [12]byte
	size int
	ok   chan struct{} // Closed at the first good reply.
	once sync.Once
}

// probeMTU returns the inner MTU that the path probe of a new session tests,
// or 0 for no probe.
func (a *Agent) probeMTU(vpcMTU int) int {
	if a.cfg.MTU != 0 {
		return 0
	}
	a.mu.Lock()
	if a.bind != nil {
		vpcMTU = a.bind.DeviceMTU()
	}
	a.mu.Unlock()
	if vpcMTU <= psp.DefaultMTU {
		return 0
	}
	return vpcMTU
}

// probe tests whether the path to the relay carries PSP packets with inner
// packets of mtu B. The channel gets true at the first reply, or false after 1 s.
func (rc *relayConn) probe(ctx context.Context, mtu int) <-chan bool {
	out := make(chan bool, 1)
	keys, err := p2p.NewProbeKeys(rc.qc.ConnectionState().TLS)
	if err != nil {
		slog.Warn("Failed to get the path probe keys", "relay", rc.addr, "error", err)
		out <- false
		return out
	}
	p := &pathProbe{keys: keys, size: mtu + pspwire.Overhead, ok: make(chan struct{})}
	_, _ = rand.Read(p.txid[:])
	a := rc.a
	a.probeMu.Lock()
	a.probes[keys.SID] = p
	a.probeMu.Unlock()
	go func() {
		defer func() {
			a.probeMu.Lock()
			if a.probes[keys.SID] == p {
				delete(a.probes, keys.SID)
			}
			a.probeMu.Unlock()
		}()
		to := net.UDPAddrFromAddrPort(rc.relayAddr)
		buf := make([]byte, 0, p.size)
		wait := time.NewTimer(probeWait)
		defer wait.Stop()
		tick := time.NewTicker(probeInterval)
		defer tick.Stop()
		for round := uint32(0); ; {
			if round < probeRounds {
				buf = p2p.AppendProbe(buf[:0], p2p.Probe{SID: keys.SID, TxID: p.txid, Round: round}, p.size, &keys.Dialer)
				if _, err := a.cfg.Transport.WriteTo(buf, to); err != nil {
					slog.Debug("Failed to send a path probe", "relay", rc.addr, "error", err)
				}
				round++
			}
			select {
			case <-p.ok:
				out <- true
				return
			case <-wait.C:
				out <- false
				return
			case <-ctx.Done():
				out <- false
				return
			case <-tick.C:
			}
		}
	}()
	return out
}

// onProbe gets the path probes on the agent socket.
func (a *Agent) onProbe(pkt []byte, _ net.Addr) {
	sid, ok := p2p.ProbeSID(pkt)
	if !ok {
		return
	}
	a.probeMu.Lock()
	p := a.probes[sid]
	a.probeMu.Unlock()
	if p != nil {
		p.reply(pkt)
	}
}

// reply accepts a reply from the relay of the same size as the probe.
func (p *pathProbe) reply(pkt []byte) {
	if len(pkt) != p.size {
		return
	}
	if sid, ok := p2p.ProbeSID(pkt); !ok || sid != p.keys.SID {
		return
	}
	r, err := p2p.OpenProbe(pkt, &p.keys.Listener)
	if err != nil || !r.Reply || r.TxID != p.txid {
		return
	}
	p.once.Do(func() { close(p.ok) })
}

// setClamp sets the MSS clamp of the binding from the result of a later path
// probe. a.mu is held.
func (a *Agent) setClamp(pathMTU int) {
	dev, clamp := a.bind.DeviceMTU(), 0
	if pathMTU < dev {
		clamp = pathMTU
	}
	if a.bind.SetClampMTU(clamp) == clamp {
		return
	}
	if clamp == 0 {
		slog.Info("Path to the relay carries the device MTU; removed the TCP MSS clamp", "device_mtu", dev)
	} else {
		slog.Info("Path to the relay does not carry the device MTU; clamped the TCP MSS", "mtu", clamp, "device_mtu", dev)
	}
}
