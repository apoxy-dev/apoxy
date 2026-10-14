// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// checkTx is the period of the BFD packets of a session in PSP mode. The relay
// has the same period, so the two ends have the same detect time.
const checkTx = bfdl.DefaultTxInterval

// pathCheck is the BFD session of a relay session in PSP mode. Its packets go
// to the PSP socket of the relay in path probes, so they use the PSP path.
type pathCheck struct {
	rc   *relayConn
	keys p2p.ProbeKeys
	bfd  *p2p.Check
	stop context.CancelFunc
	lost chan struct{} // Closed when the PSP path is lost.
	once sync.Once
}

// startCheck starts the PSP path check of rc. It takes the place of the path
// probes of rc on the agent socket: a session in PSP mode sends no other probe.
func (rc *relayConn) startCheck() error {
	keys, err := p2p.NewProbeKeys(rc.qc.ConnectionState().TLS)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(rc.ctx)
	c := &pathCheck{rc: rc, keys: keys, bfd: p2p.NewCheck(p2p.RoleAgent, checkTx), stop: cancel, lost: make(chan struct{})}
	rc.check.Store(c)
	a := rc.a
	a.probeMu.Lock()
	a.probes[keys.SID] = c
	a.probeMu.Unlock()
	go c.run(ctx)
	return nil
}

// pspLost returns the channel that closes when the PSP path of rc is lost. It
// is nil for a session in QUIC mode.
func (rc *relayConn) pspLost() <-chan struct{} {
	if c := rc.check.Load(); c != nil {
		return c.lost
	}
	return nil
}

// run sends a BFD packet at each period until the path is lost. The packets
// also keep the NAT mapping, and give the relay a new source address.
func (c *pathCheck) run(ctx context.Context) {
	rc := c.rc
	defer c.end()
	tx := time.NewTicker(checkTx)
	defer tx.Stop()
	detect := time.NewTicker(checkTx / 2)
	defer detect.Stop()
	seen := rc.seen.Load()
	c.send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.qc.Context().Done():
			return
		case <-c.lost:
			return
		case now := <-detect.C:
			if c.bfd.Lost(now) {
				// This packet tells the relay of the Down state.
				c.send()
				c.setLost()
				return
			}
		case <-tx.C:
			c.send()
			// The relay drops the lane ports at an address change.
			if now := rc.seen.Load(); *now != *seen {
				seen = now
				rc.a.stopLanes(rc)
			}
		}
	}
}

// end removes c from the agent socket and from the metrics.
func (c *pathCheck) end() {
	a := c.rc.a
	a.probeMu.Lock()
	if a.probes[c.keys.SID] == c {
		delete(a.probes, c.keys.SID)
	}
	a.probeMu.Unlock()
	c.bfd.Close()
}

// checkSize returns the size of the BFD packets of a session in PSP mode: the
// largest PSP packet that the agent sends, with the clamp when it is on.
func (a *Agent) checkSize() int {
	a.mu.Lock()
	b := a.bind
	a.mu.Unlock()
	return cmp.Or(b.ClampMTU(), b.DeviceMTU()) + pspwire.Overhead
}

func (c *pathCheck) setLost() { c.once.Do(func() { close(c.lost) }) }

// send sends one BFD packet with the state of this end.
func (c *pathCheck) send() {
	rc := c.rc
	c.bfd.SetSize(rc.a.checkSize())
	pkt := c.bfd.Append(nil, p2p.Probe{SID: c.keys.SID, Counter: rc.probeSeq.Add(1)}, &c.keys.Dialer)
	if _, err := rc.a.cfg.Transport.WriteTo(pkt, net.UDPAddrFromAddrPort(rc.relayAddr)); err != nil {
		slog.Debug("Failed to send a BFD packet", "relay", rc.addr, "error", err)
	}
}

// reply takes a BFD packet of the relay from the agent socket.
func (c *pathCheck) reply(pkt []byte) {
	r, err := p2p.OpenProbe(pkt, &c.keys.Listener)
	if err != nil || !r.Reply || r.BFD == nil {
		return
	}
	c.rc.seen.Store(&r.Seen)
	changed := c.bfd.Receive(r)
	switch {
	case c.bfd.Lost(time.Now()):
		c.setLost()
	case changed:
		c.send()
	}
}

// useQUIC changes rc to QUIC mode after its PSP path check failed. The session
// and its addresses stay. The relay changes from its own end of the check.
func (a *Agent) useQUIC(rc *relayConn) {
	c := rc.check.Swap(nil)
	if c == nil {
		return
	}
	c.stop()
	if err := rc.relay.UseQUIC(rc.pc); err != nil {
		// A session with no place for its data frames carries no data.
		slog.Warn("Failed to change the relay session to QUIC mode; closing it", "relay", rc.addr, "error", err)
		_ = rc.qc.CloseWithError(0, "no data path")
		return
	}
	rc.mode.Store(int32(dp.Mode_MODE_QUIC))
	rc.reason.Store(int32(dp.FallbackReason_FALLBACK_REASON_PROBE_TIMEOUT))
	// The next change to PSP mode gives new SAs and waits for the relay.
	rc.relay.StopRekeys()
	rc.resetBridge()
	rc.lanes.Store(1)
	if !rc.visitor() {
		var shards context.Context
		shards, rc.stopShards = context.WithCancel(rc.ctx)
		go rc.keepShards(shards, quicShards)
	}
	// The peer sessions of PSP mode send on the PSP path. The next packet
	// to a peer opens a session through the relay.
	a.closePeers(func(p *peer) bool { return p.rc == rc }, "relay session changed to QUIC mode")
	slog.Warn("PSP path to the relay stopped; changed the relay session from PSP mode to QUIC mode", "relay", rc.addr, "address", rc.self)
}
