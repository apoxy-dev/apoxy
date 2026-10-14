// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// peerCheckWait is the period of the BFD packets of a peer path before Up.
	// RFC 5880 asks for 1 s or more.
	peerCheckWait = time.Second
	// peerCheckTx is the period of the BFD packets of a peer path when Up. The
	// path is lost when no packet comes for 3 periods.
	peerCheckTx = bfdl.DefaultTxInterval
	// bfdSrcPort is the source port of the BFD packets, from the range of RFC 5881.
	bfdSrcPort = 49152
	// bfdQueue is the most received BFD packets that wait for the agent.
	bfdQueue = 256
)

// peerCheck is one try of the BFD session of the PSP path to a peer. Its
// packets go in PSP packets with the SAs of the two agents, as UDP to the BFD
// port of the overlay address of the peer, so they take the path of the data.
type peerCheck struct {
	p    *peer
	bfd  *p2p.Check
	rx   chan []byte // BFD packets of the peer.
	stop context.CancelFunc
	// stopped is true when the agent stopped the try: no next try follows.
	// Guarded by Agent.mu.
	stopped bool
	done    chan struct{} // Closed when the try ends.
}

// bfdIn is a BFD packet of a peer path from the receive path.
type bfdIn struct {
	src, dst netip.Addr
	bfd      []byte
}

// ended reports whether the try ended.
func (c *peerCheck) ended() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// onBFD takes a BFD packet of a peer path from the binding. It does not wait:
// the packet drops when the queue is full.
func (a *Agent) onBFD(pkt []byte) {
	src, dst, payload, ok := udpPayload(pkt)
	if !ok {
		return
	}
	select {
	case a.bfd <- bfdIn{src, dst, append([]byte(nil), payload...)}:
	default:
	}
}

// readBFD gives the BFD packets of the peer paths to their peer sessions until
// ctx ends.
func (a *Agent) readBFD(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-a.bfd:
			if p := a.peerOfBFD(m.src, m.dst); p != nil {
				a.takeBFD(p, m.bfd)
			}
		}
	}
}

// peerOfBFD returns the open peer session with the agent at src on a relay
// session with the address dst.
func (a *Agent) peerOfBFD(src, dst netip.Addr) *peer {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.bp != nil && p.addr == src && p.rc.self == dst && !a.gone(p) {
			return p
		}
	}
	return nil
}

// takeBFD gives a BFD packet of the peer to the try that runs. With none, a
// new try starts at once, so that the tries of the two agents run together.
// AdminDown ends the try that runs and starts none: the next try waits.
func (a *Agent) takeBFD(p *peer, pkt []byte) {
	if adminDown(pkt) {
		a.endCheck(p)
		return
	}
	c := a.tryCheck(p)
	if c == nil {
		return
	}
	select {
	case c.rx <- pkt:
	default:
	}
}

// endCheck ends the try of p that runs. checkEnded then removes the route and
// starts the next try after its wait.
func (a *Agent) endCheck(p *peer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c := p.check; c != nil && !c.ended() {
		c.stop()
	}
}

// tryCheck returns the try of the BFD check of p that runs, or starts one. It
// returns nil when the pair cannot use the PSP path: this agent or the peer is
// in QUIC mode.
func (a *Agent) tryCheck(p *peer) *peerCheck {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c := p.check; c != nil && !c.ended() {
		return c
	}
	if a.gone(p) || p.bp == nil || p.quic || p.rc.dataMode() != dp.Mode_MODE_PSP {
		return nil
	}
	if p.retry != nil {
		p.retry.Stop()
		p.retry = nil
	}
	ctx, cancel := context.WithCancel(p.qc.Context())
	c := &peerCheck{p: p, bfd: p2p.NewCheck(p2p.RoleAgent, peerCheckTx), rx: make(chan []byte, 4), stop: cancel, done: make(chan struct{})}
	p.check = c
	go c.run(ctx)
	return c
}

// run sends a BFD packet at each period until the path is lost or the try
// stops. The route to the peer is up from BFD Up.
func (c *peerCheck) run(ctx context.Context) {
	a := c.p.rc.a
	defer a.checkEnded(c)
	tx := time.NewTimer(0)
	defer tx.Stop()
	detect := time.NewTicker(peerCheckWait / 2)
	defer detect.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.rx:
			changed := c.bfd.Receive(p2p.Probe{BFD: pkt})
			if c.bfd.Lost(time.Now()) {
				// The peer said Down.
				return
			}
			if changed {
				c.send()
			}
			if changed && c.bfd.Up() {
				a.pathUp(c)
			}
		case now := <-detect.C:
			if c.bfd.Lost(now) {
				// This packet tells the peer of the Down state.
				c.send()
				return
			}
		case <-tx.C:
			c.send()
			tx.Reset(c.period())
		}
	}
}

// period returns the time to the next BFD packet.
func (c *peerCheck) period() time.Duration {
	if c.bfd.Up() {
		return peerCheckTx
	}
	return peerCheckWait
}

// send sends one BFD packet with the state of this end to the peer.
func (c *peerCheck) send() {
	p := c.p
	if err := p.bp.Send(bfdPacket(p.rc.self, p.addr, c.bfd.Packet(), p.bfdSize())); err != nil {
		slog.Debug("Failed to send a BFD packet to a peer", "peer", p.subject, "error", err)
	}
}

// bfdSize is the size of the BFD packets to the peer: the largest inner packet
// of the agent. The PSP seal adds the overhead, which gives the size of checkSize.
func (p *peer) bfdSize() int { return p.rc.a.checkSize() - pspwire.Overhead }

// pathUp puts the route to the peer of c in the binding at BFD Up.
func (a *Agent) pathUp(c *peerCheck) {
	p := c.p
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.check != c || c.stopped || p.up || a.gone(p) {
		return
	}
	if err := p.bp.SetUp(true); err != nil {
		slog.Warn("Failed to add the route to a peer", "peer", p.subject, "address", p.addr, "error", err)
		return
	}
	p.up, p.retryWait = true, 0
	p.settle()
	slog.Info("Added the route to a peer after its BFD check passed", "peer", p.subject, "address", p.addr)
}

// checkEnded removes the route of the try c at once, and starts the next try
// after a wait that doubles from retryMin to retryMax.
func (a *Agent) checkEnded(c *peerCheck) {
	p := c.p
	c.bfd.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	close(c.done)
	// The packets of the first try that failed go on the default route.
	p.settle()
	if p.check != c || c.stopped || a.gone(p) {
		return
	}
	if p.up {
		p.up = false
		_ = p.bp.SetUp(false)
		slog.Info("Removed the route to a peer: its BFD check failed", "peer", p.subject, "address", p.addr)
	}
	p.retryWait = min(max(2*p.retryWait, a.retryMin), a.retryMax)
	p.retry = time.AfterFunc(p.retryWait, func() { a.tryCheck(p) })
}

// stopCheck stops the try of p with no next try, and removes the route of p.
// It returns the last try, or nil. a.mu must be held.
func (a *Agent) stopCheck(p *peer) *peerCheck {
	c := p.check
	if c != nil {
		c.stopped = true
		c.stop()
	}
	if p.retry != nil {
		p.retry.Stop()
		p.retry = nil
	}
	if p.up {
		p.up = false
		_ = p.bp.SetUp(false)
	}
	return c
}

// pathsDown removes at once the routes of the peers of rc after rc changed to
// QUIC mode, and sends each peer one BFD packet with the state AdminDown on the
// default route, so that the peer removes its route too. The sessions stay.
func (a *Agent) pathsDown(rc *relayConn) {
	var ps []*peer
	var downs [][]byte
	a.mu.Lock()
	for _, p := range a.peers {
		if p.rc != rc || p.bp == nil {
			continue
		}
		ps = append(ps, p)
		p.taken = false
		if c := a.stopCheck(p); c != nil {
			// No padding: in QUIC mode the default route drops a packet above QUICMTU.
			downs = append(downs, bfdPacket(rc.self, p.addr, adminDownPacket(c.bfd), 0))
		}
	}
	b := a.bind
	a.mu.Unlock()
	if _, err := b.Send(downs); err != nil {
		slog.Debug("Failed to send BFD AdminDown packets to the peers", "relay", rc.addr, "error", err)
	}
	for _, p := range ps {
		// The next change to PSP mode gives the peer new SAs.
		p.bp.StopRekeys()
	}
}

// offerAll gives the peers of rc new SAs after rc changed to PSP mode. Their
// routes come at BFD Up.
func (a *Agent) offerAll(rc *relayConn) {
	a.mu.Lock()
	var ps []*peer
	for _, p := range a.peers {
		if p.rc == rc && p.bp != nil {
			ps = append(ps, p)
		}
	}
	a.mu.Unlock()
	for _, p := range ps {
		go p.offer()
	}
}

// adminDownPacket returns the next BFD packet of c with the state AdminDown. A
// Down packet also starts a try of the peer, so it cannot stop the peer.
func adminDownPacket(c *p2p.Check) []byte {
	var pkt bfdl.Packet
	if err := bfdl.UnmarshalInto(&pkt, c.Packet()); err != nil {
		return nil
	}
	pkt.State = bfdl.StateAdminDown
	return bfdl.Marshal(&pkt)
}

// adminDown reports whether pkt is a BFD packet with the state AdminDown.
func adminDown(pkt []byte) bool {
	var m bfdl.Packet
	return bfdl.UnmarshalInto(&m, pkt) == nil && m.State == bfdl.StateAdminDown
}

// bfdPacket returns a UDP packet from src to the BFD port of dst with the BFD
// packet bfd, padded with zeros to size bytes.
func bfdPacket(src, dst netip.Addr, bfd []byte, size int) []byte {
	ipLen := header.IPv6MinimumSize
	if src.Is4() {
		ipLen = header.IPv4MinimumSize
	}
	n := max(size, ipLen+header.UDPMinimumSize+len(bfd))
	pkt := make([]byte, n)
	udpLen := n - ipLen
	if src.Is4() {
		ip := header.IPv4(pkt)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(n), TTL: 255, Protocol: uint8(header.UDPProtocolNumber),
			SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4()),
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		header.IPv6(pkt).Encode(&header.IPv6Fields{
			PayloadLength: uint16(udpLen), TransportProtocol: header.UDPProtocolNumber, HopLimit: 255,
			SrcAddr: tcpip.AddrFrom16(src.As16()), DstAddr: tcpip.AddrFrom16(dst.As16()),
		})
	}
	udp := header.UDP(pkt[ipLen:])
	udp.Encode(&header.UDPFields{SrcPort: bfdSrcPort, DstPort: bfdl.BFDPort, Length: uint16(udpLen)})
	copy(udp.Payload(), bfd)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, tcpip.AddrFromSlice(src.AsSlice()), tcpip.AddrFromSlice(dst.AsSlice()), uint16(udpLen))
	udp.SetChecksum(^checksum.Checksum(udp, xsum))
	return pkt
}

// udpPayload returns the addresses and the UDP payload of an IPv4 or IPv6 UDP
// packet.
func udpPayload(pkt []byte) (src, dst netip.Addr, payload []byte, ok bool) {
	var ipLen int
	switch {
	case len(pkt) >= header.IPv4MinimumSize && pkt[0]>>4 == 4:
		ip := header.IPv4(pkt)
		ipLen = int(ip.HeaderLength())
		src, dst = netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
	case len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == 6:
		ipLen = header.IPv6MinimumSize
		src, dst = netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
	default:
		return src, dst, nil, false
	}
	if len(pkt) < ipLen+header.UDPMinimumSize {
		return src, dst, nil, false
	}
	return src, dst, pkt[ipLen+header.UDPMinimumSize:], true
}
