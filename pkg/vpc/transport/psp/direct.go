// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ChannelPort is the UDP port of the channel between two agents, at the overlay address of each
// end.
const ChannelPort = 1001

// ipProtoAH is the IPv6 next header of the Authentication Header.
const ipProtoAH = 51

var errDirect = errors.New("psp: a direct peer has no link")

// prefixSet is a set of prefixes that does not change. A nil set has no prefix.
type prefixSet struct{ r engine.Routes[struct{}] }

// newPrefixSet returns the set of the valid prefixes of pfxs, or nil when it has none.
func newPrefixSet(pfxs []netip.Prefix) *prefixSet {
	s := &prefixSet{}
	for _, pfx := range pfxs {
		if pfx.IsValid() {
			_ = s.r.Add(pfx.Masked(), struct{}{})
		}
	}
	if s.r.Len() == 0 {
		return nil
	}
	return s
}

func (s *prefixSet) has(a netip.Addr) bool {
	if s == nil {
		return false
	}
	_, ok := s.r.Lookup(a)
	return ok
}

// AddDirect adds a peer on no link at addr, for a direct path to another agent. It sends from the
// agent socket only, and it has no routes and accepts no inner source until SetDirect.
func (b *Binding) AddDirect(addr netip.AddrPort) (*Peer, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("psp: invalid direct peer address %v", addr)
	}
	p := &Peer{b: b, tx: b.send.NewPeer(), rxSPIs: map[uint32]struct{}{}}
	p.SetLaneSockets(1)
	// The check reads the newest sources, so that SetDirect applies to the SAs that exist.
	sources := func(a netip.Addr) bool { return p.srcs.Load().has(a) }
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: 1, Sources: sources})
	if err != nil {
		return nil, err
	}
	p.rx = rx
	p.SetAddr(addr)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return nil, ErrClosed
	}
	b.peers[rx] = p
	return p, nil
}

// Direct reports whether p is a peer of AddDirect.
func (p *Peer) Direct() bool { return p.l == nil }

// SetDirect sets the inner sources that the receive SAs of the direct peer p accept, and makes
// routes the routes of p in the direct table.
func (b *Binding) SetDirect(p *Peer, sources, routes []netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.removed {
		return ErrClosed
	}
	if p.l != nil {
		return errors.New("psp: SetDirect needs a peer of AddDirect")
	}
	if err := b.setDirectRoutes(p, routes); err != nil {
		return err
	}
	p.srcs.Store(newPrefixSet(sources))
	return nil
}

// setDirectRoutes makes routes the direct routes of p, or changes nothing when another peer has
// one of them. b.mu must be held.
func (b *Binding) setDirectRoutes(p *Peer, routes []netip.Prefix) error {
	var want []netip.Prefix
	for _, pfx := range routes {
		if !pfx.IsValid() {
			return fmt.Errorf("psp: invalid direct route %v", pfx)
		}
		if pfx = pfx.Masked(); !slices.Contains(want, pfx) {
			want = append(want, pfx)
		}
	}
	// All checks run before the first change, because readers use the table with no lock.
	for _, q := range b.peers {
		if q == p || q.l != nil {
			continue
		}
		for _, pfx := range want {
			if slices.Contains(q.routes, pfx) {
				return fmt.Errorf("psp: direct route %v: %w", pfx, engine.ErrRouteTaken)
			}
		}
	}
	for _, pfx := range want {
		if err := b.direct.Add(pfx, p); err != nil {
			return fmt.Errorf("psp: direct route %v: %w", pfx, err)
		}
	}
	for _, pfx := range p.routes {
		if !slices.Contains(want, pfx) {
			b.direct.Remove(pfx, p)
		}
	}
	p.routes = want
	b.directN.Store(int32(b.direct.Len()))
	return nil
}

// SetOwn sets the own list. Packets from it use the direct table, and channel packets to it go to
// the take-out. It ignores invalid prefixes.
func (b *Binding) SetOwn(own []netip.Prefix) { b.own.Store(newPrefixSet(own)) }

// directPeer returns the direct peer of an inner packet to dst from a source in the own list. The
// callers check directN first, so that an empty table costs one load and no call.
func (b *Binding) directPeer(pkt []byte, dst netip.Addr) (*Peer, bool) {
	if src, _ := innerSrc(pkt); !b.own.Load().has(src) {
		return nil, false
	}
	return b.direct.Lookup(dst)
}

// Source is the way that a packet of the take-out came: the peer of its SA and its outer source,
// or the link of the relay session of its data frame.
type Source struct {
	Peer *Peer
	Addr netip.AddrPort
	Link *Link
}

// TakeOut gets the channel packets to the own list. It runs on a receive goroutine, so it must
// not block. pkt is valid only during the call.
type TakeOut func(pkt []byte, src Source)

// SetTakeOut gives the channel packets to the own list to h after the replay check, not to the
// driver. Nil stops it.
func (b *Binding) SetTakeOut(h TakeOut) {
	if h == nil {
		b.takeOut.Store(nil)
		return
	}
	b.takeOut.Store(&h)
}

// isChannel reports whether pkt is an IPv6 packet to UDP port ChannelPort, also after extension
// headers. A fragment after the first has no UDP header, so it is not a channel packet.
func isChannel(pkt []byte) bool {
	if len(pkt) < header.IPv6MinimumSize || pkt[0]>>4 != header.IPv6Version {
		return false
	}
	// Each step goes at least 8 bytes forward, so the loop ends at the end of pkt.
	nh, off := pkt[6], header.IPv6MinimumSize
	for {
		if len(pkt) < off+8 {
			return false
		}
		switch nh {
		case uint8(header.UDPProtocolNumber):
			return binary.BigEndian.Uint16(pkt[off+2:]) == ChannelPort
		case uint8(header.IPv6HopByHopOptionsExtHdrIdentifier), uint8(header.IPv6RoutingExtHdrIdentifier),
			uint8(header.IPv6DestinationOptionsExtHdrIdentifier):
			nh, off = pkt[off], off+(int(pkt[off+1])+1)*8
		case ipProtoAH:
			nh, off = pkt[off], off+(int(pkt[off+1])+2)*4
		case uint8(header.IPv6FragmentExtHdrIdentifier):
			if binary.BigEndian.Uint16(pkt[off+2:])&^7 != 0 {
				return false
			}
			nh, off = pkt[off], off+8
		default:
			return false
		}
	}
}

// takes reports whether the take-out gets the inner packet pkt: a channel packet to an address
// of the own list.
func (b *Binding) takes(pkt []byte) bool {
	return isChannel(pkt) && b.own.Load().has(netip.AddrFrom16([16]byte(pkt[24:40])))
}

// give gives an opened channel packet to the take-out, and reports whether it took the packet.
// A packet whose SA has no peer now drops. It counts no drop.
func (b *Binding) give(inner []byte, o engine.Opened, l *Link, from netip.AddrPort) bool {
	h := b.takeOut.Load()
	src := Source{Link: l}
	if l == nil {
		src.Peer, src.Addr = (*b.spis.Load())[o.SPI()], from
	}
	if h == nil || (l == nil && src.Peer == nil) {
		return false
	}
	// The count goes first, so that the counters have the packet when the take-out has it.
	b.stats.rxPackets.Add(1)
	(*h)(inner, src)
	return true
}

// editSPIs gives edit a copy of the SPI table without the deleted SAs, and stores the copy. b.mu
// must be held.
func (b *Binding) editSPIs(edit func(map[uint32]*Peer)) {
	old := *b.spis.Load()
	m := make(map[uint32]*Peer, len(old)+1)
	for spi, p := range old {
		if _, ok := b.table.Stats(spi); ok {
			m[spi] = p
		}
	}
	edit(m)
	b.spis.Store(&m)
}

// SendVia sends pkt to p with no route lookup: a PSP packet to to, or to Peer.Addr when to is
// not valid. After Peer.UseQUIC it sends a data frame, which drops when the send queue is full.
func (b *Binding) SendVia(p *Peer, pkt []byte, to netip.AddrPort) error {
	if b.ctx.Err() != nil {
		return ErrClosed
	}
	err := b.sendVia(p, pkt, to)
	if err != nil {
		b.countTx(err)
	} else {
		b.stats.txPackets.Add(1)
	}
	return err
}

func (b *Binding) sendVia(p *Peer, pkt []byte, to netip.AddrPort) error {
	if _, ok := innerDst(pkt); !ok || len(pkt) > b.mtu {
		return errDrop
	}
	var f netstack.TxFrame
	if slot := p.slot.Load(); slot != 0 {
		if !b.quic.limiter.admit(len(pkt)) {
			return errLimit
		}
		f = netstack.TxFrame{Lane: int(slot)}
	} else {
		sa, lane := p.txSA(pkt)
		if sa == nil {
			return ErrNoRoute
		}
		if !p.br.limiter.admit(len(pkt)) {
			return errLimit
		}
		seq, err := sa.Reserve()
		if err != nil {
			return err
		}
		if !to.IsValid() {
			to = p.Addr()
		}
		to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
		f = netstack.TxFrame{SA: sa, Seq: seq, Dst: to, Lane: p.SendLane(lane)}
	}
	phy := make([]byte, addrLen+pspwire.Overhead+len(pkt))
	n, err := b.seal(&f, pkt, phy)
	if err != nil {
		return err
	}
	if f.SA != nil {
		return b.write(phy[:n], &net.UDPAddr{IP: make(net.IP, net.IPv6len)}, false)
	}
	pc := b.dataConn(f.Lane)
	if pc == nil {
		return errNoRelay
	}
	if err := pc.TrySendData(phy[addrLen:n]); err != nil {
		return err
	}
	b.stats.txFrames.Add(1)
	return nil
}
