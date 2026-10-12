// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// Link is the routes of one relay connection of the agent. An inner packet uses the
// link of its source address, and goes to the peer that this link routes its
// destination to. Thus a prefix has one peer on each link.
type Link struct {
	b      *Binding
	routes engine.Routes[*Peer]
	// routed reports whether a peer of the link has a route to an address.
	routed func(netip.Addr) bool

	// Guarded by b.mu.
	sources []netip.Prefix
	removed bool
}

// AddLink adds a link with no sources and no peers. While the binding has one
// link, each packet uses it.
func (b *Binding) AddLink() (*Link, error) {
	l := &Link{b: b}
	l.routed = func(a netip.Addr) bool {
		_, ok := l.routes.Lookup(a)
		return ok
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return nil, ErrClosed
	}
	b.links = append(b.links, l)
	b.setOnly()
	return l, nil
}

// RemoveLink removes l and its sources. The caller removes the peers of l.
func (b *Binding) RemoveLink(l *Link) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if l.removed {
		return
	}
	for _, pfx := range l.sources {
		b.sources.Remove(pfx, l)
	}
	l.sources, l.removed = nil, true
	b.def.CompareAndSwap(l, nil)
	b.links = slices.DeleteFunc(b.links, func(o *Link) bool { return o == l })
	b.setOnly()
}

// setOnly keeps b.only: the link of a binding with one link. b.mu must be held.
func (b *Binding) setOnly() {
	if len(b.links) == 1 {
		b.only.Store(b.links[0])
	} else {
		b.only.Store(nil)
	}
}

// AddSource sends the inner packets with a source in pfx on l: pfx has the
// addresses of the agent on the relay connection of l. A prefix has one link.
func (l *Link) AddSource(pfx netip.Prefix) error {
	pfx = pfx.Masked()
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	if l.removed {
		return ErrClosed
	}
	if err := l.b.sources.Add(pfx, l); err != nil {
		return err
	}
	if !slices.Contains(l.sources, pfx) {
		l.sources = append(l.sources, pfx)
	}
	return nil
}

// RemoveSource ends AddSource for pfx.
func (l *Link) RemoveSource(pfx netip.Prefix) {
	pfx = pfx.Masked()
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	if l.b.sources.Remove(pfx, l) {
		l.sources = slices.DeleteFunc(l.sources, func(o netip.Prefix) bool { return o == pfx })
	}
}

// SetDefault sends the inner packets whose source no link has on l, for example
// the traffic from a network that the agent advertises. Nil drops them.
func (b *Binding) SetDefault(l *Link) { b.def.Store(l) }

// linkOf returns the link of an inner packet, or nil when no link sends it.
// It is small, so that the send path with one link has no call.
func (b *Binding) linkOf(pkt []byte) *Link {
	l := b.only.Load()
	if l == nil {
		l = b.sourceLink(pkt)
	}
	return l
}

// sourceLink returns the link that has the source address of an inner packet,
// or else the default link.
func (b *Binding) sourceLink(pkt []byte) *Link {
	if src, ok := innerSrc(pkt); ok {
		if l, ok := b.sources.Lookup(src); ok {
			return l
		}
	}
	return b.def.Load()
}

// AddPeer adds a remote agent at addr, for example its relay on port 443.
func (l *Link) AddPeer(addr netip.AddrPort) (*Peer, error) { return l.AddPeerLanes(addr, 1) }

// AddPeerLanes adds a remote agent at addr that sends to this agent on lanes
// SAs. The peer sends each lane from its own UDP port, so use more than one
// lane only on a direct path with no NAT. Its receive SAs accept only the
// sources that l routes to it.
func (l *Link) AddPeerLanes(addr netip.AddrPort, lanes int) (*Peer, error) {
	b := l.b
	if !addr.IsValid() {
		return nil, fmt.Errorf("psp: invalid peer address %v", addr)
	}
	p := &Peer{b: b, l: l, tx: b.send.NewPeer(), rxSPIs: map[uint32]struct{}{}}
	p.sockets.Store(keys.MaxLanes)
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: lanes, Sources: l.routes.Sources(p)})
	if err != nil {
		return nil, err
	}
	p.rx = rx
	p.SetAddr(addr)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil || l.removed {
		return nil, ErrClosed
	}
	b.peers[rx] = p
	return p, nil
}

// HandleData opens a data frame of the relay session of l and gives it to the driver.
// Set it with (*peerconn.Conn).HandleData.
func (l *Link) HandleData(frame []byte) {
	b := l.b
	d := b.drv.Load()
	if d == nil {
		b.stats.rxNoDriver.Add(1)
		return
	}
	inner, err := peerconn.OpenData(frame, b.vni, l.routed)
	if err != nil {
		b.stats.rxDrops.Add(1)
		return
	}
	b.deliver(d, frame, len(frame)-len(inner), false)
}
