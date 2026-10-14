// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// Link is the routes of one relay connection. An inner packet uses the link of
// its source address, so a prefix has one peer on each link.
type Link struct {
	b *Binding
	// routes are the send routes: the route of an agent peer that is up, else
	// the route of a relay.
	routes engine.Routes[*Peer]
	// peers has the prefixes of the agent peers, up or not, for their source checks.
	peers engine.Routes[*Peer]
	// routed reports whether a peer of the link has a route to an address.
	routed func(netip.Addr) bool

	// Guarded by b.mu.
	sources []netip.Prefix
	relays  map[netip.Prefix]*Peer // The relay route of each prefix.
	removed bool
}

// AddLink adds a link with no sources and no peers. While the binding has one
// link, each packet uses it.
func (b *Binding) AddLink() (*Link, error) {
	l := &Link{b: b, relays: map[netip.Prefix]*Peer{}}
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
	src, _ := innerSrc(pkt)
	return b.addrLink(src)
}

// addrLink returns the link that has the address a of this agent, or else the
// default link.
func (b *Binding) addrLink(a netip.Addr) *Link {
	if a.IsValid() {
		if l, ok := b.sources.Lookup(a); ok {
			return l
		}
	}
	return b.def.Load()
}

// AddPeer adds a remote agent at addr, for example its relay on port 443.
func (l *Link) AddPeer(addr netip.AddrPort) (*Peer, error) { return l.AddPeerLanes(addr, 1) }

// AddPeerLanes adds a remote agent at addr that sends on lanes SAs, each lane
// from its own UDP port: use more than one only with no NAT. The peer is up.
func (l *Link) AddPeerLanes(addr netip.AddrPort, lanes int) (*Peer, error) {
	return l.addPeer(addr, lanes, false)
}

// AddRelay adds the relay of the link at addr. Its routes are the routes of the
// prefixes that no up agent peer has, for example a default route. It sends each
// source that the link routes: the relay checks the sources.
func (l *Link) AddRelay(addr netip.AddrPort) (*Peer, error) {
	return l.addPeer(addr, 1, true)
}

func (l *Link) addPeer(addr netip.AddrPort, lanes int, relay bool) (*Peer, error) {
	b := l.b
	if !addr.IsValid() {
		return nil, fmt.Errorf("psp: invalid peer address %v", addr)
	}
	p := &Peer{b: b, l: l, tx: b.send.NewPeer(), rxSPIs: map[uint32]struct{}{}, relay: relay, up: true}
	p.sockets.Store(keys.MaxLanes)
	sources := l.peers.Sources(p)
	if relay {
		sources = l.routed
	}
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: lanes, Sources: sources})
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

// addRoute adds pfx to the routes of p. A prefix has one agent peer and one
// relay. b.mu must be held.
func (l *Link) addRoute(pfx netip.Prefix, p *Peer) error {
	if p.relay {
		if r := l.relays[pfx]; r != nil && r != p {
			return engine.ErrRouteTaken
		}
		l.relays[pfx] = p
	} else if err := l.peers.Add(pfx, p); err != nil {
		return err
	}
	if p.up {
		return l.show(pfx, p)
	}
	return nil
}

// removeRoute removes pfx from the routes of p. b.mu must be held.
func (l *Link) removeRoute(pfx netip.Prefix, p *Peer) {
	l.hide(pfx, p)
	if !p.relay {
		l.peers.Remove(pfx, p)
	} else if l.relays[pfx] == p {
		delete(l.relays, pfx)
	}
}

// show puts the route of pfx to p in the send routes. The route of an up agent
// peer takes the place of the relay route. b.mu must be held.
func (l *Link) show(pfx netip.Prefix, p *Peer) error {
	if r := l.relays[pfx]; !p.relay && r != nil {
		l.routes.Remove(pfx, r)
	}
	err := l.routes.Add(pfx, p)
	if p.relay && errors.Is(err, engine.ErrRouteTaken) {
		// An up agent peer has pfx.
		return nil
	}
	return err
}

// hide takes the route of pfx to p out of the send routes, and puts the relay
// route of pfx back. b.mu must be held.
func (l *Link) hide(pfx netip.Prefix, p *Peer) {
	if !l.routes.Remove(pfx, p) || p.relay {
		return
	}
	if r := l.relays[pfx]; r != nil {
		_ = l.routes.Add(pfx, r)
	}
}

// noPeer reports whether no agent peer of l has the address a, up or not.
func (l *Link) noPeer(a netip.Addr) bool {
	_, ok := l.peers.Lookup(a)
	return !ok
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
