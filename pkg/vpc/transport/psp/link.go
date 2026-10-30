// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	"github.com/gaissmai/bart"
)

// Link is the routes of one relay connection. An inner packet uses the link of
// its source address, so a prefix has one relay on each link.
type Link struct {
	b *Binding
	// routes are the send routes: the relay of each prefix.
	routes engine.Routes[*Peer]
	// routed reports whether a relay of the link has a route to an address.
	routed func(netip.Addr) bool
	// rx is the state of the reader of the relay session of l in the receive pipe.
	rx rxReader

	// removed is set under b.mu. The send path reads it with no lock.
	removed atomic.Bool

	// Guarded by b.mu.
	sources []netip.Prefix
}

// AddLink adds a link with no sources and no relays. While the binding has one
// link, each packet uses it.
func (b *Binding) AddLink() (*Link, error) {
	l := &Link{b: b, rx: rxReader{lane: -1}}
	l.rx.link = l
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

// RemoveLink removes l and its sources. The caller removes the relays of l.
func (b *Binding) RemoveLink(l *Link) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if l.removed.Load() {
		return
	}
	for _, pfx := range l.sources {
		b.sources.Remove(pfx, l)
	}
	l.sources = nil
	l.removed.Store(true)
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
	if l.removed.Load() {
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

// SetDefault sends the inner packets whose source no link has and that no visit
// link takes on l, for example from an advertised network. Nil drops them.
func (b *Binding) SetDefault(l *Link) { b.def.Store(l) }

// SetVisits replaces the visit links: a packet whose source no link has goes on
// the live link of its destination in visits, else on the default link.
func (b *Binding) SetVisits(visits map[netip.Prefix]*Link) {
	if len(visits) == 0 {
		b.visits.Store(nil)
		return
	}
	t := &bart.Fast[*Link]{}
	for pfx, l := range visits {
		t.Insert(pfx.Masked(), l)
	}
	b.visits.Store(t)
}

// linkOf returns the link of an inner packet to dst, or nil when no link sends
// it. It is small, so that the send path with one link has no call.
func (b *Binding) linkOf(pkt []byte, dst netip.Addr) *Link {
	l := b.only.Load()
	if l == nil {
		l = b.sendLink(pkt, dst)
	}
	return l
}

// sendLink returns the link that has the source address of an inner packet,
// else the visit link of its destination dst, else the default link.
func (b *Binding) sendLink(pkt []byte, dst netip.Addr) *Link {
	if src, ok := innerSrc(pkt); ok {
		if l, ok := b.sources.Lookup(src); ok {
			return l
		}
	}
	if t := b.visits.Load(); t != nil {
		if l, ok := t.Lookup(dst); ok && !l.removed.Load() {
			return l
		}
	}
	return b.def.Load()
}

// AddRelay adds a relay of the link at addr, for example the relay of the
// connection of the link. Its routes are the routes of the link to it, for
// example a default route. It sends each source that the link routes: the relay
// checks the sources.
func (l *Link) AddRelay(addr netip.AddrPort) (*Peer, error) {
	b := l.b
	if !addr.IsValid() {
		return nil, fmt.Errorf("psp: invalid relay address %v", addr)
	}
	p := &Peer{b: b, l: l, tx: b.send.NewPeer(), rxSPIs: map[uint32]struct{}{}}
	p.sockets.Store(keys.MaxLanes)
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: 1, Sources: l.routed})
	if err != nil {
		return nil, err
	}
	p.rx = rx
	p.SetAddr(addr)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil || l.removed.Load() {
		return nil, ErrClosed
	}
	b.peers[rx] = p
	return p, nil
}

// HandleData takes a data frame of the relay session of l and waits as Binding.read does. One
// goroutine calls it: set l with (*peerconn.Conn).HandleData.
func (l *Link) HandleData(frame []byte) { l.b.read(&l.rx, frame) }

// BatchEnd gives the data frames of one read of the relay session to the driver.
func (l *Link) BatchEnd() { l.b.readEnd(&l.rx) }
