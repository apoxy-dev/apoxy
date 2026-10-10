// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
)

// Peer is one remote agent of a binding. This agent receives from it with
// the SAs that Offer creates, and sends to it with the SAs that Apply gets.
type Peer struct {
	b     *Binding
	rx    *keys.Peer
	tx    *keys.TxPeer
	addr  atomic.Pointer[netip.AddrPort]
	lanes atomic.Int32 // Highest lane with a transmit SA, plus one.
	// sockets is the lane count that sends from lane sockets. The other
	// lanes send from the agent socket.
	sockets atomic.Int32
	br      breaker
	// slot is the place of the relay session of UseQUIC in Binding.slots, plus one.
	slot atomic.Int32
	// flows has the lane of each flow slot. txSA reads and writes it.
	flows [flowSlots]atomic.Uint32

	// Guarded by b.mu.
	routes  []netip.Prefix
	removed bool
	rxSPIs  map[uint32]struct{} // Receive SAs. RxReport removes the deleted ones.
}

// SetAddr changes the address that packets to the peer go to.
func (p *Peer) SetAddr(addr netip.AddrPort) {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	p.addr.Store(&addr)
}

// Addr returns the address that packets to the peer go to.
func (p *Peer) Addr() netip.AddrPort { return *p.addr.Load() }

// Offer creates new receive SAs for the peer and starts their rekeys. SAs of
// an earlier offer stay for the overlap.
func (p *Peer) Offer(now time.Time) (keys.Request, error) {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if p.removed {
		return keys.Request{}, ErrClosed
	}
	req, err := p.rx.Offer(now)
	p.addRxSAs(req.SAs)
	return req, err
}

// Refused deletes the receive SAs that the peer refused and offers new ones
// for their lanes.
func (p *Peer) Refused(spis []uint32, now time.Time) (keys.Request, error) {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if p.removed {
		return keys.Request{}, ErrClosed
	}
	req, err := p.rx.Refused(spis, now)
	p.addRxSAs(req.SAs)
	return req, err
}

// addRxSAs adds receive SAs for RxReport. b.mu must be held.
func (p *Peer) addRxSAs(sas []keys.SA) {
	for _, sa := range sas {
		p.rxSPIs[sa.SPI] = struct{}{}
	}
}

// RxReport returns the receive counters of the SAs that the peer sends with.
// Send them to the peer for its breaker.
func (p *Peer) RxReport() []SACount {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	out := make([]SACount, 0, len(p.rxSPIs))
	for spi := range p.rxSPIs {
		st, ok := p.b.table.Stats(spi)
		if !ok {
			delete(p.rxSPIs, spi)
			continue
		}
		out = append(out, SACount{SPI: spi, Packets: st.Packets, Seq: st.Seq})
	}
	return out
}

// Report gives an RxReport from the peer, received at now, to the breaker of
// the packets to the peer.
func (p *Peer) Report(now time.Time, sas []SACount) {
	if t, ok := p.br.addSAs(now, sas); ok {
		p.b.onTrip(p, t)
	}
}

// Limit returns the send limit to the peer in bytes per second, or 0 when
// there is none.
func (p *Peer) Limit() int64 { return p.br.limit() }

// StopRekeys stops the rekeys of the receive SAs, for example when the peer
// session closes. The SAs stay until they expire. Offer starts rekeys again.
func (p *Peer) StopRekeys() { p.rx.Close() }

// Apply applies a key change from the peer, received at now, to the transmit
// SAs. It returns the SPIs that it refuses because another peer gave them.
func (p *Peer) Apply(req keys.Request, now time.Time) ([]uint32, error) {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if p.removed {
		return nil, ErrClosed
	}
	for _, sa := range req.SAs {
		if sa.VNI != p.b.vni {
			return nil, fmt.Errorf("psp: SA %#x has VNI %d, not %d", sa.SPI, sa.VNI, p.b.vni)
		}
	}
	refused, err := p.tx.Apply(req, now)
	p.updateLanes()
	p.b.openLanes(min(int(p.lanes.Load()), int(p.sockets.Load())))
	return refused, err
}

// SetLaneSockets lets lanes 1 to n-1 send to the peer from their own socket.
// The other lanes send from the agent socket. A new peer uses the sockets of
// all lanes.
func (p *Peer) SetLaneSockets(n int) {
	p.sockets.Store(int32(min(max(n, 1), keys.MaxLanes)))
}

// SendLane returns the socket lane of the SA lane: the lane, or 0 for the
// agent socket.
func (p *Peer) SendLane(lane int) int {
	if lane >= int(p.sockets.Load()) {
		return 0
	}
	return lane
}

// updateLanes sets the lane count from the transmit SAs. b.mu must be held,
// so that the last count follows the last change.
func (p *Peer) updateLanes() {
	n := 0
	for i := range keys.MaxLanes {
		if p.tx.SA(i) != nil {
			n = i + 1
		}
	}
	p.lanes.Store(int32(n))
}

// txSA returns the transmit SA for the inner packet and its lane. A flow keeps
// its lane while it sends, and a new flow gets the lane with the lowest load.
func (p *Peer) txSA(inner []byte) (*engine.TxSA, int) {
	n := int(p.lanes.Load())
	if n <= 1 {
		if n == 0 {
			return nil, 0
		}
		return p.tx.SA(0), 0
	}
	s := &p.flows[flow.Hash(p.b.seed, inner)&(flowSlots-1)]
	v := s.Load()
	// The interval is read after the slot, so it is not older than the slot.
	now := p.b.load.tick.Load() & slotTick
	if lane := int(v&slotLane) - 1; lane >= 0 && lane < n {
		if age := (now - v>>8) & slotTick; age <= flowIdle {
			if sa := p.tx.SA(lane); sa != nil {
				if age != 0 {
					s.CompareAndSwap(v, v&slotLane|now<<8)
				}
				return sa, lane
			}
		}
	}
	return p.newLane(s, n)
}
