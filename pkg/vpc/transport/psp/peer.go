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
	br    breaker

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
	p.b.openLanes(int(p.lanes.Load()))
	return refused, err
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

// txSA returns the transmit SA for the inner packet and its lane: the lane of
// its flow, or another lane if that one has no SA.
func (p *Peer) txSA(inner []byte) (*engine.TxSA, int) {
	n := int(p.lanes.Load())
	if n == 0 {
		return nil, 0
	}
	lane := 0
	if n > 1 {
		lane = int(flow.Hash(p.b.seed, inner) % uint64(n))
	}
	if sa := p.tx.SA(lane); sa != nil {
		return sa, lane
	}
	for i := range n {
		if sa := p.tx.SA(i); sa != nil {
			return sa, i
		}
	}
	return nil, 0
}
