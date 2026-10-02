// SPDX-License-Identifier: AGPL-3.0-only

// Package psp is the SoftPSP binding of an agent. PSP packets share the UDP
// socket of a quic.Transport; PSP starts with 0x04 or 0x29, QUIC sets bit 0x40.
package psp

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

const (
	// DefaultMTU is the inner MTU when Config sets none.
	DefaultMTU = vpcv1alpha1.DefaultMTU
	// MaxMTU is the largest inner MTU.
	MaxMTU = vpcv1alpha1.MaxMTU
)

// ErrClosed is the error of calls on a closed binding or a removed peer.
var ErrClosed = errors.New("psp: binding or peer is closed")

// Demux passes the non-QUIC packets of an agent socket to the binding on it.
// Set Handle as the NonQUICPacketHandler of the transport before its first use.
type Demux struct{ b atomic.Pointer[Binding] }

// Handle runs on the QUIC read loop. It does not block.
func (m *Demux) Handle(pkt []byte, _ net.Addr) {
	if b := m.b.Load(); b != nil {
		b.receive(pkt)
	}
}

// Config configures a Binding.
type Config struct {
	// Transport is the agent socket. The caller owns it.
	Transport *quic.Transport
	// Demux is the NonQUICPacketHandler of Transport.
	Demux *Demux
	// VNI is the network ID of the VPC.
	VNI uint32
	// MTU is the inner MTU, at most MaxMTU. Zero means DefaultMTU.
	MTU int
}

// Binding is the SoftPSP data path of one VPC on one agent socket.
type Binding struct {
	tr     *quic.Transport
	demux  *Demux
	vni    uint32
	mtu    int
	rxq    *engine.RxQueue
	recv   *keys.Receiver
	send   *keys.Sender
	routes engine.Routes[*Peer]
	seed   maphash.Seed

	ctx    context.Context // Ends at Close.
	cancel context.CancelFunc
	drv    atomic.Pointer[driver]

	mu    sync.Mutex
	peers map[*keys.Peer]*Peer

	stats counters
}

// New returns a binding with a new master key and no peers.
func New(cfg Config) (*Binding, error) {
	if cfg.Transport == nil || cfg.Demux == nil || cfg.Transport.NonQUICPacketHandler == nil {
		return nil, errors.New("psp: no transport, or no demux as its NonQUICPacketHandler")
	}
	if cfg.VNI > pspwire.MaxVNI {
		return nil, pspwire.ErrVNI
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < 0 || cfg.MTU > MaxMTU {
		return nil, fmt.Errorf("psp: MTU must be 1 to %d, got %d", MaxMTU, cfg.MTU)
	}
	// One receive queue: one goroutine reads the PSP packets.
	table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
	if err != nil {
		return nil, err
	}
	recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
	if err != nil {
		return nil, err
	}
	send, err := keys.NewSender(cfg.MTU)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Binding{
		tr:     cfg.Transport,
		demux:  cfg.Demux,
		vni:    cfg.VNI,
		mtu:    cfg.MTU,
		rxq:    table.Queue(0),
		recv:   recv,
		send:   send,
		seed:   maphash.MakeSeed(),
		ctx:    ctx,
		cancel: cancel,
		peers:  map[*keys.Peer]*Peer{},
	}
	if !cfg.Demux.b.CompareAndSwap(nil, b) {
		cancel()
		return nil, errors.New("psp: demux already has a binding")
	}
	if err := cfg.Transport.Start(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("psp: start transport: %w", err)
	}
	return b, nil
}

// Close stops the driver and the receive SAs. It does not close the transport.
func (b *Binding) Close() error {
	b.demux.b.CompareAndSwap(b, nil)
	b.cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.peers {
		b.removeLocked(p)
	}
	return nil
}

// Update is a key change that Tick made for one peer.
type Update struct {
	Peer *Peer
	keys.Request
}

// Tick rekeys the due receive SAs and removes expired SAs. Call it about once a
// second, and send each Update to its peer. Failed lanes are due again.
func (b *Binding) Tick(now time.Time) ([]Update, error) {
	ups, err := b.recv.Tick(now)
	b.send.Expire(now)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.peers {
		p.updateLanes()
	}
	out := make([]Update, 0, len(ups))
	for _, u := range ups {
		if p := b.peers[u.Peer]; p != nil {
			out = append(out, Update{Peer: p, Request: u.Request})
		}
	}
	return out, err
}

// Rotate starts a new master key. It returns keys.ErrBusy while SAs of the
// previous key are live.
func (b *Binding) Rotate() error { return b.recv.Rotate() }

// AddPeer adds a remote agent at addr, for example its relay on port 443.
func (b *Binding) AddPeer(addr netip.AddrPort) (*Peer, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("psp: invalid peer address %v", addr)
	}
	p := &Peer{b: b, tx: b.send.NewPeer()}
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: 1, Sources: b.routes.Sources(p)})
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

// RemovePeer deletes the SAs and routes of p. Send the returned revoke to the peer.
func (b *Binding) RemovePeer(p *Peer) keys.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.removeLocked(p)
}

func (b *Binding) removeLocked(p *Peer) keys.Request {
	if p.removed {
		return keys.Request{Op: keys.OpRevoke}
	}
	req := p.rx.Revoke()
	var spis []uint32
	for i := range keys.MaxLanes {
		if sa := p.tx.SA(i); sa != nil {
			spis = append(spis, sa.SPI())
		}
	}
	_, _ = p.tx.Apply(keys.Request{Op: keys.OpRevoke, SPIs: spis}, time.Time{})
	p.updateLanes()
	for _, pfx := range p.routes {
		b.routes.Remove(pfx, p)
	}
	p.routes, p.removed = nil, true
	delete(b.peers, p.rx)
	return req
}

// AddRoute sends inner packets for pfx to p, and lets p send from pfx. A
// prefix has one peer.
func (b *Binding) AddRoute(pfx netip.Prefix, p *Peer) error {
	pfx = pfx.Masked()
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.removed {
		return ErrClosed
	}
	if err := b.routes.Add(pfx, p); err != nil {
		return err
	}
	for _, have := range p.routes {
		if have == pfx {
			return nil
		}
	}
	p.routes = append(p.routes, pfx)
	return nil
}

// RemoveRoute removes the route of pfx to p and reports whether it did.
func (b *Binding) RemoveRoute(pfx netip.Prefix, p *Peer) bool {
	pfx = pfx.Masked()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.routes.Remove(pfx, p) {
		return false
	}
	for i, have := range p.routes {
		if have == pfx {
			p.routes = append(p.routes[:i], p.routes[i+1:]...)
			break
		}
	}
	return true
}

// Stats are the packet counters of a binding.
type Stats struct {
	RxPackets uint64 // PSP packets that passed the checks.
	RxDrops   uint64 // PSP packets that failed a check, for example no SA.
	RxFull    uint64 // PSP packets dropped: no driver, or no free receive slot.
	RxOther   uint64 // Non-QUIC packets that are not PSP, for example probes.
	TxPackets uint64 // PSP packets sent.
	TxNoRoute uint64 // Inner packets with no route or no transmit SA.
	TxDrops   uint64 // Inner packets that a size check, a seal or a write dropped.
}

type counters struct {
	rxPackets, rxDrops, rxFull, rxOther atomic.Uint64
	txPackets, txNoRoute, txDrops       atomic.Uint64
}

// Stats returns the packet counters.
func (b *Binding) Stats() Stats {
	c := &b.stats
	return Stats{
		RxPackets: c.rxPackets.Load(),
		RxDrops:   c.rxDrops.Load(),
		RxFull:    c.rxFull.Load(),
		RxOther:   c.rxOther.Load(),
		TxPackets: c.txPackets.Load(),
		TxNoRoute: c.txNoRoute.Load(),
		TxDrops:   c.txDrops.Load(),
	}
}

// receive hands a non-QUIC packet to the driver. Probes come later.
func (b *Binding) receive(pkt []byte) {
	if len(pkt) == 0 || (pkt[0] != pspwire.NextHdrV4 && pkt[0] != pspwire.NextHdrV6) {
		b.stats.rxOther.Add(1)
		return
	}
	if d := b.drv.Load(); d == nil || !d.push(pkt) {
		b.stats.rxFull.Add(1)
	}
}
