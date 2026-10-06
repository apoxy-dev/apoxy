// SPDX-License-Identifier: AGPL-3.0-only

// Package psp is the agent data path: SoftPSP packets, or QUIC data frames on the relay
// session. PSP (0x04, 0x29), path probes (0x02) and QUIC (0x40 and up) share the agent
// socket. Lane sockets send PSP packets and lane keepalives (0x03), and read PSP packets.
package psp

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
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
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/mss"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/udpbatch"
)

const (
	// DefaultMTU is the inner MTU when Config sets none.
	DefaultMTU = vpcv1alpha1.DefaultMTU
	// MaxMTU is the largest inner MTU.
	MaxMTU = vpcv1alpha1.MaxMTU
	// QUICMTU is the largest inner packet in a data frame on a relay session with
	// InitialPacketSize 1350: quic-go takes 1350 - 37 B, and the frame header is 5 B.
	QUICMTU = 1308
	// sockBuf is the send and receive buffer size of the agent socket, and of a
	// lane socket that reads.
	sockBuf = 16 << 20
	// laneRcvBuf is the receive buffer size of a lane socket that only sends.
	// Packets to it stay in this buffer.
	laneRcvBuf = 4 << 10
)

// laneKeepalive is the packet that keeps the path from the relay to a lane socket open.
var laneKeepalive = []byte{p2p.TypeKeepalive}

var (
	// ErrClosed is the error of calls on a closed binding or a removed peer.
	ErrClosed = errors.New("psp: binding or peer is closed")
	// ErrNoRoute is the error of a packet that no peer routes, or whose peer has no
	// transmit SA.
	ErrNoRoute = errors.New("psp: no route or no transmit SA")

	errDrop    = errors.New("psp: packet is not IP or is too large")
	errNoRelay = errors.New("psp: no relay session for data frames")
	errLimit   = errors.New("psp: breaker limit drops the packet")
)

// Demux gives the non-QUIC packets of an agent socket to its binding, and path probes to Probe.
// Set Handle, BatchEnd and Probe on the transport before it starts.
type Demux struct {
	// Probe gets the path probes on the QUIC read loop. It must not block or keep pkt.
	Probe func(pkt []byte, from net.Addr)

	b atomic.Pointer[Binding]
}

// Handle runs on the QUIC read loop. It waits only while the receive pipe is full.
func (m *Demux) Handle(pkt []byte, from net.Addr) {
	if len(pkt) > 0 && pkt[0] == p2p.TypeProbe && m.Probe != nil {
		m.Probe(pkt, from)
		return
	}
	if b := m.b.Load(); b != nil {
		b.receive(0, pkt)
	}
}

// BatchEnd is the NonQUICBatchEnd of the transport. It gives the packets of one read to
// the TUN device or the netstack.
func (m *Demux) BatchEnd() {
	if b := m.b.Load(); b != nil {
		b.batchEnd(0)
	}
}

// Config configures a Binding.
type Config struct {
	// Transport is the agent socket. The caller owns it.
	Transport *quic.Transport
	// Demux has the NonQUICPacketHandler and the NonQUICBatchEnd of Transport.
	Demux *Demux
	// VNI is the network ID of the VPC.
	VNI uint32
	// MTU is the inner MTU, at most MaxMTU. Zero means DefaultMTU.
	MTU int
	// DeviceMTU is the MTU of the device on the binding, at most MTU. Zero means MTU.
	DeviceMTU int
	// NoRoute gets the inner packets that VirtToPhy cannot send for ErrNoRoute. It
	// runs on the send path of the driver, so it must not block or keep pkt.
	NoRoute func(pkt []byte)
	// OnTrip gets each change of a breaker limit. The peer is nil for the QUIC
	// data path. It must not block.
	OnTrip func(*Peer, Trip)
}

// Binding is the data path of one VPC on one agent socket.
type Binding struct {
	tr      *quic.Transport
	demux   *Demux
	vni     uint32
	mtu     int
	devMTU  int
	clamp   atomic.Int32 // MTU for the MSS of TCP SYN packets. Zero means off.
	table   *engine.RxTable
	rxq     *engine.RxQueue
	recv    *keys.Receiver
	send    *keys.Sender
	routes  engine.Routes[*Peer]
	seed    maphash.Seed
	relay   atomic.Pointer[peerconn.Conn] // Set when data goes as QUIC data frames.
	quic    breaker                       // Breaker of the QUIC data path.
	noRoute func(pkt []byte)
	onTrip  func(*Peer, Trip)

	// routed reports whether a peer has a route to an address.
	routed func(netip.Addr) bool

	ctx    context.Context // Ends at Close.
	cancel context.CancelFunc
	drv    atomic.Pointer[driver]
	// laneConns are the sockets of send lanes 1 and up. Lane 0 sends on the
	// agent socket. Set under mu, closed at Close.
	laneConns [keys.MaxLanes]atomic.Pointer[net.UDPConn]
	// laneSends are the send sockets of the lanes in laneConns. A lane with none
	// sends on its laneConns socket. Set under mu before laneConns, closed at Close.
	laneSends [keys.MaxLanes]atomic.Pointer[udpbatch.SendSocket]
	// sendWarn logs one time that a lane has no send socket.
	sendWarn sync.Once
	// rxMu guards the receive queue and the read batch of a driver with no receive
	// pipe, because lane sockets can read too.
	rxMu sync.Mutex

	mu      sync.Mutex
	peers   map[*keys.Peer]*Peer
	readers [keys.MaxLanes]*quic.Transport // The read loops of lane sockets 1 and up.

	stats counters
	load  laneLoad
}

// New returns a binding with a new master key and no peers.
func New(cfg Config) (*Binding, error) {
	if cfg.Transport == nil || cfg.Demux == nil || cfg.Transport.NonQUICPacketHandler == nil ||
		cfg.Transport.NonQUICBatchEnd == nil {
		return nil, errors.New("psp: no transport, or no demux as its NonQUICPacketHandler and NonQUICBatchEnd")
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
	if cfg.DeviceMTU == 0 {
		cfg.DeviceMTU = cfg.MTU
	}
	if cfg.DeviceMTU < 0 || cfg.DeviceMTU > cfg.MTU {
		return nil, fmt.Errorf("psp: device MTU must be 1 to %d, got %d", cfg.MTU, cfg.DeviceMTU)
	}
	// One receive queue. Many goroutines can open packets on it, and one checks the
	// replay window.
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
		tr:      cfg.Transport,
		demux:   cfg.Demux,
		vni:     cfg.VNI,
		mtu:     cfg.MTU,
		devMTU:  cfg.DeviceMTU,
		table:   table,
		rxq:     table.Queue(0),
		recv:    recv,
		send:    send,
		seed:    maphash.MakeSeed(),
		noRoute: cfg.NoRoute,
		onTrip:  cfg.OnTrip,
		ctx:     ctx,
		cancel:  cancel,
		peers:   map[*keys.Peer]*Peer{},
	}
	if b.onTrip == nil {
		b.onTrip = func(*Peer, Trip) {}
	}
	b.routed = func(a netip.Addr) bool {
		_, ok := b.routes.Lookup(a)
		return ok
	}
	if !cfg.Demux.b.CompareAndSwap(nil, b) {
		cancel()
		return nil, errors.New("psp: demux already has a binding")
	}
	if uc, ok := cfg.Transport.Conn.(*net.UDPConn); ok {
		if err := setSockBufs(uc, sockBuf, sockBuf); err != nil {
			slog.Debug("Failed to set the agent socket buffers", "bytes", sockBuf, "error", err)
		}
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
	for _, p := range b.peers {
		b.removeLocked(p)
	}
	readers := b.readers
	b.readers = [keys.MaxLanes]*quic.Transport{}
	b.mu.Unlock()
	// A lane sender that waits in a send returns when its send socket closes.
	for i := range b.laneSends {
		if s := b.laneSends[i].Load(); s != nil {
			_ = s.Close()
		}
	}
	// Close waits for the read loop, so b.mu is not held.
	for _, tr := range readers {
		if tr != nil {
			_ = tr.Close()
		}
	}
	for i := range b.laneConns {
		if c := b.laneConns[i].Load(); c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// DeviceMTU returns the MTU for the device on the binding.
func (b *Binding) DeviceMTU() int { return b.devMTU }

// SetClampMTU lowers the MSS of TCP SYN packets in both directions to fit mtu. Zero, or
// DeviceMTU or more, turns it off. It returns the previous MTU.
func (b *Binding) SetClampMTU(mtu int) (old int) {
	if mtu >= b.devMTU {
		mtu = 0
	} else if mtu != 0 {
		mtu = max(mtu, DefaultMTU)
	}
	return int(b.clamp.Swap(int32(mtu)))
}

// ClampMTU returns the MTU of the MSS clamp, or 0 when the clamp is off.
func (b *Binding) ClampMTU() int { return int(b.clamp.Load()) }

// clampMSS lowers the MSS of a TCP SYN in pkt to fit the clamp, and to fit QUICMTU on the
// QUIC path.
func (b *Binding) clampMSS(pkt []byte, quic bool) {
	m := int(b.clamp.Load())
	if quic && b.devMTU > QUICMTU && (m == 0 || m > QUICMTU) {
		m = QUICMTU
	}
	if m != 0 {
		mss.Clamp(pkt, m)
	}
}

// Update is a key change that Tick made for one peer.
type Update struct {
	Peer *Peer
	keys.Request
}

// Tick rekeys the due receive SAs, removes expired SAs and the breaker limits whose
// time ended, and moves the clock of the send lanes. Call it each second, and send each
// Update to its peer. Failed lanes are due again.
func (b *Binding) Tick(now time.Time) ([]Update, error) {
	ups, err := b.recv.Tick(now)
	b.send.Expire(now)
	b.load.advance(now, &b.stats.txLanes)
	b.mu.Lock()
	var opened []*Peer
	for _, p := range b.peers {
		p.updateLanes()
		if _, ok := p.br.expire(now); ok {
			opened = append(opened, p)
		}
	}
	out := make([]Update, 0, len(ups))
	for _, u := range ups {
		if p := b.peers[u.Peer]; p != nil {
			p.addRxSAs(u.SAs)
			out = append(out, Update{Peer: p, Request: u.Request})
		}
	}
	b.mu.Unlock()
	for _, p := range opened {
		b.onTrip(p, Trip{})
	}
	if _, ok := b.quic.expire(now); ok {
		b.onTrip(nil, Trip{})
	}
	return out, err
}

// Rotate starts a new master key. It returns keys.ErrBusy while SAs of the previous key
// are live.
func (b *Binding) Rotate() error { return b.recv.Rotate() }

// AddPeer adds a remote agent at addr, for example its relay on port 443.
func (b *Binding) AddPeer(addr netip.AddrPort) (*Peer, error) { return b.AddPeerLanes(addr, 1) }

// AddPeerLanes adds a remote agent at addr that sends to this agent on lanes
// SAs. The peer sends each lane from its own UDP port, so use more than one
// lane only on a direct path with no NAT.
func (b *Binding) AddPeerLanes(addr netip.AddrPort, lanes int) (*Peer, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("psp: invalid peer address %v", addr)
	}
	p := &Peer{b: b, tx: b.send.NewPeer(), rxSPIs: map[uint32]struct{}{}}
	p.sockets.Store(keys.MaxLanes)
	rx, err := b.recv.NewPeer(keys.PeerConfig{VNI: b.vni, MTU: b.mtu, Lanes: lanes, Sources: b.routes.Sources(p)})
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
	clear(p.rxSPIs)
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

// openLanes opens the sockets of send lanes 1 to n-1. A lane with no socket
// sends on the agent socket. b.mu must be held.
func (b *Binding) openLanes(n int) {
	uc, ok := b.tr.Conn.(*net.UDPConn)
	if !ok || b.ctx.Err() != nil {
		return
	}
	for i := 1; i < min(n, len(b.laneConns)); i++ {
		if b.laneConns[i].Load() != nil {
			continue
		}
		c, s, err := b.listenLane(uc)
		if err != nil {
			slog.Warn("Failed to open a send lane socket", "lane", i, "error", err)
			return
		}
		// A driver that finds the socket of a lane must find its send socket too.
		b.laneSends[i].Store(s)
		b.laneConns[i].Store(c)
	}
}

// listenLane opens a UDP socket on the address of uc, with a new port, and its
// send socket. The send socket is nil when the system cannot open one.
func (b *Binding) listenLane(uc *net.UDPConn) (*net.UDPConn, *udpbatch.SendSocket, error) {
	la, ok := uc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, nil, errors.New("agent socket has no UDP address")
	}
	network, ip := "udp", la.IP
	if ip4 := ip.To4(); ip4 != nil {
		network, ip = "udp4", ip4
	}
	laddr := &net.UDPAddr{IP: ip, Zone: la.Zone}
	c, s, err := udpbatch.Listen(network, laddr)
	if err != nil {
		cause := err
		if c, err = net.ListenUDP(network, laddr); err != nil {
			return nil, nil, err
		}
		b.sendWarn.Do(func() {
			slog.Warn("Failed to open a send socket for a lane, so the lane sends on its read socket", "error", cause)
		})
	}
	if err := setSockBufs(c, laneRcvBuf, sockBuf); err != nil {
		slog.Debug("Failed to set the lane socket buffers", "rcvBytes", laneRcvBuf, "sndBytes", sockBuf, "error", err)
	}
	syncSend(s)
	return c, s, nil
}

// syncSend copies the options of a lane socket to its send socket s. It does
// nothing for a lane with no send socket.
func syncSend(s *udpbatch.SendSocket) {
	if s == nil {
		return
	}
	if err := s.Sync(); err != nil {
		slog.Debug("Failed to copy the lane socket options to the send socket", "error", err)
	}
}

// OpenLanes opens the sockets of send lanes 1 to n-1 and returns their ports
// in lane order. It stops at the first lane with no socket.
func (b *Binding) OpenLanes(n int) []uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return nil
	}
	b.openLanes(n)
	var ports []uint16
	for i := 1; i < min(n, len(b.laneConns)); i++ {
		c := b.laneConns[i].Load()
		if c == nil {
			break
		}
		ports = append(ports, uint16(c.LocalAddr().(*net.UDPAddr).Port))
	}
	return ports
}

// ReadLanes starts a read loop on each open lane socket, which gives its PSP
// packets to the driver as the agent socket does.
func (b *Binding) ReadLanes() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return ErrClosed
	}
	for i := 1; i < len(b.laneConns); i++ {
		c := b.laneConns[i].Load()
		if c == nil || b.readers[i] != nil {
			continue
		}
		if err := setSockBufs(c, sockBuf, sockBuf); err != nil {
			slog.Debug("Failed to set the lane socket buffers", "bytes", sockBuf, "error", err)
		}
		tr := &quic.Transport{
			Conn:                 c,
			EnableGRO:            b.tr.EnableGRO,
			NonQUICPacketHandler: func(pkt []byte, _ net.Addr) { b.receive(i, pkt) },
			NonQUICBatchEnd:      func() { b.batchEnd(i) },
		}
		if err := tr.Start(); err != nil {
			return fmt.Errorf("psp: start the read loop of lane %d: %w", i, err)
		}
		// The transport set options on the socket, for example UDP GRO.
		syncSend(b.laneSends[i].Load())
		b.readers[i] = tr
	}
	return nil
}

// KeepLanes sends a lane keepalive from each lane socket to dst, so that the
// path back from dst stays open.
func (b *Binding) KeepLanes(dst netip.AddrPort) {
	ua := net.UDPAddrFromAddrPort(dst)
	for i := range b.laneConns {
		if c := b.laneConns[i].Load(); c != nil {
			_, _ = c.WriteToUDP(laneKeepalive, ua)
		}
	}
}

// LaneConns returns the open sockets of send lanes 1 and up.
func (b *Binding) LaneConns() []*net.UDPConn {
	var out []*net.UDPConn
	for i := range b.laneConns {
		if c := b.laneConns[i].Load(); c != nil {
			out = append(out, c)
		}
	}
	return out
}

// LaneSendQueue returns the bytes that the lane send sockets sent and the NIC
// did not complete. The sockets of LaneConns do not have these bytes.
func (b *Binding) LaneSendQueue() int {
	var n int
	for i := range b.laneSends {
		if s := b.laneSends[i].Load(); s != nil {
			n += s.Queued()
		}
	}
	return n
}

// laneConn returns the socket of a send lane, or nil for lane 0 and for a
// lane with no socket.
func (b *Binding) laneConn(lane byte) *net.UDPConn {
	if lane == 0 || int(lane) >= len(b.laneConns) {
		return nil
	}
	return b.laneConns[lane].Load()
}

// AddRoute sends inner packets for pfx to p, and lets p send from pfx. A prefix has one
// peer.
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

// Stats are the packet counters of a binding. They count PSP packets and QUIC data frames
// together.
type Stats struct {
	RxPackets    uint64 // Packets that passed the checks and went to the driver.
	RxDrops      uint64 // Packets that failed a check or the delivery, for example no SA.
	RxNoDriver   uint64 // Packets dropped because no driver runs.
	RxOther      uint64 // Non-QUIC packets that are not PSP, for example probes.
	TxPackets    uint64 // Packets sent.
	TxNoRoute    uint64 // Inner packets with no route or no transmit SA.
	TxDrops      uint64 // Inner packets that a size check, a seal or a write dropped.
	TxLimitDrops uint64 // Inner packets that the limiter of a tripped breaker dropped.
}

type counters struct {
	rxPackets, rxDrops, rxNoDriver, rxOther     atomic.Uint64
	txPackets, txNoRoute, txDrops, txLimitDrops atomic.Uint64
	txFrames                                    atomic.Uint64 // Data frames sent.
	txLanes                                     [keys.MaxLanes]atomic.Uint64
	rxLanes                                     [keys.MaxLanes]atomic.Uint64 // PSP packets read on each socket.
}

// Stats returns the packet counters.
func (b *Binding) Stats() Stats {
	c := &b.stats
	return Stats{
		RxPackets:    c.rxPackets.Load(),
		RxDrops:      c.rxDrops.Load(),
		RxNoDriver:   c.rxNoDriver.Load(),
		RxOther:      c.rxOther.Load(),
		TxPackets:    c.txPackets.Load(),
		TxNoRoute:    c.txNoRoute.Load(),
		TxDrops:      c.txDrops.Load(),
		TxLimitDrops: c.txLimitDrops.Load(),
	}
}

// LanePackets returns the PSP packets sent on each send lane, up to the last
// lane that sent a packet.
func (b *Binding) LanePackets() []uint64 { return lanePackets(&b.stats.txLanes) }

// RxLanePackets returns the PSP packets read on the agent socket and on each
// lane socket, up to the last socket that read a packet.
func (b *Binding) RxLanePackets() []uint64 { return lanePackets(&b.stats.rxLanes) }

func lanePackets(c *[keys.MaxLanes]atomic.Uint64) []uint64 {
	out := make([]uint64, len(c))
	n := 0
	for i := range out {
		if out[i] = c[i].Load(); out[i] > 0 {
			n = i + 1
		}
	}
	return out[:n]
}

// UseQUIC sends inner packets as data frames on the relay session of pc, not as PSP
// packets. Nil sends PSP packets again. Both paths always receive.
func (b *Binding) UseQUIC(pc *peerconn.Conn) { b.relay.Store(pc) }

// ReportQUIC gives the QUIC packets lost on the relay connections, in total, to the
// breaker of the data frames. Call it every 500 ms.
func (b *Binding) ReportQUIC(now time.Time, lost uint64) {
	if t, ok := b.quic.addQUIC(now, b.stats.txFrames.Load(), lost); ok {
		b.onTrip(nil, t)
	}
}

// QUICLimit returns the send limit of the data frames in bytes per second, or 0
// when there is none.
func (b *Binding) QUICLimit() int64 { return b.quic.limit() }

// receive gives a PSP packet from the socket of lane to the driver. It runs on the read
// loop of that socket. With a receive pipe, it copies the packet into the pipe, else it
// opens the packet.
func (b *Binding) receive(lane int, pkt []byte) {
	if len(pkt) == 0 || (pkt[0] != pspwire.NextHdrV4 && pkt[0] != pspwire.NextHdrV6) {
		b.stats.rxOther.Add(1)
		return
	}
	d := b.drv.Load()
	if d == nil {
		b.stats.rxNoDriver.Add(1)
		return
	}
	if d.pipe != nil {
		d.pipe.add(lane, pkt)
		return
	}
	b.rxMu.Lock()
	b.stats.rxLanes[lane].Add(1)
	b.open(d, pkt)
	b.rxMu.Unlock()
}

// batchEnd gives the packets of one read of the socket of lane to the driver.
func (b *Binding) batchEnd(lane int) {
	d := b.drv.Load()
	switch {
	case d == nil:
	case d.pipe != nil:
		d.pipe.flush(lane)
	case d.batch != nil:
		b.rxMu.Lock()
		d.batch.flush()
		b.rxMu.Unlock()
	}
}

// open opens a PSP packet in place and gives it to the driver, with b.rxMu held. Only the
// read loops call it, when the driver has no receive pipe.
func (b *Binding) open(d *driver, pkt []byte) {
	inner, _, err := b.rxq.Receive(pkt)
	if err != nil {
		b.stats.rxDrops.Add(1)
		return
	}
	b.deliver(d, pkt[:pspwire.PrefixLen+len(inner)], pspwire.PrefixLen, true)
}

// HandleData opens a data frame of the relay session and gives it to the driver. Set it
// with (*peerconn.Conn).HandleData.
func (b *Binding) HandleData(frame []byte) {
	d := b.drv.Load()
	if d == nil {
		b.stats.rxNoDriver.Add(1)
		return
	}
	inner, err := peerconn.OpenData(frame, b.vni, b.routed)
	if err != nil {
		b.stats.rxDrops.Add(1)
		return
	}
	b.deliver(d, frame, len(frame)-len(inner), false)
}

// deliver gives the inner packet buf[off:] of the PSP path or the QUIC path to the driver,
// after the MSS clamp. Both paths deliver only here. The PSP path sets batch.
func (b *Binding) deliver(d *driver, buf []byte, off int, batch bool) {
	b.clampMSS(buf[off:], b.relay.Load() != nil)
	if batch && d.batch != nil {
		d.batch.add(buf[off:])
		return
	}
	if d.deliver(buf, off) {
		b.stats.rxPackets.Add(1)
	} else {
		b.stats.rxDrops.Add(1)
	}
}
