// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"hash/maphash"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxUDP is the largest UDP payload that quic-go reads.
	maxUDP = 1452
	// maxClashes limits the new offers when relay SPIs are in rows of the agent.
	maxClashes = 4
)

// shardSeed keys the flow hash that picks the shard of a data frame.
var shardSeed = maphash.MakeSeed()

var (
	errMode    = errors.New("data frame from a session that is not in QUIC mode")
	errNoRoute = errors.New("no route to the inner destination")
	errNoSA    = errors.New("no SA for the PSP-mode destination")
)

// bridge is the PSP endpoint of the relay. It opens the PSP packets that
// agents send to the relay, and seals the packets that it sends to PSP agents.
type bridge struct {
	tr       *quic.Transport // Sends the sealed packets.
	local    *Session        // Receiver of the rows of relay SAs. It has no address.
	rxMu     sync.Mutex      // The read loops of all relay sockets share rxq.
	table    *engine.RxTable
	rxq      *engine.RxQueue
	recv     *keys.Receiver
	send     *keys.Sender
	lifetime time.Duration

	// Guarded by Router.mu.
	senders  map[uint32]*Session     // Session of each relay SA.
	peers    map[*keys.Peer]*Session // Session of each receive peer.
	reported map[*Session]uint64     // Accepted packets in the last RxReport to each session.
}

// startBridge returns the bridge of r. The first call makes it, with tr for
// the sealed packets.
func (r *Router) startBridge(tr *quic.Transport) *bridge {
	if br := r.bridge.Load(); br != nil {
		return br
	}
	br, err := newBridge(tr)
	if err != nil {
		slog.Error("Failed to start the PSP bridge", "error", err)
		return nil
	}
	if !r.bridge.CompareAndSwap(nil, br) {
		return r.bridge.Load()
	}
	return br
}

func newBridge(tr *quic.Transport) (*bridge, error) {
	table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
	if err != nil {
		return nil, err
	}
	recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
	if err != nil {
		return nil, err
	}
	send, err := keys.NewSender(maxUDP - pspwire.Overhead)
	if err != nil {
		return nil, err
	}
	return &bridge{
		tr:       tr,
		local:    newSession(Identity{}, func() netip.AddrPort { return netip.AddrPort{} }),
		table:    table,
		rxq:      table.Queue(0),
		recv:     recv,
		send:     send,
		lifetime: table.Lifetime(),
		senders:  map[uint32]*Session{},
		peers:    map[*keys.Peer]*Session{},
		reported: map[*Session]uint64{},
	}, nil
}

// hop is where the relay sends one inner packet.
type hop struct {
	dst  netip.Addr     // Inner destination.
	next *Session       // Nil if there is no route.
	out  *Session       // Connection of next for data frames: next or a shard.
	mode dp.Mode        // Mode of next.
	addr netip.AddrPort // Address of next.
	sa   *engine.TxSA   // SA of next for packets from the relay, or nil.
}

// nextHop returns the hop of an inner packet from src. Router.mu must be held.
func (r *Router) nextHop(src *Session, inner []byte) hop {
	dst, ok := innerDest(inner)
	if !ok {
		return hop{}
	}
	h := hop{dst: dst}
	if !r.permit(src.id.VPC, src.id.ID, src.id.VPC, dst) {
		return h
	}
	if h.next = r.lookup(src.id.VPC, dst); h.next != nil {
		h.out, h.mode, h.addr = h.next, h.next.sync.mode, h.next.addr
		n := 1
		for i, sh := range h.next.shards {
			if sh != nil {
				n = i + 1
			}
		}
		if n > 1 {
			if sh := h.next.shards[flow.Hash(shardSeed, inner)%uint64(n)]; sh != nil {
				h.out = sh
			}
		}
		if h.next.tx != nil {
			h.sa = h.next.tx.SA(0)
		}
	}
	return h
}

// forwardData sends a data frame from the QUIC-mode session s, or from a shard
// of it, to the session of its inner destination. buf holds a sealed packet.
func (r *Router) forwardData(s *Session, b, buf []byte, now time.Time) bool {
	var inner []byte
	var h hop
	err := errMode
	r.mu.RLock()
	if s.shardOf != nil {
		s = s.shardOf
	}
	if s.sync.mode == dp.Mode_MODE_QUIC {
		if inner, err = peerconn.OpenData(b, s.sync.ref.GetNetworkId(), s.sources); err == nil {
			h = r.nextHop(s, inner)
		}
	}
	r.mu.RUnlock()
	if err != nil {
		s.dataDrops.Add(1)
		return false
	}
	if !r.allow(s, len(b), now) {
		return false
	}
	return r.deliver(s, h, b, inner, buf, now)
}

// receivePSP opens a PSP packet to the relay in place and sends its inner
// packet to the QUIC-mode session of the destination as a data frame.
func (r *Router) receivePSP(br *bridge, pkt []byte, spi uint32, now time.Time) bool {
	br.rxMu.Lock()
	inner, _, err := br.rxq.Receive(pkt)
	br.rxMu.Unlock()
	var h hop
	r.mu.RLock()
	src := br.senders[spi]
	if src != nil && !src.closed && err == nil {
		h = r.nextHop(src, inner)
	}
	r.mu.RUnlock()
	if src == nil {
		return false
	}
	if err != nil {
		src.dataDrops.Add(1)
		return false
	}
	// The frame header takes the 5 bytes before the inner packet. Its type
	// byte is the last byte of the old VNI word, so the copy comes first.
	frame := pkt[pspwire.PrefixLen-peerconn.DataLen : pspwire.PrefixLen+len(inner)]
	copy(frame[1:peerconn.DataLen], pkt[pspwire.HeaderLen:pspwire.HeaderLen+4])
	frame[0] = peerconn.TypeData
	return r.deliver(src, h, frame, inner, nil, now)
}

// deliver sends frame to a QUIC-mode next hop, or inner sealed in buf to a
// PSP-mode next hop. A nil buf drops packets to PSP-mode sessions.
func (r *Router) deliver(src *Session, h hop, frame, inner, buf []byte, now time.Time) bool {
	var err error
	switch {
	case h.next == nil:
		if h.dst.IsValid() {
			r.noRoute(src, h.dst, now)
		}
		err = errNoRoute
	case h.mode == dp.Mode_MODE_QUIC:
		err = h.out.sendDatagram(frame)
	case h.mode == dp.Mode_MODE_PSP && h.sa != nil && buf != nil:
		err = r.sealTo(h, inner, buf)
	default:
		err = errNoSA
	}
	if err != nil {
		src.dataDrops.Add(1)
		return false
	}
	src.dataSent.Add(1)
	return true
}

// sealTo seals inner into buf with the SA of h and sends it to the address of h.
func (r *Router) sealTo(h hop, inner, buf []byte) error {
	br := r.bridge.Load()
	if br == nil {
		return errNoSA
	}
	n, err := h.sa.Seal(buf, inner)
	if err != nil {
		return err
	}
	ua := h.next.udpAddr.Load()
	if ua == nil || ua.AddrPort() != h.addr {
		ua = net.UDPAddrFromAddrPort(h.addr)
		h.next.udpAddr.Store(ua)
	}
	_, err = br.tr.WriteTo(buf[:n], ua)
	return err
}

// innerDest returns the destination address of an IPv4 or IPv6 packet.
func innerDest(p []byte) (netip.Addr, bool) {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(p[16:20])), true
	case len(p) >= 40 && p[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(p[24:40])).Unmap(), true
	}
	return netip.Addr{}, false
}

// offer gives the PSP-mode session s relay SAs, and returns the Rekey message
// for its agent. It returns nil if the relay has no bridge.
func (r *Router) offer(s *Session, n Network, now time.Time) (*dp.SessionResponse, error) {
	br := r.bridge.Load()
	if br == nil {
		return nil, nil
	}
	p, err := br.recv.NewPeer(keys.PeerConfig{VNI: n.ID, MTU: int(n.MTU), Lanes: 1, Sources: s.sources})
	if err != nil {
		return nil, err
	}
	req, err := p.Offer(now)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		p.Revoke()
		return nil, rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if req, err = r.avoidClashes(s, p, req, now); err != nil {
		p.Revoke()
		return nil, err
	}
	s.rx = p
	br.peers[p] = s
	r.addRelaySAs(br, s, req.SAs, now)
	return &dp.SessionResponse{Msg: &dp.SessionResponse_Rekey{Rekey: keyproto.ToProto(req)}}, nil
}

// avoidClashes offers new SAs for the relay SPIs that are in rows of s. An
// agent holds each SPI from one receiver. Router.mu must be held.
func (r *Router) avoidClashes(s *Session, p *keys.Peer, req keys.Request, now time.Time) (keys.Request, error) {
	for range maxClashes {
		var clash []uint32
		for _, sa := range req.SAs {
			if s.rows[sa.SPI] != nil {
				clash = append(clash, sa.SPI)
			}
		}
		if len(clash) == 0 {
			return req, nil
		}
		next, err := p.Refused(clash, now)
		if err != nil {
			return keys.Request{}, err
		}
		req.SAs = slices.DeleteFunc(req.SAs, func(sa keys.SA) bool { return slices.Contains(clash, sa.SPI) })
		req.SAs = append(req.SAs, next.SAs...)
	}
	return keys.Request{}, errors.New("relay SPIs are in rows of the agent")
}

// addRelaySAs adds relay SAs of s and their rows. The SAs that they replace
// end after a quarter of the lifetime, as in keys.Receiver. Router.mu must be held.
func (r *Router) addRelaySAs(br *bridge, s *Session, sas []keys.SA, now time.Time) {
	if s.relaySAs == nil {
		s.relaySAs = map[uint32]time.Time{}
	}
	end := now.Add(br.lifetime / 4)
	for spi, t := range s.relaySAs {
		if end.Before(t) {
			s.relaySAs[spi] = end
		}
	}
	for _, sa := range sas {
		s.relaySAs[sa.SPI] = now.Add(sa.ExpiresIn)
		br.senders[sa.SPI] = s
	}
	r.keepRows(br, s, now)
}

// keepRows removes the ended relay SAs of s and keeps a row to the relay for
// each live one, so that idle rows stay. Router.mu must be held.
func (r *Router) keepRows(br *bridge, s *Session, now time.Time) {
	for spi, end := range s.relaySAs {
		w := s.rows[spi]
		if !now.Before(end) || s.closed {
			delete(s.relaySAs, spi)
			delete(br.senders, spi)
			if w != nil && w.receiver == br.local {
				r.removeRow(w)
			}
			continue
		}
		if w == nil {
			w = &row{sender: s, receiver: br.local, spi: spi, vpc: s.id.VPC}
			if r.cfg.LaneRate > 0 {
				w.meter = rate.NewLimiter(rate.Limit(r.cfg.LaneRate), r.cfg.LaneBurst)
			}
			s.rows[spi] = w
			br.local.inbound[w] = struct{}{}
		}
		if w.receiver == br.local {
			w.expires = end
			w.lastUsed.Store(now.UnixNano())
		}
	}
}

// tickBridge rekeys the relay SAs that are due and sends the new SAs to the
// agents. It removes the SAs that ended, and sends the receive counters.
func (r *Router) tickBridge(now time.Time) {
	br := r.bridge.Load()
	if br == nil {
		return
	}
	ups, err := br.recv.Tick(now)
	if err != nil {
		slog.Warn("Failed to rekey relay SAs", "error", err)
	}
	br.send.Expire(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range ups {
		s := br.peers[u.Peer]
		if s == nil || s.closed {
			continue
		}
		req, err := r.avoidClashes(s, u.Peer, u.Request, now)
		if err != nil {
			slog.Warn("Failed to rekey relay SAs", "agent", s.id.ID, "error", err)
			continue
		}
		r.addRelaySAs(br, s, req.SAs, now)
		s.queue(&dp.SessionResponse{Msg: &dp.SessionResponse_Rekey{Rekey: keyproto.ToProto(req)}})
	}
	for _, s := range br.peers {
		r.keepRows(br, s, now)
		r.reportRx(br, s)
	}
}

// reportRx sends s the receive counters of its relay SAs when they changed.
// The agent gives them to its breaker. Router.mu must be held.
func (r *Router) reportRx(br *bridge, s *Session) {
	if s.closed || !s.sync.open {
		return
	}
	var sum uint64
	for spi := range s.relaySAs {
		if st, ok := br.table.Stats(spi); ok {
			sum += st.Packets
		}
	}
	if sum == br.reported[s] {
		return
	}
	br.reported[s] = sum
	rep := &dp.RxReport{Sas: make([]*dp.SAStats, 0, len(s.relaySAs))}
	for spi := range s.relaySAs {
		if st, ok := br.table.Stats(spi); ok {
			rep.Sas = append(rep.Sas, &dp.SAStats{Spi: spi, Packets: st.Packets, Seq: st.Seq})
		}
	}
	s.sync.report = rep
	s.notify()
}

// closeBridge deletes the SAs between the relay and s after s is removed.
func (r *Router) closeBridge(s *Session) {
	br := r.bridge.Load()
	if br == nil {
		return
	}
	r.mu.Lock()
	rx, tx := s.rx, s.tx
	s.rx, s.tx = nil, nil
	delete(br.peers, rx)
	delete(br.reported, s)
	for spi := range s.relaySAs {
		if br.senders[spi] == s {
			delete(br.senders, spi)
		}
	}
	s.relaySAs = nil
	r.mu.Unlock()
	if rx != nil {
		rx.Revoke()
	}
	if tx != nil {
		var spis []uint32
		for i := range keys.MaxLanes {
			if sa := tx.SA(i); sa != nil {
				spis = append(spis, sa.SPI())
			}
		}
		_, _ = tx.Apply(keys.Request{Op: keys.OpRevoke, SPIs: spis}, time.Time{})
	}
}

// Rekey applies a key change from a PSP-mode agent to the SAs that the relay
// seals packets to the agent with.
func (srv *Server) Rekey(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	req, err := keyproto.FromProto(in)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	refused, err := srv.R.rekey(s, req, time.Now())
	if err != nil {
		return nil, err
	}
	return &dp.KeysResponse{RefusedSpis: refused}, nil
}

func (r *Router) rekey(s *Session, req keys.Request, now time.Time) ([]uint32, error) {
	br := r.bridge.Load()
	if br == nil {
		return nil, rpc.Errorf(rpc.Unavailable, "relay has no PSP bridge")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return nil, rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if s.sync.mode != dp.Mode_MODE_PSP {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "Rekey needs a Session call in PSP mode")
	}
	vni := s.sync.ref.GetNetworkId()
	for _, sa := range req.SAs {
		if sa.VNI != vni {
			return nil, rpc.Errorf(rpc.InvalidArgument, "SA %#x has VNI %#x, not the VNI %#x of the VPC", sa.SPI, sa.VNI, vni)
		}
	}
	if s.tx == nil {
		s.tx = br.send.NewPeer()
	}
	refused, err := s.tx.Apply(req, now)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	return refused, nil
}
