// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// RegisterLanes sets the lane ports of the caller. Forward then takes PSP
// packets from these ports at the session address as from the session. With
// receive, it also sends the SA lanes of the caller to these ports.
func (srv *Server) RegisterLanes(ctx context.Context, in *dp.RegisterLanesRequest) (*emptypb.Empty, error) {
	c, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, srv.R.registerLanes(c, in.GetPorts(), in.GetReceive())
}

// maxLanes returns the lane port limit for the Welcome of a session in mode.
// A session in QUIC mode sends no PSP packets, so it gets 0.
func (r *Router) maxLanes(mode dp.Mode) uint32 {
	if mode != dp.Mode_MODE_PSP {
		return 0
	}
	return uint32(r.cfg.LaneSources)
}

// registerLanes replaces the lane ports of c. It sets all ports or none. A
// port must be free, or a lane port of another session of the same agent.
func (r *Router) registerLanes(c *Session, ports []uint32, receive bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed {
		return rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if len(ports) > r.cfg.LaneSources {
		return rpc.Errorf(rpc.InvalidArgument, "%d lane ports is above the limit of %d", len(ports), r.cfg.LaneSources)
	}
	if !c.addr.IsValid() || c.shardOf != nil {
		return rpc.Errorf(rpc.FailedPrecondition, "session has no source address")
	}
	lanes := make([]netip.AddrPort, 0, len(ports))
	for _, p := range ports {
		a := netip.AddrPortFrom(c.addr.Addr(), uint16(p))
		switch {
		case p == 0 || p > 0xffff:
			return rpc.Errorf(rpc.InvalidArgument, "port %d is not valid", p)
		case a == c.addr || a == c.prev || slices.Contains(lanes, a):
			return rpc.Errorf(rpc.InvalidArgument, "port %d is the session port or a repeated port", p)
		}
		if o := r.bySource[a]; o != nil && o != c && (o.id != c.id || !slices.Contains(o.lanes, a)) {
			return rpc.Errorf(rpc.AlreadyExists, "port %d is a source of another session", p)
		}
		lanes = append(lanes, a)
	}
	r.dropLanes(c)
	c.lanes, c.receive = lanes, receive && len(lanes) > 0
	for _, a := range lanes {
		r.bySource[a] = c
	}
	r.markXDP(c)
	return nil
}

// dropLanes removes the lane ports of s. A port goes to another session of
// the agent that registered it. Router.mu must be held.
func (r *Router) dropLanes(s *Session) {
	r.markXDP(s)
	if s.receive && s.laneSeen != 0 {
		r.markInbound(s)
	}
	for _, a := range s.lanes {
		if r.bySource[a] == s {
			delete(r.bySource, a)
			r.passLane(s, a)
		}
	}
	s.lanes, s.receive, s.laneSeen = nil, false, 0
}

// dst returns where the PSP packets of SA lane go to s: lane port lane mod
// (n+1) of s, where 0 is the session address. A lane port with no keepalive
// yet is not used. Router.mu must be held.
func (s *Session) dst(lane int) netip.AddrPort {
	if lane == 0 || !s.receive {
		return s.addr
	}
	i := lane % (len(s.lanes) + 1)
	if i == 0 || s.laneSeen&(1<<(i-1)) == 0 {
		return s.addr
	}
	return s.lanes[i-1]
}

// Keepalive marks the lane port src as seen in each session of the agent that
// receives on it. It reports whether b is a keepalive.
func (r *Router) Keepalive(b []byte, src netip.AddrPort) bool {
	if len(b) != 1 || b[0] != p2p.TypeKeepalive {
		return false
	}
	r.mu.RLock()
	s := r.bySource[src]
	news := s != nil && !s.seen(src)
	r.mu.RUnlock()
	if !news {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s = r.bySource[src]; s == nil || r.domains[s.id.VPC] == nil {
		return true
	}
	// The sessions of one agent socket share its lane ports.
	for o := range r.domains[s.id.VPC].members {
		if i := slices.Index(o.lanes, src); o.id == s.id && o.receive && i >= 0 && o.laneSeen&(1<<i) == 0 {
			o.laneSeen |= 1 << i
			r.markInbound(o)
		}
	}
	return true
}

// seen reports whether a keepalive came from the lane port src of s, or s
// does not receive on src. Router.mu must be held.
func (s *Session) seen(src netip.AddrPort) bool {
	i := slices.Index(s.lanes, src)
	return !s.receive || i < 0 || s.laneSeen&(1<<i) != 0
}

// markInbound marks the senders of the rows to s for the next XDP sync, after
// the destinations of s change. Router.mu must be held.
func (r *Router) markInbound(s *Session) {
	if r.xdp == nil {
		return
	}
	for w := range s.inbound {
		r.markXDP(w.sender)
	}
}

// passLane gives lane port a of s to an open session of the same agent with
// the same lane port. Router.mu must be held.
func (r *Router) passLane(s *Session, a netip.AddrPort) {
	d := r.domains[s.id.VPC]
	if d == nil {
		return
	}
	for o := range d.members {
		if o != s && !o.closed && o.id == s.id && slices.Contains(o.lanes, a) {
			r.bySource[a] = o
			r.markXDP(o)
			return
		}
	}
}

// srcAddrs returns the outer addresses that s can send from: its address, its
// previous address and its lane ports. Router.mu must be held.
func (s *Session) srcAddrs() []netip.AddrPort {
	return append([]netip.AddrPort{s.addr, s.prev}, s.lanes...)
}

// from reports whether a is a source of s at now. Router.mu must be held.
func (s *Session) from(a netip.AddrPort, now time.Time) bool {
	_, ok := s.laneOf(a, now)
	return ok
}

// laneOf returns the lane of source a of s: 0 for its address, also the
// previous one in the overlap. It returns false when a is not a source of s at
// now. Router.mu must be held.
func (s *Session) laneOf(a netip.AddrPort, now time.Time) (int, bool) {
	if a == s.addr || (a == s.prev && !now.After(s.prevUntil)) {
		return 0, true
	}
	if i := slices.Index(s.lanes, a); i >= 0 {
		return i + 1, true
	}
	return 0, false
}
