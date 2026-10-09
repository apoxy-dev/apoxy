// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"net/netip"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// caller returns the session of the call. A call with no session, for
// example from the JSON debug handler or from a connection whose agent cert
// failed the check, gets Unauthenticated. A shard connection carries only
// data, so its calls get FailedPrecondition.
func (r *Router) caller(ctx context.Context) (*Session, error) {
	if conn := rpc.ConnFromContext(ctx); conn != nil {
		r.mu.RLock()
		s := r.byConn[conn]
		shard := s != nil && s.shardOf != nil
		r.mu.RUnlock()
		if shard {
			return nil, rpc.Errorf(rpc.FailedPrecondition, "a shard connection carries only data")
		}
		if s != nil {
			return s, nil
		}
	}
	return nil, rpc.Errorf(rpc.Unauthenticated, "no authenticated relay session")
}

// vpc returns the key of ref. ref must name the VPC of the agent cert: one
// VPC for each cert.
func (s *Session) vpc(ref *dp.VPCRef) (VPCKey, error) {
	key, err := KeyOf(ref)
	if err != nil {
		return VPCKey{}, err
	}
	if key != s.id.VPC {
		return VPCKey{}, rpc.Errorf(rpc.PermissionDenied, "VPC %s/%s is not the VPC of the agent cert", key.Project, key.UID)
	}
	return key, nil
}

func (s *Session) target(ref *dp.VPCRef, addr string) (VPCKey, netip.Addr, error) {
	key, err := s.vpc(ref)
	if err != nil {
		return VPCKey{}, netip.Addr{}, err
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return VPCKey{}, netip.Addr{}, rpc.Errorf(rpc.InvalidArgument, "address: %v", err)
	}
	return key, a.Unmap(), nil
}

// visitReachRevision is the first revision of an agent that takes REACH_VISIT
// from ResolvePeer and a home relay in NoRoute.
const visitReachRevision = 12

// ResolvePeer tells how the caller reaches an address: on a session of this relay,
// over a trunk, or as a visitor. Permit runs first, so a denied caller learns nothing.
func (srv *Server) ResolvePeer(ctx context.Context, in *dp.ResolvePeerRequest) (*dp.ResolvePeerResponse, error) {
	c, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	return srv.R.resolvePeer(c, in)
}

func (r *Router) resolvePeer(c *Session, in *dp.ResolvePeerRequest) (*dp.ResolvePeerResponse, error) {
	key, dst, err := c.target(in.GetVpc(), in.GetAddress())
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.permit(c.id.VPC, c.id.ID, key, dst) {
		return nil, rpc.Errorf(rpc.PermissionDenied, "permit denies %s", dst)
	}
	peer := r.ownerOf(key, dst).s
	var res *dp.ResolvePeerResponse
	switch {
	case peer == nil:
		res = r.visitReach(c, key, dst, "")
	case peer.home != "":
		// The visit is only for a relay that is away, and the trunk reaches no such relay.
		if res = r.trunkReach(c, peer); res == nil {
			res = r.visitReach(c, key, dst, peer.home)
		}
	default:
		res = &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_LOCAL, P2P: true, Subject: peer.id.ID}
		// Many agents can have the subject. The attachments tell which agent has dst.
		for _, a := range peer.attachments {
			res.AttachmentIds = append(res.AttachmentIds, a.ID)
		}
	}
	if res == nil {
		return nil, rpc.Errorf(rpc.NotFound, "no route to %s", dst)
	}
	return res, nil
}

// trunkReach returns the answer for an address of peer, a session of another
// relay, or nil if c cannot open a peer session to it now. Router.mu must be held.
func (r *Router) trunkReach(c, peer *Session) *dp.ResolvePeerResponse {
	// An agent from before the answer, with no routes of other relays or with no
	// sender tag opens no peer session to another relay.
	if c.version.GetRevision() < trunkReachRevision || !c.sync.meshRoutes || !r.trunked(c) {
		return nil
	}
	t := r.trunk.Load()
	if !t.reaches(peer.home) {
		return nil
	}
	// The entry that has the route is one of the attachments, so the list is not empty.
	ids := t.m.pres.attachments(remoteKey{home: peer.home, id: peer.id, agent: peer.name, tag: peer.tag})
	return &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_TRUNK, Subject: peer.id.ID, AttachmentIds: ids}
}

// visitReach returns the answer that sends c to the home relay of dst as a
// visitor, or nil. home is as for visitRef. Router.mu must be held.
func (r *Router) visitReach(c *Session, key VPCKey, dst netip.Addr, home string) *dp.ResolvePeerResponse {
	ref := r.visitRef(c, key, dst, home)
	if ref == nil {
		return nil
	}
	return &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_VISIT, HomeRelay: ref}
}

// visitRef returns the relay that c must visit to reach dst, or nil. home is the
// member that has the route of dst, or "" with no route. Router.mu must be held.
func (r *Router) visitRef(c *Session, key VPCKey, dst netip.Addr, home string) *dp.RelayRef {
	// An agent that gets no REACH_TRUNK opens no peer session to another relay.
	if c.version.GetRevision() < visitReachRevision || !c.sync.meshRoutes || !r.trunked(c) {
		return nil
	}
	m := r.trunk.Load().m
	if home == "" {
		home = m.homeOf(key, dst)
	}
	return m.awayRef(home)
}

// RegisterSPI adds rows from the caller to the receiver of the destination.
// It installs all SPIs or none. An SPI that the caller holds for another
// destination gets AlreadyExists. The lane of an SPI sets only the source of
// its XDP row: Forward takes the SPI from all sources of the caller. The SA
// lane sets the lane port of the receiver.
//
// A receiver on another relay gets rows to that relay, which knows a row only by
// its SPI: an SPI that another row to it or one of its trunk SAs has gets AlreadyExists.
func (srv *Server) RegisterSPI(ctx context.Context, in *dp.RegisterSPIRequest) (*emptypb.Empty, error) {
	c, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, srv.R.registerSPI(c, in, time.Now())
}

func (r *Router) registerSPI(c *Session, in *dp.RegisterSPIRequest, now time.Time) error {
	key, dst, err := c.target(in.GetVpc(), in.GetDestination())
	if err != nil {
		return err
	}
	if len(in.GetSpis()) == 0 {
		return rpc.Errorf(rpc.InvalidArgument, "no SPIs")
	}
	ttl := in.GetExpiresIn().AsDuration()
	if in.GetExpiresIn().CheckValid() != nil || ttl <= 0 {
		return rpc.Errorf(rpc.InvalidArgument, "expires_in must be positive")
	}
	lanes, saLanes := in.GetLanes(), in.GetSaLanes()
	if err := checkLanes("lanes", lanes, len(in.GetSpis())); err != nil {
		return err
	}
	if err := checkLanes("SA lanes", saLanes, len(in.GetSpis())); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.closed {
		return rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if !r.permit(c.id.VPC, c.id.ID, key, dst) {
		return rpc.Errorf(rpc.PermissionDenied, "permit denies %s", dst)
	}
	to := r.reach(c, dst)
	// A caller with no sender tag has no path to another relay.
	if to.s != nil && to.s.home != "" && !r.trunked(c) {
		to = owner{}
	}
	if to.s == nil {
		return rpc.Errorf(rpc.NotFound, "no route to %s", dst)
	}
	twin := r.twinOf(c)
	home := to.s.home
	for _, spi := range in.GetSpis() {
		w := c.rows[spi]
		if w != nil && (w.vpc != key || w.dst != dst) {
			return rpc.Errorf(rpc.AlreadyExists, "SPI %#x is held for another destination", spi)
		}
		if home != "" && r.spiTaken(home, spi, w) {
			return rpc.Errorf(rpc.AlreadyExists, "SPI %#x is in use at relay %q", spi, home)
		}
		// Forward finds the sender of a packet from its socket and its SPI.
		if twin != nil {
			if w := twin.rows[spi]; w != nil && !now.After(w.expires) {
				return rpc.Errorf(rpc.AlreadyExists, "SPI %#x is held by another session on this socket", spi)
			}
		}
	}
	for i, spi := range in.GetSpis() {
		w := c.rows[spi]
		if w == nil {
			w = &row{sender: c, spi: spi, vpc: key, dst: dst}
			if r.cfg.LaneRate > 0 {
				w.meter = rate.NewLimiter(rate.Limit(r.cfg.LaneRate), r.cfg.LaneBurst)
			}
			c.rows[spi] = w
		}
		if w.receiver != to.s || w.att != to.att {
			r.aim(w, to)
		}
		w.lane, w.saLane = laneAt(lanes, i), laneAt(saLanes, i)
		w.expires = now.Add(ttl)
		w.lastUsed.Store(now.UnixNano())
		// The other relay gets each new end time of the row.
		r.tellRow(w)
	}
	r.markXDP(c)
	return nil
}

// checkLanes checks a lane list of RegisterSPI: empty, or one lane of at most
// MaxLaneSources for each of n SPIs.
func checkLanes(name string, lanes []uint32, n int) error {
	if len(lanes) != 0 && len(lanes) != n {
		return rpc.Errorf(rpc.InvalidArgument, "%d %s for %d SPIs", len(lanes), name, n)
	}
	for _, l := range lanes {
		if l > MaxLaneSources {
			return rpc.Errorf(rpc.InvalidArgument, "%s %d is above %d", name, l, MaxLaneSources)
		}
	}
	return nil
}

// laneAt returns lane i of a checked lane list, or 0 when it is empty.
func laneAt(lanes []uint32, i int) int {
	if len(lanes) == 0 {
		return 0
	}
	return int(lanes[i])
}

// UnregisterSPI removes rows of the caller. SPIs with no row are ignored. The
// relay of a receiver on another relay learns that the row ended.
func (srv *Server) UnregisterSPI(ctx context.Context, in *dp.UnregisterSPIRequest) (*emptypb.Empty, error) {
	c, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, srv.R.unregisterSPI(c, in)
}

func (r *Router) unregisterSPI(c *Session, in *dp.UnregisterSPIRequest) error {
	key, err := c.vpc(in.GetVpc())
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, spi := range in.GetSpis() {
		if w := c.rows[spi]; w != nil && w.vpc == key {
			r.removeRow(w)
		}
	}
	return nil
}
