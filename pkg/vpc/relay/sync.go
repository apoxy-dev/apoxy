// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxSyncQueue limits the messages that wait for the Session call.
	maxSyncQueue = 4096
	// noRouteInterval is the minimum time between NoRoute messages for an address.
	noRouteInterval = time.Second
)

// syncState is what the relay still has to send to the agent on Sync.
type syncState struct {
	open   bool           // A Session call runs.
	mode   dp.Mode        // QUIC at Hello. A Rekey call changes it to PSP, and a lost PSP path to QUIC.
	hello  dp.Mode        // The mode of Hello, for the metrics.
	ref    *dp.VPCRef     // VPC of the session, with the network ID.
	mtu    uint32         // MTU of the VPC at Hello, for the relay SAs.
	routes map[route]bool // Route changes: true adds, false removes.
	// standby has the prefixes whose route stays and whose standby list changed.
	standby map[netip.Prefix]struct{}
	out     []*dp.SessionResponse
	noRoute map[netip.Addr]time.Time // Last NoRoute for each address.
	rev     uint64                   // Revision of the last RouteDelta.
	acked   uint64
	dropped uint64
	// connected is true after the agent reports its time to connect.
	connected bool
	// report is the last receive report of the relay SAs. A new one replaces it.
	report *dp.RxReport
	// meshRoutes is true when the agent gets the routes of the attachments of
	// other relays: its revision has them, and its Hello did not refuse them.
	meshRoutes bool
}

// queueRoute adds a change of the route rt to the sync queue. A change cancels
// the opposite change. Router.mu must be held.
func (s *Session) queueRoute(rt route, add bool) {
	if was, ok := s.sync.routes[rt]; ok && was != add {
		delete(s.sync.routes, rt)
	} else {
		s.sync.routes[rt] = add
	}
	s.notify()
}

// queue adds m to the sync queue. Router.mu must be held.
func (s *Session) queue(m *dp.SessionResponse) {
	if len(s.sync.out) >= maxSyncQueue {
		s.sync.dropped++
		return
	}
	s.sync.out = append(s.sync.out, m)
	s.notify()
}

func (s *Session) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// noRoute tells s that the relay cannot reach dst, with the relay to visit if s
// must visit one. home is the member that has the route of dst, or "".
func (r *Router) noRoute(s *Session, dst netip.Addr, home string, now time.Time) {
	visit, ok := r.noRouteVisit(s, dst, home, now)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed || s.sync.ref == nil || now.Sub(s.sync.noRoute[dst]) < noRouteInterval {
		return
	}
	s.sync.noRoute[dst] = now
	s.queue(&dp.SessionResponse{Msg: &dp.SessionResponse_NoRoute{NoRoute: &dp.NoRoute{Vpc: s.sync.ref, Address: dst.String(), HomeRelay: visit}}})
}

// noRouteVisit reports whether s gets a NoRoute for dst now, and the relay that s
// must visit, or nil. It runs for each dropped packet, so it takes no write lock.
func (r *Router) noRouteVisit(s *Session, dst netip.Addr, home string, now time.Time) (*dp.RelayRef, bool) {
	// The address has a route. Its sender gets a NoRoute only to visit a member.
	if t := r.trunk.Load(); home != "" && (t == nil || t.m.awayRef(home) == nil) {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if now.Sub(s.sync.noRoute[dst]) < noRouteInterval {
		return nil, false
	}
	// A sender that Permit denies does not learn the home of the address.
	if home == "" && !r.permit(s.id.VPC, s.id.ID, s.id.VPC, dst) {
		return nil, true
	}
	visit := r.visitRef(s, s.id.VPC, dst, home)
	return visit, home == "" || visit != nil
}

// sweepNoRoute forgets old NoRoute times. Router.mu must be held.
func (s *Session) sweepNoRoute(now time.Time) {
	for a, t := range s.sync.noRoute {
		if now.Sub(t) >= noRouteInterval {
			delete(s.sync.noRoute, a)
		}
	}
}

// takeSync returns the messages that wait for the agent. Route changes
// become one RouteDelta with the next revision. The first RouteDelta has all
// routes of the VPC, and it comes also when the VPC has no routes.
func (r *Router) takeSync(s *Session) []*dp.SessionResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	var msgs []*dp.SessionResponse
	dom := r.domains[s.id.VPC]
	// A route with a new standby list comes again as an add.
	for p := range s.sync.standby {
		if e := s.sees(dom.orderOf(p)); e != nil {
			s.sync.routes[route{p, e.origin}] = true
		}
	}
	clear(s.sync.standby)
	if len(s.sync.routes) > 0 || s.sync.rev == 0 {
		s.sync.rev++
		d := &dp.RouteDelta{Rev: s.sync.rev}
		for rt, add := range s.sync.routes {
			m := &dp.Route{Vpc: s.sync.ref, Prefix: rt.prefix.String(), Origin: rt.origin}
			if add {
				// An agent of an older revision gets one announcer for each prefix.
				if s.version.GetRevision() >= announcerRevision {
					m.Standby = s.standby(dom.orderOf(rt.prefix))
				}
				d.Add = append(d.Add, m)
			} else {
				d.Remove = append(d.Remove, m)
			}
		}
		sortRoutes(d.Add)
		sortRoutes(d.Remove)
		clear(s.sync.routes)
		msgs = append(msgs, &dp.SessionResponse{Msg: &dp.SessionResponse_RouteDelta{RouteDelta: d}})
	}
	msgs = append(msgs, s.sync.out...)
	s.sync.out = nil
	if s.sync.report != nil {
		msgs = append(msgs, &dp.SessionResponse{Msg: &dp.SessionResponse_RxReport{RxReport: s.sync.report}})
		s.sync.report = nil
	}
	return msgs
}

func sortRoutes(rs []*dp.Route) {
	slices.SortFunc(rs, func(a, b *dp.Route) int {
		return cmp.Or(cmp.Compare(a.Prefix, b.Prefix), cmp.Compare(a.Origin, b.Origin))
	})
}

// Session runs the Sync of a relay session: Hello, Welcome, Config, relay SAs,
// routes, NoRoute and Drain to the agent, and Ack and Status from it.
func (srv *Server) Session(ctx context.Context, st rpc.BidiStreamServer[dp.SessionRequest, dp.SessionResponse]) (err error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return err
	}
	first, err := st.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return rpc.Errorf(rpc.InvalidArgument, "first message is not Hello")
	}
	if err := srv.R.checkRevision(s, hello.GetVersion()); err != nil {
		return err
	}
	if sh := hello.GetShard(); sh != nil {
		return srv.serveShard(ctx, s, sh, st)
	}
	mode := hello.GetMode()
	if mode != dp.Mode_MODE_PSP && mode != dp.Mode_MODE_QUIC {
		return rpc.Errorf(rpc.InvalidArgument, "Hello needs a mode")
	}
	n, err := srv.network(s.id.VPC)
	if err != nil {
		return err
	}
	ref := &dp.VPCRef{ProjectId: s.id.VPC.Project, VpcUid: s.id.VPC.UID, NetworkId: n.ID}
	if err := srv.R.openSync(s, mode, ref, n.MTU, hello); err != nil {
		return err
	}
	sessionsTotal.WithLabelValues(modeLabel(mode), reasonLabel(hello)).Inc()
	sessionVersions.WithLabelValues(versionLabels.of(hello.GetVersion())...).Inc()
	// The session ends with the call. The close carries the error.
	defer func() {
		msg := "Session call ended"
		if err != nil {
			msg = err.Error()
		}
		s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, msg)
	}()
	if err := st.Send(&dp.SessionResponse{Msg: &dp.SessionResponse_Welcome{Welcome: &dp.Welcome{
		ReflexiveAddress: s.remote().String(),
		MaxLanes:         uint32(srv.R.cfg.LaneSources),
		Version:          srv.R.ver,
		// The host stays empty: the agent sends to the host that it dialed.
		PspPort: srv.R.pspPort(),
	}}}); err != nil {
		return err
	}
	if err := st.Send(&dp.SessionResponse{Msg: &dp.SessionResponse_Config{Config: &dp.Config{
		Vpc:              ref,
		Mtu:              n.MTU,
		DnsServers:       n.DNSServers,
		DnsSearchDomains: n.DNSSearchDomains,
	}}}); err != nil {
		return err
	}

	recvDone := make(chan error, 1)
	go func() { recvDone <- srv.R.recvSync(s, st) }()
	for {
		select {
		case err := <-recvDone:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-s.wake:
			for _, m := range srv.R.takeSync(s) {
				if err := st.Send(m); err != nil {
					return err
				}
			}
		}
	}
}

// openSync marks the Session call of s as open, and gives s the agent name
// and the instance of its Hello. A session has at most one Session call.
func (r *Router) openSync(s *Session, mode dp.Mode, ref *dp.VPCRef, mtu uint32, hello *dp.Hello) error {
	refused, err := r.startSync(s, mode, ref, mtu, hello)
	if refused > 0 {
		slog.Warn("Refused attachments of other relays with another network ID", "project", s.id.VPC.Project,
			"vpc", s.id.VPC.UID, "network_id", ref.GetNetworkId(), "count", refused)
	}
	return err
}

// startSync does the work of openSync. It returns the number of attachments
// of other relays that have another network ID than ref.
func (r *Router) startSync(s *Session, mode dp.Mode, ref *dp.VPCRef, mtu uint32, hello *dp.Hello) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return 0, rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if s.sync.open {
		return 0, rpc.Errorf(rpc.FailedPrecondition, "session already has a Session call")
	}
	// Each session starts in QUIC mode. A Rekey call changes it to PSP.
	s.sync.open, s.sync.mode, s.sync.hello, s.sync.ref, s.sync.mtu = true, dp.Mode_MODE_QUIC, mode, ref, mtu
	s.name, s.instance = hello.GetName(), hello.GetInstance()
	s.sync.meshRoutes = s.version.GetRevision() >= meshRoutesRevision && !hello.GetLocalRoutesOnly()
	d := r.domain(s.id.VPC)
	// The relay knows the network ID of the VPC from here on.
	refused := r.know(d, ref.GetNetworkId())
	// The routes that s gets depend on its agent and on meshRoutes, so its
	// queue starts again with the values of the Hello.
	d.queueRoutes(s)
	r.takeSource(s)
	return refused, nil
}

// hasHello reports whether the relay accepted the Hello of s. It stays true.
func (r *Router) hasHello(s *Session) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return s.sync.open
}

func (r *Router) recvSync(s *Session, st rpc.BidiStreamServer[dp.SessionRequest, dp.SessionResponse]) error {
	for {
		m, err := st.Recv()
		if err != nil {
			return err
		}
		switch m := m.GetMsg().(type) {
		case *dp.SessionRequest_Ack:
			r.mu.Lock()
			if m.Ack.GetRev() <= s.sync.rev {
				s.sync.acked = max(s.sync.acked, m.Ack.GetRev())
			}
			r.mu.Unlock()
		case *dp.SessionRequest_Status:
			if d := m.Status.GetConnectTime(); d != nil {
				r.reportConnect(s, d.AsDuration())
			}
			r.ReportStatus(s, m.Status)
		case nil:
			slog.Debug("Ignoring an unknown message on a Session call", "agent", s.id.ID)
		default:
			return rpc.Errorf(rpc.InvalidArgument, "unexpected message on Session")
		}
	}
}

// reportConnect records the time to connect of s. Only the first one counts.
func (r *Router) reportConnect(s *Session, d time.Duration) {
	r.mu.Lock()
	first := !s.sync.connected
	s.sync.connected = true
	mode := s.sync.hello
	r.mu.Unlock()
	if first {
		connectSeconds.WithLabelValues(modeLabel(mode)).Observe(d.Seconds())
	}
}

// SyncStats are the Sync counters of one session.
type SyncStats struct {
	Rev, Acked uint64
	Dropped    uint64
}

func (r *Router) SyncStats(s *Session) SyncStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return SyncStats{Rev: s.sync.rev, Acked: s.sync.acked, Dropped: s.sync.dropped}
}
