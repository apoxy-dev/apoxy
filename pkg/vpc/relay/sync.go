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
	open    bool           // A Session call runs.
	mode    dp.Mode        // From Hello.
	ref     *dp.VPCRef     // VPC of the session, with the network ID.
	routes  map[route]bool // Route changes: true adds, false removes.
	out     []*dp.SessionResponse
	noRoute map[netip.Addr]time.Time // Last NoRoute for each address.
	rev     uint64                   // Revision of the last RouteDelta.
	acked   uint64
	dropped uint64
	// connected is true after the agent reports its time to connect.
	connected bool
	// report is the last receive report of the relay SAs. A new one replaces it.
	report *dp.RxReport
}

// queueRoute adds a change of the route rt of owner to the sync queue. A
// session gets no routes of its own subject. A change cancels the opposite
// change that waits. Router.mu must be held.
func (s *Session) queueRoute(rt route, owner *Session, add bool) {
	if owner.id.ID == s.id.ID {
		return
	}
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

func (r *Router) noRoute(s *Session, dst netip.Addr, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed || s.sync.ref == nil || now.Sub(s.sync.noRoute[dst]) < noRouteInterval {
		return
	}
	s.sync.noRoute[dst] = now
	s.queue(&dp.SessionResponse{Msg: &dp.SessionResponse_NoRoute{NoRoute: &dp.NoRoute{Vpc: s.sync.ref, Address: dst.String()}}})
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
	if len(s.sync.routes) > 0 || s.sync.rev == 0 {
		s.sync.rev++
		d := &dp.RouteDelta{Rev: s.sync.rev}
		for rt, add := range s.sync.routes {
			m := &dp.Route{Vpc: s.sync.ref, Prefix: rt.prefix.String(), Origin: rt.origin}
			if add {
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
	if err := srv.R.openSync(s, mode, ref); err != nil {
		return err
	}
	sessionsTotal.WithLabelValues(modeLabel(mode), reasonLabel(hello)).Inc()
	// The session ends with the call. The close carries the error.
	defer func() {
		msg := "Session call ended"
		if err != nil {
			msg = err.Error()
		}
		s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, msg)
	}()
	if err := st.Send(&dp.SessionResponse{Msg: &dp.SessionResponse_Welcome{Welcome: &dp.Welcome{
		ReflexiveAddress: srv.R.Addr(s).String(),
		MaxLanes:         srv.R.maxLanes(mode),
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
	if mode == dp.Mode_MODE_PSP {
		m, err := srv.R.offer(s, n, time.Now())
		if err != nil {
			slog.Warn("Failed to give relay SAs to an agent", "agent", s.id.ID, "error", err)
		} else if m != nil {
			if err := st.Send(m); err != nil {
				return err
			}
		}
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

// openSync marks the Session call of s as open. A session has at most one.
func (r *Router) openSync(s *Session, mode dp.Mode, ref *dp.VPCRef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if s.sync.open {
		return rpc.Errorf(rpc.FailedPrecondition, "session already has a Session call")
	}
	s.sync.open, s.sync.mode, s.sync.ref = true, mode, ref
	r.takeSource(s)
	s.notify()
	return nil
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
		case *dp.SessionRequest_Moved:
			r.watchAddr(s)
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
	mode := s.sync.mode
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
