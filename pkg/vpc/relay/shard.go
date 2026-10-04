// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// serveShard runs the Session call of a shard. It joins s to the session of
// the attachment, sends Welcome and waits until the call or the owner ends.
func (srv *Server) serveShard(ctx context.Context, s *Session, sh *dp.Shard, st rpc.BidiStreamServer[dp.SessionRequest, dp.SessionResponse]) error {
	owner, old, err := srv.R.joinShard(s, sh.GetAttachmentId(), sh.GetIndex())
	if err != nil {
		return err
	}
	if old != nil {
		old.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "shard replaced")
	}
	defer func() {
		srv.R.leaveShard(s)
		s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "shard ended")
	}()
	if err := st.Send(&dp.SessionResponse{Msg: &dp.SessionResponse_Welcome{Welcome: &dp.Welcome{
		ReflexiveAddress: s.remote().String(),
	}}}); err != nil {
		return err
	}
	recvDone := make(chan error, 1)
	go func() {
		_, err := st.Recv()
		if err == nil {
			err = rpc.Errorf(rpc.InvalidArgument, "unexpected message on a shard")
		}
		recvDone <- err
	}()
	select {
	case err := <-recvDone:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-owner.conn.QUIC().Context().Done():
		return nil
	}
}

// joinShard makes s shard index of the session that has the attachment. It
// returns that session and the shard that s replaces. A shard has no routes,
// rows, Sync or source address.
func (r *Router) joinShard(s *Session, attachment string, index uint32) (owner, old *Session, err error) {
	if index == 0 || index >= peerconn.MaxShards {
		return nil, nil, rpc.Errorf(rpc.InvalidArgument, "shard index %d is not from 1 to %d", index, peerconn.MaxShards-1)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return nil, nil, rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	if s.sync.open || len(s.routes) > 0 || len(s.rows) > 0 {
		return nil, nil, rpc.Errorf(rpc.FailedPrecondition, "connection already has a Session call, routes or SPI rows")
	}
	d := r.domains[s.id.VPC]
	for m := range d.members {
		if slices.ContainsFunc(m.attachments, func(a *Attachment) bool { return a.ID == attachment }) {
			owner = m
			break
		}
	}
	if owner == nil {
		return nil, nil, rpc.Errorf(rpc.NotFound, "no open session has attachment %q", attachment)
	}
	if owner.id != s.id {
		return nil, nil, rpc.Errorf(rpc.PermissionDenied, "attachment %q has another agent identity", attachment)
	}
	// The shard leaves the domain and gives its source address to the owner.
	r.markXDP(s)
	delete(d.members, s)
	clear(s.sync.routes)
	for _, a := range []netip.AddrPort{s.addr, s.prev} {
		if r.bySource[a] == s {
			delete(r.bySource, a)
		}
	}
	s.addr, s.prev = netip.AddrPort{}, netip.AddrPort{}
	for _, a := range []netip.AddrPort{owner.addr, owner.prev} {
		if a.IsValid() && r.bySource[a] == nil {
			r.bySource[a] = owner
		}
	}
	r.markXDP(owner)
	s.sync.open = true
	s.shardOf = owner
	old = owner.shards[index]
	owner.shards[index] = s
	return owner, old, nil
}

// leaveShard removes shard s from its owner.
func (r *Router) leaveShard(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := s.shardOf; o != nil {
		for i, sh := range o.shards {
			if sh == s {
				o.shards[i] = nil
			}
		}
	}
}
