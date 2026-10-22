// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Server serves the Relay service on agent connections (ALPN apoxy-vpc/2) for the Router R. Set
// R before Serve.
type Server struct {
	dpv1.UnimplementedRelayServer

	R *Router

	muxOnce sync.Once
	mux     *rpc.Mux

	mu       sync.Mutex
	draining bool
	active   int           // Connections in ServeConn.
	idle     chan struct{} // Closed when active is 0 during a drain.
}

type linkKey struct{}

// linkOf returns the agent connection of a call.
func linkOf(ctx context.Context) (*link, error) {
	if l, ok := ctx.Value(linkKey{}).(*link); ok {
		return l, nil
	}
	return nil, rpc.Errorf(rpc.Unauthenticated, "no authenticated relay session")
}

// Serve accepts agent connections on ln until ctx ends or ln closes. The listener must use
// Router.TLSConfig and enable datagrams.
func (srv *Server) Serve(ctx context.Context, ln *quic.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		qc, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { srv.ServeConn(ctx, qc) })
	}
}

// enter counts a new connection. It returns false during a drain.
func (srv *Server) enter() bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.draining {
		return false
	}
	srv.active++
	return true
}

func (srv *Server) leave() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.active--
	if srv.active == 0 && srv.idle != nil {
		close(srv.idle)
		srv.idle = nil
	}
}

// ServeConn serves one agent connection until it closes and its process and hook tasks ended. A
// host that shares its listener calls it for apoxy-vpc/2.
func (srv *Server) ServeConn(ctx context.Context, qc quic.Connection) {
	if !srv.enter() {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), "relay is draining")
		return
	}
	defer srv.leave()
	srv.muxOnce.Do(func() {
		srv.mux = rpc.NewMux()
		dpv1.RegisterRelayServer(srv.mux, srv)
	})
	l, err := srv.newLink(qc)
	if err != nil {
		slog.Info("Rejected an agent connection", "remote", qc.RemoteAddr(), "error", err)
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_CERT), "agent cert rejected")
		return
	}
	_ = rpc.NewConn(qc, srv.mux).Serve(context.WithValue(ctx, linkKey{}, l))
	_ = qc.CloseWithError(quic.ApplicationErrorCode(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED), "")
	if l.owned.Load() {
		<-l.finished
	}
}

// newLink checks the agent cert of qc and returns its link.
func (srv *Server) newLink(qc quic.Connection) (*link, error) {
	tc := qc.ConnectionState().TLS
	if tc.NegotiatedProtocol != dpv1.ALPNRelay {
		return nil, fmt.Errorf("ALPN %q is not %s", tc.NegotiatedProtocol, dpv1.ALPNRelay)
	}
	now := time.Now()
	id, err := checkCert(srv.R.cfg.Trust, tc.PeerCertificates, now)
	if err != nil {
		return nil, fmt.Errorf("agent cert rejected: %w", err)
	}
	probe, err := p2p.NewProbeKeys(tc)
	if err != nil {
		return nil, err
	}
	return &link{
		qc:         qc,
		vpc:        VPCKey{Project: id.Project, UID: id.VPC},
		subject:    id.String(),
		chain:      tc.PeerCertificates,
		verified:   now,
		probe:      probe,
		trace:      traceOf(qc.Context()),
		finished:   make(chan struct{}),
		streamDone: make(chan struct{}),
	}, nil
}

// Drain refuses new connections, makes the candidates of each connection draining, then tells
// each agent to move. It returns when each connection and its hook tasks ended, or closes the
// connections at ctx end.
func (srv *Server) Drain(ctx context.Context, alternates []*dpv1.RelayRef) {
	srv.mu.Lock()
	srv.draining = true
	idle := make(chan struct{})
	if srv.active == 0 {
		close(idle)
	} else {
		srv.idle = idle
	}
	srv.mu.Unlock()
	srv.R.box.send(drainEv{alternates: alternates})
	select {
	case <-idle:
	case <-ctx.Done():
		srv.R.box.send(endAllEv{code: dpv1.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN, msg: "relay stopped"})
		<-idle
	}
}

// Session runs the Session call: Hello, then Welcome, Config and the route table for a main
// connection, or Welcome for an extra connection. The process of the connection sends the rest.
func (srv *Server) Session(ctx context.Context, st sessionStream) error {
	l, err := linkOf(ctx)
	if err != nil {
		return err
	}
	if !l.session.CompareAndSwap(false, true) {
		return rpc.Errorf(rpc.FailedPrecondition, "session already has a Session call")
	}
	first, err := st.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return rpc.Errorf(rpc.InvalidArgument, "first message is not Hello")
	}
	if got, least := hello.GetVersion().GetRevision(), srv.R.ver.GetMinRevision(); got < least {
		msg := fmt.Sprintf("agent revision %d is below the relay minimum %d", got, least)
		slog.Info("Refused the Session call of an old agent", "agent", l.subject,
			"revision", got, "min_revision", least, "build", buildLabel(hello.GetVersion().GetBuild()))
		l.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UPGRADE, msg)
		return rpc.Errorf(rpc.FailedPrecondition, "%s", msg)
	}
	if x := hello.GetShard(); x != nil {
		if i := x.GetIndex(); i == 0 || i >= peerconn.MaxConns {
			return rpc.Errorf(rpc.InvalidArgument, "extra connection index %d is not from 1 to %d", i, peerconn.MaxConns-1)
		}
	} else if m := hello.GetMode(); m != dpv1.Mode_MODE_PSP && m != dpv1.Mode_MODE_QUIC {
		return rpc.Errorf(rpc.InvalidArgument, "Hello needs a mode")
	}
	res := make(chan error, 1)
	if !srv.R.box.send(accepted{l: l, st: st, hello: hello, res: res}) {
		return rpc.Errorf(rpc.Unavailable, "relay stopped")
	}
	// The root answers each accepted call, also at its end.
	if err := <-res; err != nil {
		return err
	}
	if hello.GetShard() == nil {
		sessionsTotal.WithLabelValues(modeLabel(hello.GetMode()), reasonLabel(hello)).Inc()
		sessionVersions.WithLabelValues(versionLabels.of(hello.GetVersion())...).Inc()
	}
	select {
	case <-l.streamDone:
	case <-ctx.Done():
	}
	return nil
}

// Attach adds an attachment to the connection: addresses from Addresses, and routes in the VPC.
func (srv *Server) Attach(ctx context.Context, in *dpv1.AttachRequest) (*dpv1.AttachResponse, error) {
	out, err := call(ctx, callAttach, in, "attach needs a Session call with Hello first")
	if err != nil {
		return nil, err
	}
	return out.(*dpv1.AttachResponse), nil
}

// Detach removes an attachment of the connection: its routes, and its addresses.
func (srv *Server) Detach(ctx context.Context, in *dpv1.DetachRequest) (*emptypb.Empty, error) {
	if _, err := call(ctx, callDetach, in, "detach needs a Session call with Hello first"); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// Rekey applies a key change of the agent to the SAs that the relay seals packets to the agent
// with. It changes a connection in QUIC mode to PSP mode.
func (srv *Server) Rekey(ctx context.Context, in *dpv1.KeysRequest) (*dpv1.KeysResponse, error) {
	out, err := call(ctx, callRekey, in, "Rekey needs a Session call")
	if err != nil {
		return nil, err
	}
	return out.(*dpv1.KeysResponse), nil
}

// RegisterLanes sets the lane ports of the connection.
func (srv *Server) RegisterLanes(ctx context.Context, in *dpv1.RegisterLanesRequest) (*emptypb.Empty, error) {
	if _, err := call(ctx, callLanes, in, "session has no source address"); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// call gives a unary call to the A of the connection and waits for its answer. noA is the error
// message for a connection with no A.
func call(ctx context.Context, kind callKind, in proto.Message, noA string) (proto.Message, error) {
	l, err := linkOf(ctx)
	if err != nil {
		return nil, err
	}
	if l.extra.Load() {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "an extra connection carries only data")
	}
	box := l.a.Load()
	if box == nil {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "%s", noA)
	}
	res := make(chan callResult, 1)
	if !box.send(aCall{kind: kind, in: in, res: res}) {
		return nil, rpc.Errorf(rpc.Unavailable, "relay connection closed")
	}
	select {
	case r := <-res:
		return r.out, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func addrPort(a net.Addr) netip.AddrPort {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
