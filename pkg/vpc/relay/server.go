// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"sync"

	"github.com/quic-go/quic-go"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// Network is the data of one VPC that sessions and attaches need.
type Network struct {
	// ID is the 24-bit network ID, the VNI on the wire.
	ID uint32
	// Name is the name of the VPC network object. The stats of an attachment
	// have it.
	Name             string
	MTU              uint32 // Zero means 1280.
	DNSServers       []string
	DNSSearchDomains []string
}

// Networks gives the VPC data from the relay snapshot. The relay host
// implements it.
type Networks interface {
	// Network returns the VPC. An error rejects new sessions and attaches in it.
	Network(project, vpcUID string) (Network, error)
}

// Server serves the Relay service on relay sessions (ALPN apoxy-vpc/2).
// Set the fields before Serve.
type Server struct {
	dp.UnimplementedRelayServer

	R         *Router
	Networks  Networks
	Addresses Addresses
	// Cert returns the relay TLS cert. Its key signs AttachmentGrants, and
	// each grant carries its chain.
	Cert func() (*tls.Certificate, error)
	// RelayID goes in grants. It is a DNS name that the relay cert covers.
	RelayID string

	muxOnce sync.Once
	mux     *rpc.Mux

	mu       sync.Mutex
	draining bool
	active   int           // Connections in ServeConn.
	idle     chan struct{} // Closed when active is 0 during a drain.
}

func (srv *Server) network(vpc VPCKey) (Network, error) {
	if srv.Networks == nil {
		return Network{}, rpc.Errorf(rpc.Unavailable, "relay has no VPC data")
	}
	n, err := srv.Networks.Network(vpc.Project, vpc.UID)
	if err != nil {
		return Network{}, rpc.Errorf(rpc.Unavailable, "VPC %s/%s: %v", vpc.Project, vpc.UID, err)
	}
	if n.MTU == 0 {
		n.MTU = vpcv1alpha1.DefaultMTU
	}
	// The API server checks the MTU only when the spec changes, so a network can have more.
	n.MTU = min(n.MTU, vpcv1alpha1.MaxMTU)
	return n, nil
}

// Serve accepts relay sessions on ln until ctx ends or ln closes. The
// listener must use Router.TLSConfig and enable datagrams.
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

// ServeConn serves one relay session until the connection closes, then
// removes it. A host that shares its listener calls it for apoxy-vpc/2.
func (srv *Server) ServeConn(ctx context.Context, qc quic.Connection) {
	if !srv.enter() {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN), "relay is draining")
		return
	}
	defer srv.leave()
	srv.muxOnce.Do(func() {
		srv.mux = rpc.NewMux()
		dp.RegisterRelayServer(srv.mux, srv)
	})
	conn := rpc.NewConn(qc, srv.mux)
	s, err := srv.R.AddSession(conn)
	if err != nil {
		slog.Info("Rejected relay session", "remote", qc.RemoteAddr(), "error", err)
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_CERT), "agent cert rejected")
		return
	}
	if qc.ConnectionState().SupportsDatagrams {
		go srv.R.serveDatagrams(s, qc)
	}
	_ = conn.Serve(ctx)
	_ = qc.CloseWithError(quic.ApplicationErrorCode(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED), "")
	srv.R.removeSession(s)
	srv.R.closeBridge(s)
	atts, last := srv.R.endAttachments(s)
	for i, a := range atts {
		srv.R.ended(last[i])
		srv.Addresses.Release(a)
	}
}

// Drain refuses new sessions and tells each session to move, to alternates if it
// gets routes of other relays. It returns when all end, or closes them at ctx end.
func (srv *Server) Drain(ctx context.Context, alternates []*dp.RelayRef) {
	srv.mu.Lock()
	srv.draining = true
	idle := make(chan struct{})
	if srv.active == 0 {
		close(idle)
	} else {
		srv.idle = idle
	}
	srv.mu.Unlock()
	r := srv.R
	r.mu.Lock()
	sessions := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		sessions = append(sessions, s)
		d := &dp.Drain{}
		// An agent with one session for each relay must stay on this relay.
		if s.sync.meshRoutes {
			d.Alternates = alternates
		}
		s.queue(&dp.SessionResponse{Msg: &dp.SessionResponse_Drain{Drain: d}})
	}
	r.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
		for _, s := range sessions {
			s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_DRAIN, "relay stopped")
		}
		<-idle
	}
}
