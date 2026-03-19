package bfdl

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"
)

// OnAliveFunc is called on each valid BFD packet received from a client.
type OnAliveFunc func(ctx context.Context, connID string)

// serverSession wraps a Session with server-side metadata.
type serverSession struct {
	*Session
	connID   string
	peerAddr net.UDPAddr
}

// Server listens for BFD packets from all tunnel clients and manages
// per-client sessions. It runs on the kernel network stack, bound to
// [listenAddr]:3784.
//
// The server both responds to incoming BFD packets (RX loop) and
// independently sends periodic BFD probes to each client (TX loop),
// so both directions of the data plane are exercised.
type Server struct {
	listenAddr netip.Addr
	onAlive    OnAliveFunc

	mu       sync.RWMutex
	sessions map[uint32]*serverSession    // localDiscr -> session
	addrIdx  map[netip.Addr]*serverSession // overlay addr -> session (initial lookup)
	peers    map[netip.Addr]string         // registered peers: overlay addr -> connID

	// blackholed tracks connections for which the server drops all BFD
	// traffic — no responses, no probes, no onAlive callbacks. The
	// client's detect timer will fire after 30s, transitioning its
	// session to Down. Used for integration testing.
	blackholed map[string]struct{}
}

// NewServer creates a new BFD server.
func NewServer(listenAddr netip.Addr, onAlive OnAliveFunc) *Server {
	return &Server{
		listenAddr: listenAddr,
		onAlive:    onAlive,
		sessions:   make(map[uint32]*serverSession),
		addrIdx:    make(map[netip.Addr]*serverSession),
		peers:      make(map[netip.Addr]string),
		blackholed: make(map[string]struct{}),
	}
}

// SuppressHeartbeat blackholes all BFD traffic for the given connection:
// the server stops sending probes, stops responding to the client's packets,
// and stops firing the onAlive callback. The client's detect timer will
// fire after detectMult * txInterval (default 30s).
func (s *Server) SuppressHeartbeat(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blackholed[connID] = struct{}{}
	slog.Info("BFD blackholed", "connID", connID)
}

// ResumeHeartbeat removes the blackhole for a connection, restoring
// normal BFD traffic.
func (s *Server) ResumeHeartbeat(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blackholed, connID)
	slog.Info("BFD un-blackholed", "connID", connID)
}

// AddPeer registers a client for BFD. Called when setupConn assigns an
// overlay address.
func (s *Server) AddPeer(addr netip.Addr, connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[addr] = connID
	slog.Info("BFD peer registered", "addr", addr, "connID", connID)
}

// RemovePeer tears down a client's BFD session. Called on connection close.
func (s *Server) RemovePeer(addr netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.peers, addr)

	ss, ok := s.addrIdx[addr]
	if !ok {
		return
	}

	// Update gauge for the removed session's state.
	BFDSessionsActive.WithLabelValues("server", ss.State().String()).Dec()

	delete(s.addrIdx, addr)
	delete(s.sessions, ss.localDiscr)
	delete(s.blackholed, ss.connID)
	slog.Info("BFD peer removed", "addr", addr, "connID", ss.connID)
}

// Start binds UDP on [listenAddr]:3784 and runs the receive and transmit loops.
// Blocks until ctx is canceled.
func (s *Server) Start(ctx context.Context) error {
	addr := net.UDPAddr{
		IP:   s.listenAddr.AsSlice(),
		Port: BFDPort,
		Zone: s.listenAddr.Zone(),
	}

	conn, err := net.ListenUDP("udp6", &addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	slog.Info("BFD server listening", "addr", addr.String())

	// Close the socket when context is canceled.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// TX loop: send periodic unsolicited BFD probes to every session
	// and check for detect-timer expirations.
	go s.txLoop(ctx, conn)

	// RX loop: receive and respond to incoming BFD packets.
	buf := make([]byte, 128)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("BFD read error", "error", err)
			continue
		}

		pkt, err := Unmarshal(buf[:n])
		if err != nil {
			slog.Debug("BFD unmarshal error", "error", err, "src", raddr)
			BFDPacketErrors.WithLabelValues("server", "rx").Inc()
			continue
		}

		BFDPacketsRx.WithLabelValues("server").Inc()

		resp, connID := s.handlePacket(pkt, raddr)

		// Check blackhole: drop response and skip onAlive.
		s.mu.RLock()
		_, hole := s.blackholed[connID]
		s.mu.RUnlock()
		if hole {
			continue
		}

		if resp != nil {
			out := Marshal(resp)
			if _, err := conn.WriteToUDP(out, raddr); err != nil {
				slog.Warn("BFD write error", "error", err, "dst", raddr)
				BFDPacketErrors.WithLabelValues("server", "tx").Inc()
			} else {
				BFDPacketsTx.WithLabelValues("server").Inc()
			}
		}

		if connID != "" && s.onAlive != nil {
			s.onAlive(ctx, connID)
		}
	}
}

// txLoop sends periodic BFD control packets to all active sessions and
// checks for detect-timer expirations.
func (s *Server) txLoop(ctx context.Context, conn *net.UDPConn) {
	ticker := time.NewTicker(DefaultTxInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			type txTarget struct {
				pkt    *Packet
				addr   net.UDPAddr
				connID string
			}
			targets := make([]txTarget, 0, len(s.sessions))
			for _, ss := range s.sessions {
				// Check detect timer expiration.
				if ss.Expired() && ss.State() == StateUp {
					old := ss.State()
					ss.mu.Lock()
					ss.localState = StateDown
					ss.remoteDiscr = 0
					ss.mu.Unlock()
					slog.Warn("BFD server session expired",
						"connID", ss.connID,
						"peerAddr", ss.peerAddr.String())
					BFDDetectTimeouts.WithLabelValues("server").Inc()
					BFDSessionsActive.WithLabelValues("server", old.String()).Dec()
					BFDSessionsActive.WithLabelValues("server", StateDown.String()).Inc()
					BFDStateTransitions.WithLabelValues("server", old.String(), StateDown.String()).Inc()
				}

				// Skip blackholed connections.
				if _, hole := s.blackholed[ss.connID]; hole {
					continue
				}

				targets = append(targets, txTarget{
					pkt:    ss.BuildTx(),
					addr:   ss.peerAddr,
					connID: ss.connID,
				})
			}
			s.mu.Unlock()

			for _, t := range targets {
				out := Marshal(t.pkt)
				if _, err := conn.WriteToUDP(out, &t.addr); err != nil {
					slog.Debug("BFD server TX error", "error", err, "dst", t.addr.String())
					BFDPacketErrors.WithLabelValues("server", "tx").Inc()
				} else {
					BFDPacketsTx.WithLabelValues("server").Inc()
				}
			}
		}
	}
}

// handlePacket processes an incoming BFD packet and returns a response.
func (s *Server) handlePacket(pkt *Packet, raddr *net.UDPAddr) (*Packet, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var ss *serverSession

	// Fast path: lookup by YourDiscr (remote knows our discriminator).
	if pkt.YourDiscr != 0 {
		ss = s.sessions[pkt.YourDiscr]
	}

	// Slow path: lookup by source IP (initial packet).
	if ss == nil {
		srcIP, ok := netip.AddrFromSlice(raddr.IP)
		if !ok {
			return nil, ""
		}
		srcIP = srcIP.Unmap()

		ss = s.addrIdx[srcIP]
		if ss == nil {
			// No existing session. Check if peer is registered.
			connID, registered := s.peers[srcIP]
			if !registered {
				return nil, ""
			}

			// Create new session.
			localDiscr := rand.Uint32()
			for localDiscr == 0 || s.sessions[localDiscr] != nil {
				localDiscr = rand.Uint32()
			}

			session := NewSession(localDiscr, DefaultDetectMult, DefaultTxInterval)
			session.SetOnStateChange(func(old, new State) {
				slog.Info("BFD server session state change",
					"connID", connID,
					"from", old.String(),
					"to", new.String())
				BFDSessionsActive.WithLabelValues("server", old.String()).Dec()
				BFDSessionsActive.WithLabelValues("server", new.String()).Inc()
				BFDStateTransitions.WithLabelValues("server", old.String(), new.String()).Inc()
			})
			ss = &serverSession{
				Session:  session,
				connID:   connID,
				peerAddr: *raddr,
			}
			s.sessions[localDiscr] = ss
			s.addrIdx[srcIP] = ss
			BFDSessionsActive.WithLabelValues("server", StateDown.String()).Inc()

			slog.Info("BFD session created",
				"connID", connID,
				"localDiscr", localDiscr,
				"remoteAddr", raddr.String())
		}
	}

	// Update peer address (port may change).
	ss.peerAddr = *raddr

	resp := ss.ProcessRx(pkt)
	return resp, ss.connID
}
