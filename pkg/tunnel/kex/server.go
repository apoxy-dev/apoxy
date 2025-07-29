package kex

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	maxVNI = 1 << 24 // 24-bit space
	// Default MTU for tunnels
	// Physical MTU - 40 (IPv6) - 8 (UDP) - 32 (Geneve+opts) - 16 (AES-GCM Tag)
	mtu = 1404
	// Keys expire after 24h no matter how many packets are sent.
	// This is to preserve forward secrecy.
	keyExpiry = 24 * time.Hour
)

type clientSession struct {
	vni       uint32
	addresses []netip.Prefix
	keyEpoch  int
}

// TODO: client session timeout management, cleanup, etc.
// TODO: persistence between restarts, bboltdb?
// TODO: securely persist keys etc
type Server struct {
	vniPool        *VNIPool
	ipam           tunnet.IPAM
	sessionMu      sync.Mutex
	clientSessions map[string]clientSession
}

func NewServer(ctx context.Context) *Server {
	return &Server{
		vniPool:        NewVNIPool(maxVNI),
		ipam:           tunnet.NewIPAMv4(ctx),
		clientSessions: make(map[string]clientSession),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	switch {
	// POST /network
	case r.Method == http.MethodPost && len(parts) == 1 && parts[0] == "network":
		s.handleConnect(w, r)
		return

	// DELETE /network/{vni}
	case r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "network":
		vni, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "Invalid VNI", http.StatusBadRequest)
			return
		}
		s.handleDisconnect(w, r, uint32(vni))
		return

	// POST /network/{vni}/renewkeys
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "network" && parts[2] == "renewkeys":
		vni, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "Invalid VNI", http.StatusBadRequest)
			return
		}
		s.handleRenewKeys(w, r, uint32(vni))
		return

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID, ok := checkAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vni, err := s.vniPool.Allocate()
	if err != nil {
		http.Error(w, "No virtual networks IDs available", http.StatusServiceUnavailable)
		return
	}

	addr, err := s.ipam.Allocate()
	if err != nil {
		http.Error(w, "Failed to allocate address", http.StatusInternalServerError)
		s.vniPool.Free(vni)
		return
	}

	s.sessionMu.Lock()
	s.clientSessions[clientID] = clientSession{
		vni:       vni,
		addresses: []netip.Prefix{addr},
		keyEpoch:  1,
	}
	s.sessionMu.Unlock()

	resp := ConnectResponse{
		NetworkID: int(vni),
		Keys: Keys{
			Epoch:     1,
			Send:      randomKey(),
			Recv:      randomKey(),
			ExpiresAt: time.Now().Add(keyExpiry),
		},
		MTU:       mtu,
		Addresses: []string{addr.String()},
		Routes:    []Route{{Prefix: tunnet.IPv4CidrPrefix}},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request, vni uint32) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID, ok := checkAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.sessionMu.Lock()
	session, ok := s.clientSessions[clientID]
	if !ok || session.vni != vni {
		s.sessionMu.Unlock()
		http.Error(w, "Invalid or unauthorized NetworkID", http.StatusForbidden)
		return
	}
	delete(s.clientSessions, clientID)
	s.sessionMu.Unlock()

	s.vniPool.Free(session.vni)
	for _, addr := range session.addresses {
		s.ipam.Release(addr)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRenewKeys(w http.ResponseWriter, r *http.Request, vni uint32) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID, ok := checkAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.sessionMu.Lock()
	session, ok := s.clientSessions[clientID]
	if !ok || session.vni != vni {
		s.sessionMu.Unlock()
		http.Error(w, "Invalid or unauthorized NetworkID", http.StatusForbidden)
		return
	}

	// Increment the epoch and update the session
	session.keyEpoch++
	s.clientSessions[clientID] = session
	s.sessionMu.Unlock()

	newKeys := Keys{
		Epoch:     session.keyEpoch,
		Send:      randomKey(),
		Recv:      randomKey(),
		ExpiresAt: time.Now().Add(keyExpiry),
	}

	resp := RenewKeysResponse{
		Keys: newKeys,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func randomKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

func checkAuth(_ *http.Request) (string, bool) {
	// Placeholder for actual authentication logic, assume a JWT bearer token with some fields.
	return "client-id", true
}
