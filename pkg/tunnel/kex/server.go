package kex

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/julienschmidt/httprouter"
	"gvisor.dev/gvisor/pkg/tcpip"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

type virtualNetwork struct {
	vni                 uint32
	addresses           []netip.Prefix
	currentKeyEpoch     int
	currentKeyExpiresAt time.Time
}

// TODO: persistence between restarts, bboltdb, distributed? (prob. backed by the kube API)
type Server struct {
	handler     *icx.Handler
	validator   token.JWTValidator
	vniPool     *VNIPool    // todo: persist this?
	ipam        tunnet.IPAM // todo: persist this?
	networks    sync.Map
	keyLifespan time.Duration
}

func NewServer(ctx context.Context, handler *icx.Handler, validator token.JWTValidator, keyLifespan time.Duration) *Server {
	return &Server{
		handler:     handler,
		validator:   validator,
		vniPool:     NewVNIPool(),
		ipam:        tunnet.NewIPAMv4(ctx),
		keyLifespan: keyLifespan,
	}
}

// Start any necessary background tasks, e.g., cleanup of expired virtual networks.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.CleanupExpiredNetworks()
			}
		}
	}()

	return nil
}

func (s *Server) Routes() http.Handler {
	r := httprouter.New()

	r.POST("/network", s.withAuth(s.handleConnect))
	r.DELETE("/network/:vni", s.withAuth(s.handleDisconnect))
	r.PUT("/network/:vni/renewkeys", s.withAuth(s.handleRenewKeys))

	return r
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	clientID := ps.ByName("clientID")
	if clientID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	remoteAddrStr := req.Address
	if remoteAddrStr == "" {
		// Use the remote address of the request if no address is provided.
		remoteAddrStr = r.RemoteAddr
	}

	remoteAddrPort, err := netip.ParseAddrPort(remoteAddrStr)
	if err != nil {
		http.Error(w, "Invalid remote address format", http.StatusBadRequest)
		return
	}

	var remoteAddr tcpip.FullAddress
	if remoteAddrPort.Addr().Is4() {
		remoteAddr = tcpip.FullAddress{Addr: tcpip.AddrFrom4(remoteAddrPort.Addr().As4()), Port: remoteAddrPort.Port()}
	} else if remoteAddrPort.Addr().Is6() {
		remoteAddr = tcpip.FullAddress{Addr: tcpip.AddrFrom16(remoteAddrPort.Addr().As16()), Port: remoteAddrPort.Port()}
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

	sendKey, err := randomKey()
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	recvKey, err := randomKey()
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	keys := Keys{
		Epoch:     1,
		Send:      sendKey,
		Recv:      recvKey,
		ExpiresAt: time.Now().Add(s.keyLifespan),
	}

	entryRaw, _ := s.networks.LoadOrStore(clientID, &sync.Map{})
	entry := entryRaw.(*sync.Map)

	entry.Store(vni, virtualNetwork{
		vni:                 vni,
		addresses:           []netip.Prefix{addr},
		currentKeyEpoch:     keys.Epoch,
		currentKeyExpiresAt: keys.ExpiresAt,
	})

	resp := ConnectResponse{
		NetworkID: int(vni),
		Keys:      keys,
		MTU:       icx.MTU(1500),
		Addresses: []string{addr.String()},
		Routes:    []Route{{Prefix: tunnet.IPv4CidrPrefix}},
	}

	if err := s.handler.AddVirtualNetwork(uint(vni), &remoteAddr, []netip.Prefix{addr}, uint32(keys.Epoch),
		keys.Send, keys.Recv, keys.ExpiresAt); err != nil {
		http.Error(w, "Failed to add virtual network", http.StatusInternalServerError)
		entry.Delete(vni)
		s.vniPool.Free(vni)
		_ = s.ipam.Release(addr)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	clientID := ps.ByName("clientID")
	if clientID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vniStr := ps.ByName("vni")
	vni, err := strconv.ParseUint(vniStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid NetworkID", http.StatusBadRequest)
		return
	}

	entryRaw, ok := s.networks.Load(clientID)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	entry := entryRaw.(*sync.Map)

	virtNetRaw, ok := entry.Load(uint32(vni))
	if !ok {
		http.Error(w, "Invalid or unauthorized NetworkID", http.StatusForbidden)
		return
	}
	virtNet := virtNetRaw.(virtualNetwork)

	entry.Delete(uint32(vni))

	s.vniPool.Free(virtNet.vni)
	for _, addr := range virtNet.addresses {
		_ = s.ipam.Release(addr)
	}

	if err := s.handler.RemoveVirtualNetwork(uint(vni)); err != nil {
		http.Error(w, "Failed to remove virtual network", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRenewKeys(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	clientID := ps.ByName("clientID")
	if clientID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vniStr := ps.ByName("vni")
	vni, err := strconv.ParseUint(vniStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid NetworkID", http.StatusBadRequest)
		return
	}

	sendKey, err := randomKey()
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	recvKey, err := randomKey()
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	entryRaw, ok := s.networks.Load(clientID)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	entry := entryRaw.(*sync.Map)

	virtNetRaw, ok := entry.Load(uint32(vni))
	if !ok {
		http.Error(w, "Invalid or unauthorized NetworkID", http.StatusForbidden)
		return
	}
	virtNet := virtNetRaw.(virtualNetwork)

	if !ok {
		http.Error(w, "Invalid or unauthorized NetworkID", http.StatusForbidden)
		return
	}

	virtNet.currentKeyEpoch++
	virtNet.currentKeyExpiresAt = time.Now().Add(s.keyLifespan)
	entry.Store(uint32(vni), virtNet)

	keys := Keys{
		Epoch:     virtNet.currentKeyEpoch,
		Send:      sendKey,
		Recv:      recvKey,
		ExpiresAt: virtNet.currentKeyExpiresAt,
	}

	resp := RenewKeysResponse{
		Keys: keys,
	}

	if err := s.handler.UpdateVirtualNetworkKey(uint(vni), uint32(keys.Epoch),
		keys.Send, keys.Recv, keys.ExpiresAt); err != nil {
		http.Error(w, "Failed to update virtual network keys", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// CleanupExpiredNetworks removes networks that have expired keys.
// This is visible for testing purposes.
func (s *Server) CleanupExpiredNetworks() {
	now := time.Now()
	expirationThreshold := now.Add(-2 * s.keyLifespan)

	s.networks.Range(func(key, value any) bool {
		entry := value.(*sync.Map)

		entry.Range(func(k, v any) bool {
			vni := k.(uint32)
			virtNet := v.(virtualNetwork)
			if virtNet.currentKeyExpiresAt.Before(expirationThreshold) {
				entry.Delete(vni)
				s.vniPool.Free(virtNet.vni)
				for _, addr := range virtNet.addresses {
					_ = s.ipam.Release(addr)
				}
			}
			return true
		})

		return true
	})
}

func (s *Server) withAuth(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if authHeader == "" || len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr := authHeader[len(prefix):]
		claims, err := s.validator.Validate(tokenStr)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		sub, err := claims.GetSubject()
		if err != nil || sub == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ps = append(ps, httprouter.Param{Key: "clientID", Value: sub})

		next(w, r, ps)
	}
}

func randomKey() (Key, error) {
	var key Key
	_, err := rand.Read(key[:])
	return key, err
}
