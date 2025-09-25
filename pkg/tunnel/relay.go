package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/apoxy-dev/icx"
	"github.com/avast/retry-go/v4"
	"github.com/julienschmidt/httprouter"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

const (
	keyLifespan = 24 * time.Hour
)

type Relay struct {
	mu           sync.Mutex
	name         string
	pc           net.PacketConn
	cert         tls.Certificate
	handler      *icx.Handler
	idHasher     *hasher.Hasher
	router       router.Router
	tokens       *haxmap.Map[string, string]      // map[tunnelName]token
	conns        *haxmap.Map[string, *connection] // map[connectionID]Connection
	onConnect    func(ctx context.Context, agentName string, conn controllers.Connection) error
	onDisconnect func(ctx context.Context, agentName, id string) error
}

func NewRelay(name string, pc net.PacketConn, cert tls.Certificate, handler *icx.Handler, idHasher *hasher.Hasher, router router.Router) *Relay {
	return &Relay{
		name:     name,
		pc:       pc,
		cert:     cert,
		handler:  handler,
		idHasher: idHasher,
		router:   router,
		tokens:   haxmap.New[string, string](),
		conns:    haxmap.New[string, *connection](),
	}
}

// Name is the name of the relay.
func (r *Relay) Name() string {
	return r.name
}

// Address is the underlay address of the relay.
func (r *Relay) Address() string {
	return r.pc.LocalAddr().String()
}

// SetCredentials sets the authentication token used by agents to authenticate with the relay.
func (r *Relay) SetCredentials(tunnelName, token string) {
	r.tokens.Set(tunnelName, token)
}

// SetOnConnect sets a callback that is invoked when a new connection is established to the relay.
func (r *Relay) SetOnConnect(onConnect func(ctx context.Context, agentName string, conn controllers.Connection) error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.onConnect = onConnect
}

// SetOnDisconnect sets a callback that is invoked when a connection is closed.
func (r *Relay) SetOnDisconnect(onDisconnect func(ctx context.Context, agentName, id string) error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.onDisconnect = onDisconnect
}

// Start starts the relay.
func (r *Relay) Start(ctx context.Context) error {
	ln, err := quic.ListenEarly(
		r.pc,
		http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{r.cert}}),
		quicConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	mux := httprouter.New()

	mux.POST("/v1/tunnel/:name", r.withAuth(r.handleConnect))
	mux.DELETE("/v1/tunnel/:name", r.withAuth(r.handleDisconnect))
	mux.PUT("/v1/tunnel/:name/keys", r.withAuth(r.handleUpdateKeys))

	srv := http3.Server{
		Handler: mux,
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()

		slog.Info("Stopping relay", slog.String("addr", ln.Addr().String()))

		if err := r.router.Close(); err != nil {
			slog.Error("Failed to close router", slog.Any("error", err))
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		slog.Info("Shutting down server", slog.String("addr", ln.Addr().String()))

		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Failed to shutdown server", slog.Any("error", err))
		}

		return srv.Close()
	})

	// Start the router to handle network traffic.
	g.Go(func() error {
		return r.router.Start(ctx)
	})

	g.Go(func() error {
		slog.Info("Starting relay", slog.String("addr", ln.Addr().String()))
		if err := srv.ServeListener(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	return g.Wait()
}

func (r *Relay) handleConnect(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var request api.ConnectRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	localAddr, err := netip.ParseAddrPort(r.pc.LocalAddr().String())
	if err != nil {
		http.Error(w, "Failed to parse local address", http.StatusBadRequest)
		return
	}

	remoteAddr, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to parse remote address", http.StatusBadRequest)
		return
	}

	id := r.idHasher.Hash(localAddr, remoteAddr)

	conn := &connection{
		id:         id,
		handler:    r.handler,
		router:     r.router,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}

	r.conns.Set(conn.ID(), conn)

	r.mu.Lock()
	onConnect := r.onConnect
	r.mu.Unlock()

	if err := onConnect(req.Context(), request.Agent, conn); err != nil {
		slog.Error("onConnect callback failed", slog.Any("error", err))
		http.Error(w, "Failed to handle connection", http.StatusInternalServerError)
		return
	}

	// Wait until the connection has a VNI and overlay address assigned.
	err = retry.Do(
		func() error {
			if conn.VNI() == nil || conn.OverlayAddress() == "" {
				return fmt.Errorf("connection not ready")
			}

			return nil
		},
		retry.Context(req.Context()),
		retry.Delay(100*time.Millisecond),
		retry.Attempts(10),
	)

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

	keys := api.Keys{
		Send:      sendKey,
		Recv:      recvKey,
		ExpiresAt: time.Now().Add(keyLifespan),
	}

	vni := conn.VNI()

	resp := api.ConnectResponse{
		ID:        conn.ID(),
		VNI:       *vni,
		MTU:       icx.MTU(1500),
		Keys:      keys,
		Addresses: []string{conn.OverlayAddress()},
		// FUTURE: routes, DNS, etc.
	}

	if err := r.handler.UpdateVirtualNetworkKeys(*vni, keys.Epoch,
		keys.Send, keys.Recv, keys.ExpiresAt); err != nil {
		http.Error(w, "Failed to update virtual network keys", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (r *Relay) handleDisconnect(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var request api.Request
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	onDisconnect := r.onDisconnect
	r.mu.Unlock()

	if err := onDisconnect(req.Context(), request.Agent, request.ID); err != nil {
		slog.Error("onDisconnect callback failed", slog.Any("error", err))
		http.Error(w, "Failed to handle disconnection", http.StatusInternalServerError)
		return
	}

	r.conns.Del(request.ID)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func (r *Relay) handleUpdateKeys(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var request api.Request
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	conn, ok := r.conns.Get(request.ID)
	if !ok {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	vni := conn.VNI()
	if vni == nil {
		slog.Warn("Connection has no VNI assigned", slog.String("connID", request.ID))
		http.Error(w, "Connection is not ready", http.StatusBadRequest)
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

	keys := api.Keys{
		Epoch:     conn.IncrementKeyEpoch(),
		Send:      sendKey,
		Recv:      recvKey,
		ExpiresAt: time.Now().Add(keyLifespan),
	}

	if err := r.handler.UpdateVirtualNetworkKeys(*vni, keys.Epoch,
		keys.Send, keys.Recv, keys.ExpiresAt); err != nil {
		http.Error(w, "Failed to update virtual network keys", http.StatusInternalServerError)
		return
	}

	resp := api.UpdateKeysResponse{
		Keys: keys,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (r *Relay) withAuth(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		const prefix = "Bearer "
		authHeader := req.Header.Get("Authorization")
		if len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
			slog.Warn("Missing or invalid Authorization header")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			r.closeConn(w, http3.ErrCodeRequestRejected, "unauthorized")
			return
		}

		tokenStr := authHeader[len(prefix):]
		tunnelName := ps.ByName("name")
		if tunnelName == "" {
			slog.Warn("Missing tunnel name in request")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			r.closeConn(w, http3.ErrCodeRequestRejected, "unauthorized")
			return
		}

		if storedToken, ok := r.tokens.Get(tunnelName); !ok || storedToken != tokenStr {
			slog.Warn("Invalid token for tunnel", slog.String("tunnel", tunnelName))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			r.closeConn(w, http3.ErrCodeRequestRejected, "unauthorized")
			return
		}

		// Authenticated, call the next handler.
		next(w, req, ps)
	}
}

func (r *Relay) closeConn(w http.ResponseWriter, code http3.ErrCode, msg string) {
	hij, ok := w.(http3.Hijacker)
	if !ok {
		slog.Warn("Failed to explicitly close quic connection")
		return
	}

	h3c := hij.Connection()
	_ = h3c.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

func randomKey() (api.Key, error) {
	var key api.Key
	_, err := rand.Read(key[:])
	return key, err
}
