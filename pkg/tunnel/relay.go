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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"
	"github.com/julienschmidt/httprouter"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

const (
	keyLifespan = 24 * time.Hour
)

// connInstances numbers the connections the relay accepts. A connection ID is
// derived from the 4-tuple, so an agent that reconnects from the same address
// gets the ID of the connection it replaced; the number this counter gives out
// is what tells the two apart in the reported statistics. It starts at 1, so a
// zero instance means the connection did not come from the connect handler.
var connInstances atomic.Uint64

type Relay struct {
	mu            sync.Mutex
	name          string
	pc            net.PacketConn
	getCert       func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	handler       *icx.Handler
	idHasher      *hasher.Hasher
	router        router.Router
	egressGateway bool
	// staticTokens is the default token validator, fed by SetCredentials.
	staticTokens *token.StaticTokenValidator
	// tokenValidator authenticates connect requests; defaults to staticTokens.
	tokenValidator token.TokenValidator
	conns          *haxmap.Map[string, *connection] // map[connectionID]Connection
	agents         *haxmap.Map[string, string]      // map[connectionID]agentName
	onConnect      func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error
	onDisconnect   func(ctx context.Context, agentName, id string) error
	onDraining     func(ctx context.Context)
	onShutdown     func(ctx context.Context)
	// onConnStatsFinal receives a connection's last datapath counters at
	// teardown. See SetOnConnStatsFinal.
	onConnStatsFinal func(ConnStats)
	metricsStore     *metrics.MetricsStore

	// lameDuck is how long the relay keeps forwarding after announcing a
	// drain (GOAWAY). Zero means immediate shutdown.
	lameDuck time.Duration
	// draining flips once shutdown begins. Control sessions closing during a
	// drain are expected (agents close them on GOAWAY) and must not tear down
	// the datapath state that lame-duck forwarding depends on.
	draining atomic.Bool
}

func NewRelay(name string, pc net.PacketConn, cert tls.Certificate, handler *icx.Handler, idHasher *hasher.Hasher, router router.Router) *Relay {
	staticTokens := token.NewStaticTokenValidator()
	return &Relay{
		name:           name,
		pc:             pc,
		getCert:        staticCert(cert),
		handler:        handler,
		idHasher:       idHasher,
		router:         router,
		staticTokens:   staticTokens,
		tokenValidator: staticTokens,
		conns:          haxmap.New[string, *connection](),
		agents:         haxmap.New[string, string](),
	}
}

// staticCert returns a GetCertificate func that always serves cert. Used by
// dev mode and tests, which supply an in-memory keypair with no file to watch.
func staticCert(cert tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
}

// SetCertProvider overrides the source of the relay's TLS server certificate,
// e.g. to enable hot-reload from disk via pkg/cert/reload. Must be called
// before Start.
func (r *Relay) SetCertProvider(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getCert = getCert
}

// Name is the name of the relay.
func (r *Relay) Name() string {
	return r.name
}

// Address is the underlay address of the relay.
func (r *Relay) Address() netip.AddrPort {
	ua := r.pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr(ua.IP.String()), uint16(ua.Port))
}

// SetCredentials sets the static authentication token used by agents to
// authenticate with the relay for a tunnel. Only consulted when the default
// static token validator is in effect (see SetTokenValidator).
func (r *Relay) SetCredentials(tunnelName, token string) {
	r.staticTokens.SetToken(tunnelName, token)
}

// RemoveCredentials revokes a tunnel's static authentication token so new
// connects to it fail closed. Only consulted when the default static token
// validator is in effect (see SetTokenValidator).
func (r *Relay) RemoveCredentials(tunnelName string) {
	r.staticTokens.RemoveToken(tunnelName)
}

// SetTokenValidator overrides how agent credentials are authenticated, e.g.
// with a JWT-backed validator. Must be called before Start.
func (r *Relay) SetTokenValidator(v token.TokenValidator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokenValidator = v
}

// SetEgressGateway enables or disables internet egress for the tunnel agents.
func (r *Relay) SetEgressGateway(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.egressGateway = enabled
}

// SetOnConnect sets a callback that is invoked when a new connection is established to the relay.
func (r *Relay) SetOnConnect(onConnect func(ctx context.Context, tunnelName, agentName string, conn controllers.Connection) error) {
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

// SetOnDraining sets a callback invoked at the start of shutdown, before the
// GOAWAY goes out and while the relay is still forwarding. Deregistration
// belongs here: it stops discovery from handing this relay out while its live
// connections ride out the lame duck.
func (r *Relay) SetOnDraining(onDraining func(context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.onDraining = onDraining
}

// SetOnShutdown sets a callback that is invoked when the relay is shutting down.
func (r *Relay) SetOnShutdown(onShutdown func(context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.onShutdown = onShutdown
}

// SetLameDuckPeriod sets how long the relay keeps forwarding traffic after
// announcing a drain via GOAWAY, giving agents time to establish replacement
// sessions before this one goes dark. Zero (the default) shuts down
// immediately. Must be called before Start.
func (r *Relay) SetLameDuckPeriod(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lameDuck = d
}

// SetMetricsStore configures the push-based metrics store.
func (r *Relay) SetMetricsStore(s *metrics.MetricsStore) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.metricsStore = s
}

// MetricsStore returns the metrics store, if configured.
func (r *Relay) MetricsStore() *metrics.MetricsStore {
	return r.metricsStore
}

// ConnStats is one connection's identity and its datapath counters.
//
// The counters are cumulative over the life of the connection's current
// virtual network: they start at zero when the network is installed and go
// away with it, so a reader must take a decrease as a reset rather than as
// negative traffic. RXDrops and TXDrops fold every drop reason the datapath
// counts separately.
type ConnStats struct {
	// ID is the connection ID, which is also the name of the Tunnel object the
	// relay creates for it.
	ID string
	// Instance tells apart the connections that share an ID. The ID comes from
	// the connection 4-tuple, so an agent that reconnects from the same address
	// gets the ID of the connection it replaced. Every connection the relay
	// accepts gets its own instance number, so two ConnStats with the same ID
	// and a different Instance report different connections, and the counters
	// of one must not be compared with the counters of the other.
	Instance uint64
	// Network is the VPCNetwork name the connection is bound to.
	Network string
	// ProjectID is the tenant scope the connection's credential resolved to.
	// Empty on single-tenant relays.
	ProjectID string
	// AgentInstance is the per-process ID of the agent that opened the
	// connection, if it declared one.
	AgentInstance string

	RXBytes   uint64
	TXBytes   uint64
	RXPackets uint64
	TXPackets uint64
	RXDrops   uint64
	TXDrops   uint64
}

// SetOnConnStatsFinal sets a callback that receives a connection's last
// datapath counters when it is torn down, and for every connection still live
// at shutdown, before the virtual networks are removed and the counters go
// away. It runs at most once per connection, and under no relay lock, so the
// callback may call back into the relay.
func (r *Relay) SetOnConnStatsFinal(fn func(ConnStats)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.onConnStatsFinal = fn
}

// ConnectionStats returns the datapath counters of every live connection,
// sorted by connection ID. A connection that has no virtual network yet — one
// still completing its connect — has no counters to report and is left out.
func (r *Relay) ConnectionStats() []ConnStats {
	var out []ConnStats
	r.conns.ForEach(func(_ string, conn *connection) bool {
		if stats, ok := conn.datapathStats(); ok {
			out = append(out, stats)
		}
		return true
	})
	slices.SortFunc(out, func(a, b ConnStats) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Start starts the relay.
func (r *Relay) Start(ctx context.Context) error {
	ln, err := quic.ListenEarly(
		r.pc,
		http3.ConfigureTLSConfig(&tls.Config{GetCertificate: r.getCert}),
		quicConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	mux := httprouter.New()

	// Unauthenticated latency probe for agent relay selection. A draining
	// relay answers 503 so probes steer agents toward relays that will
	// still be there once the session is up.
	mux.GET("/ping", func(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
		if r.draining.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Agents push their Prometheus metrics over the control connection. It
	// carries no bearer token: the QUIC connection is already authenticated,
	// and the connection ID is derived from the 4-tuple, so a caller can only
	// ever push under its own connection.
	mux.POST(api.MetricsPushPath, r.handleMetricsPush)

	mux.POST("/v1/tunnel/:name", r.withAuth(r.handleConnect))
	mux.DELETE("/v1/tunnel/:name", r.withAuth(r.handleDisconnect))
	mux.PUT("/v1/tunnel/:name/keys", r.withAuth(r.handleUpdateKeys))
	mux.GET("/v1/tunnel/:name/routes", r.withAuth(r.handleRoutes))

	srv := http3.Server{
		Handler: mux,
	}

	g, ctx := errgroup.WithContext(ctx)

	// Start the router to handle network traffic.
	g.Go(func() error {
		return r.router.Start(ctx)
	})

	g.Go(func() error {
		<-ctx.Done()

		r.draining.Store(true)

		r.mu.Lock()
		onDraining := r.onDraining
		lameDuck := r.lameDuck
		r.mu.Unlock()

		// Deregister first, while the relay still forwards: discovery must
		// stop handing this relay out before its connections are asked to
		// move elsewhere.
		if onDraining != nil {
			drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			onDraining(drainCtx)
			cancel()
		}

		if lameDuck <= 0 {
			slog.Info("Stopping relay", slog.String("addr", ln.Addr().String()))

			// Last chance to report what the live connections carried: the
			// router close below removes their virtual networks.
			r.flushFinalStats()

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
		}

		deadline := time.Now().Add(lameDuck)
		slog.Info("Relay draining; entering lame duck",
			slog.String("addr", ln.Addr().String()),
			slog.Duration("lameDuck", lameDuck))

		// GOAWAY every control session. Shutdown returns when the last
		// control connection closes — near-instantly, since agents close
		// their idle control connections on GOAWAY — not when the lame duck
		// ends, so the datapath hold below is what actually paces shutdown.
		shutdownCtx, cancel := context.WithDeadline(context.Background(), deadline)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("HTTP/3 server shutdown ended early", slog.Any("error", err))
		}
		cancel()

		// Keep the router and handler forwarding until the lame duck
		// expires so agents can bring up replacement sessions while this
		// relay still carries their traffic.
		if d := time.Until(deadline); d > 0 {
			time.Sleep(d)
		}

		slog.Info("Lame duck over; stopping relay", slog.String("addr", ln.Addr().String()))

		// Last chance to report what the live connections carried: the router
		// close below removes their virtual networks.
		r.flushFinalStats()

		if err := r.router.Close(); err != nil {
			slog.Error("Failed to close router", slog.Any("error", err))
		}

		return srv.Close()
	})

	g.Go(func() error {
		slog.Info("Starting relay", slog.String("addr", ln.Addr().String()))
		if err := srv.ServeListener(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	// Invoke shutdown callback if set.
	r.mu.Lock()
	onShutdown := r.onShutdown
	r.mu.Unlock()

	if onShutdown != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		onShutdown(shutdownCtx)
	}

	return nil
}

// flushFinalStats delivers the last datapath counters of every live connection
// to the onConnStatsFinal hook. Shutdown calls it immediately before the router
// closes: the close removes the virtual networks, and their counters go with
// them, so this is the last moment the counters can be read.
//
// Each connection leaves the registry before its counters are read, with the
// identity check teardownConn uses, so a reconnect that replaced a connection
// keeps the replacement. The hard once-guard is the connection's finalReported
// flag: both this flush and teardown must win a compare-and-swap on it to
// report, so the hook cannot run twice for one connection even when the two
// paths run at the same time. The connections are not
// closed here and onDisconnect does not run: the router close tears the
// datapath down, and the control-plane cleanup belongs to the drain and
// adoption path, which must not be replaced by one blocking call per connection
// while the process exits.
func (r *Relay) flushFinalStats() {
	r.mu.Lock()
	onConnStatsFinal := r.onConnStatsFinal
	r.mu.Unlock()
	if onConnStatsFinal == nil {
		return
	}

	// Snapshot the connections first. The hook runs under no relay lock and may
	// call back into the relay, so it must not run inside the map walk.
	var live []*connection
	r.conns.ForEach(func(_ string, conn *connection) bool {
		live = append(live, conn)
		return true
	})

	var delivered int
	for _, conn := range live {
		id := conn.ID()
		if cur, ok := r.conns.Get(id); !ok || cur != conn {
			continue // already torn down, or replaced by a reconnect
		}
		r.conns.Del(id)
		r.agents.Del(id)

		// Read the counters before the compare-and-swap, for the same reason
		// teardown does: the path that loses the race must not consume the one
		// report the connection gets.
		final, ok := conn.datapathStats()
		if !ok {
			continue // no virtual network yet, so nothing to count
		}
		if !conn.finalReported.CompareAndSwap(false, true) {
			continue // teardown reported this connection already
		}
		onConnStatsFinal(final)
		delivered++
	}

	if delivered > 0 {
		slog.Info("Reported the final counters of the live connections",
			slog.Int("connections", delivered))
	}
}

// installEpoch advances the connection's key epoch and installs the derived
// per-direction SAs for that epoch on the relay's handler, returning the Keys to
// hand back to the agent. The relay is the Responder in the PSP role split; the
// agent installs the mirrored Initiator SPIs. Both handleConnect and
// handleUpdateKeys route through here so the role, epoch, and install ordering
// live in exactly one place.
func (r *Relay) installEpoch(conn *connection, vni uint) (api.Keys, error) {
	keys := api.Keys{
		Epoch:        conn.IncrementKeyEpoch(),
		MasterSecret: conn.Master(),
		ExpiresAt:    time.Now().Add(keyLifespan),
	}

	rxSPI, txSPI, err := psp.EpochSPIs(psp.Responder, keys.Epoch)
	if err != nil {
		return api.Keys{}, fmt.Errorf("derive SPIs for epoch %d: %w", keys.Epoch, err)
	}
	if err := r.handler.UpdateVirtualNetworkSecret(vni, [32]byte(keys.MasterSecret), rxSPI, txSPI, keys.ExpiresAt); err != nil {
		return api.Keys{}, fmt.Errorf("install SAs: %w", err)
	}
	return keys, nil
}

// connIdentity is the connection a relay request comes from: the address pair
// of its 4-tuple and the connection ID hashed from that pair.
type connIdentity struct {
	id         string
	localAddr  netip.AddrPort
	remoteAddr netip.AddrPort
}

// connIdentityFromRequest derives the connection identity from the request
// 4-tuple. This derivation is the authorization boundary of every
// per-connection route: the ID comes from the addresses the transport reports,
// never from the request body, so a caller can only reach the connection it
// dialed from. Every handler that needs a connection ID goes through here, so
// the connect and the metrics push paths cannot drift apart.
func (r *Relay) connIdentityFromRequest(req *http.Request) (connIdentity, error) {
	localAddr, err := netip.ParseAddrPort(r.pc.LocalAddr().String())
	if err != nil {
		return connIdentity{}, fmt.Errorf("failed to parse the relay listen address %q: %w",
			r.pc.LocalAddr().String(), err)
	}
	remoteAddr, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return connIdentity{}, fmt.Errorf("failed to parse the remote address %q: %w",
			req.RemoteAddr, err)
	}
	return connIdentity{
		id:         r.idHasher.Hash(localAddr, remoteAddr),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, nil
}

func (r *Relay) handleConnect(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var request api.ConnectRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if request.Agent == "" {
		http.Error(w, "Missing agent name", http.StatusBadRequest)
		return
	}

	// A Tunnel must have a connection-lifetime signal before it is published.
	// Without the HTTP/3 connection context, a killed agent can leave a Tunnel
	// indefinitely because no request-level context survives the response.
	hij, ok := w.(http3.Hijacker)
	if !ok || hij.Connection() == nil {
		metrics.TunnelConnectionFailures.WithLabelValues("session_tracking").Inc()
		slog.Error("HTTP/3 connection tracking is unavailable")
		http.Error(w, "connection tracking is unavailable", http.StatusInternalServerError)
		return
	}
	sessionCtx := hij.Connection().Context()

	// Enforce the credential's bounds on agent-declared labels and routes.
	// withAuth always attaches a non-nil authorization on success; a missing one
	// means a validator or wiring bug, so fail closed rather than skip the checks.
	authz := authzResultFrom(req.Context())
	if authz == nil {
		slog.Error("Connect request reached handler without an authorization")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	advertisedRoutes := make([]netip.Prefix, 0, len(request.AdvertisedRoutes))
	for _, cidr := range request.AdvertisedRoutes {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid advertised route %q", cidr), http.StatusBadRequest)
			return
		}
		if !authz.PermitsRoute(pfx) {
			http.Error(w, fmt.Sprintf("Advertised route %q not permitted by credential", cidr), http.StatusForbidden)
			return
		}
		// The overlay ULA space is relay-allocated; an advertised route inside
		// it would shadow other connections' assigned addresses in the route
		// trie regardless of credential bounds.
		if pfx.Overlaps(tunnet.ULAPrefix()) {
			http.Error(w, fmt.Sprintf("Advertised route %q overlaps the overlay address space", cidr), http.StatusForbidden)
			return
		}
		advertisedRoutes = append(advertisedRoutes, pfx)
	}
	// Advertised routes install into the handler's route trie, which is shared
	// across every VNI on this relay (per-network routing domains are a later
	// step), so an overlap with another live connection's advertised routes
	// would steal its transit traffic. First writer wins; the loser is told to
	// go elsewhere.
	if len(advertisedRoutes) > 0 {
		var conflict string
		r.conns.ForEach(func(_ string, other *connection) bool {
			for _, existing := range other.AdvertisedRoutes() {
				for _, pfx := range advertisedRoutes {
					if pfx.Overlaps(existing) {
						conflict = fmt.Sprintf("advertised route %q overlaps %q held by another connection", pfx, existing)
						return false
					}
				}
			}
			return true
		})
		if conflict != "" {
			http.Error(w, conflict, http.StatusConflict)
			return
		}
	}
	if !authz.PermitsLabels(request.Labels) {
		http.Error(w, "Labels not permitted by credential", http.StatusForbidden)
		return
	}

	ident, err := r.connIdentityFromRequest(req)
	if err != nil {
		slog.Error("Failed to derive the connection identity", slog.Any("error", err))
		http.Error(w, "Failed to derive connection identity", http.StatusBadRequest)
		return
	}
	id, localAddr, remoteAddr := ident.id, ident.localAddr, ident.remoteAddr

	// One master secret per connection, minted before the connection is published
	// so no concurrent handleUpdateKeys can ever observe a zero master. Each
	// rotation advances the epoch under it and the icx handler derives that
	// epoch's per-direction keys.
	master, err := randomMasterSecret()
	if err != nil {
		http.Error(w, "Failed to generate master secret", http.StatusInternalServerError)
		return
	}

	conn := &connection{
		id:               id,
		instance:         connInstances.Add(1),
		handler:          r.handler,
		router:           r.router,
		localAddr:        localAddr,
		remoteAddr:       remoteAddr,
		master:           master,
		network:          authz.Network,
		scope:            authz.Scope,
		labels:           request.Labels,
		advertisedRoutes: advertisedRoutes,
		agentInstance:    request.AgentInstance,
	}

	// A reconnect from the same 4-tuple hashes to the same connection ID. The
	// previous session is dead (or dying) but its close watcher may not have
	// fired yet; tear it down explicitly so its addresses and VNI are released
	// before the new connection allocates, and so the stale watcher (which
	// checks identity, not just ID) cannot reap the replacement.
	if old, ok := r.conns.Get(conn.ID()); ok {
		slog.Info("Replacing existing connection for reconnect",
			slog.String("connID", conn.ID()))
		r.teardownConn(req.Context(), old)
	}

	r.conns.Set(conn.ID(), conn)
	r.agents.Set(conn.ID(), request.Agent)

	r.mu.Lock()
	onConnect := r.onConnect
	r.mu.Unlock()

	tunnelName := ps.ByName("name")
	// onConnect allocates the connection's addresses and VNI in-process and,
	// on the new path, creates the Tunnel object - all synchronously, so the
	// connection is fully ready when it returns. There is no apiserver
	// round-trip and no await-the-reconciler retry loop (the legacy structure,
	// with its swallowed error, is deleted rather than fixed - APO-825 §2.4).
	if err := onConnect(req.Context(), tunnelName, request.Agent, conn); err != nil {
		slog.Error("Failed to establish connection", slog.String("connID", conn.ID()), slog.Any("error", err))
		r.teardownConn(req.Context(), conn)
		http.Error(w, "Failed to handle connection", http.StatusInternalServerError)
		return
	}

	vni := conn.VNI()
	if vni == nil || conn.OverlayAddress() == "" {
		slog.Warn("Connection was not assigned a VNI and address", slog.String("connID", conn.ID()))
		r.teardownConn(req.Context(), conn)
		http.Error(w, "Connection is not ready", http.StatusServiceUnavailable)
		return
	}

	// Reap the connection when its QUIC control session closes, about 15
	// seconds after an agent dies through MaxIdleTimeout.
	go r.watchSessionClose(sessionCtx, conn)

	// First epoch is 1 (epoch 0 is a reserved SPI counter the handler rejects).
	keys, err := r.installEpoch(conn, *vni)
	if err != nil {
		slog.Error("Failed to install connection keys", slog.String("connID", conn.ID()), slog.Any("error", err))
		r.teardownConn(req.Context(), conn)
		http.Error(w, "Failed to update virtual network keys", http.StatusInternalServerError)
		return
	}

	addresses := conn.Addresses()
	routes := r.routesForConn(conn)

	resp := api.ConnectResponse{
		ID:        conn.ID(),
		VNI:       *vni,
		MTU:       icx.MTU(api.TunnelPathMTU),
		Keys:      keys,
		Addresses: addresses,
		Routes:    routes,
	}

	// Register with metrics store so pushed metrics get the right labels. The
	// agent instance is the agent's per-process ID, so metrics from several
	// connections of one agent process can be told apart from several
	// processes.
	if r.metricsStore != nil {
		r.metricsStore.Register(metrics.StoreTarget{
			ConnID:         conn.ID(),
			TunnelNode:     tunnelName,
			AgentName:      request.Agent,
			AgentProcessID: conn.AgentInstance(),
			ProjectID:      conn.Scope(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// teardownConn removes a connection from the relay's maps and releases every
// resource onConnect allocated (addresses, VNI, Tunnel object) via the
// onDisconnect callback. It is used both to abort a connection that failed to
// finish establishing and to reap one whose QUIC control session has closed. It
// is idempotent, and identity-aware: if the registry maps the ID to a
// different *connection (a reconnect from the same 4-tuple replaced this one),
// the newer connection is left untouched — otherwise a stale session-close
// watcher would release the replacement's addresses while it is live, and the
// next connect would be handed a duplicate /96.
func (r *Relay) teardownConn(ctx context.Context, conn *connection) {
	id := conn.ID()
	if cur, ok := r.conns.Get(id); !ok || cur != conn {
		return
	}
	r.conns.Del(id)
	agentName, _ := r.agents.Get(id)
	r.agents.Del(id)

	if r.metricsStore != nil {
		r.metricsStore.Unregister(id)
	}

	r.mu.Lock()
	onConnStatsFinal := r.onConnStatsFinal
	r.mu.Unlock()

	// Read the counters before the close: closing removes the virtual network,
	// which takes its counters with it, so this is the last chance to report
	// what the connection carried. The compare-and-swap comes after the read so
	// that a lost race cannot consume the one report the connection gets, and
	// it is what makes the report run once when the shutdown flush reaches this
	// connection at the same time.
	var (
		final    ConnStats
		hasFinal bool
	)
	if onConnStatsFinal != nil {
		final, hasFinal = conn.datapathStats()
		if hasFinal && !conn.finalReported.CompareAndSwap(false, true) {
			hasFinal = false
		}
	}

	if err := conn.Close(); err != nil {
		slog.Warn("Failed to close connection during teardown", slog.String("connID", id), slog.Any("error", err))
	}

	if hasFinal {
		onConnStatsFinal(final)
	}

	r.mu.Lock()
	onDisconnect := r.onDisconnect
	r.mu.Unlock()
	if onDisconnect != nil {
		// Detached from the caller's context: an aborting connect arrives here
		// with its request context already canceled, and inheriting it
		// guarantees the cleanup fails — leaking the Tunnel object and the
		// connection's allocations (2026-08-03 incident).
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := onDisconnect(dctx, agentName, id); err != nil {
			slog.Warn("onDisconnect callback failed during teardown", slog.String("connID", id), slog.Any("error", err))
		}
	}
}

// DisconnectConnection closes one live connection and runs its control-plane
// cleanup. It is safe to call after another path has already removed it.
func (r *Relay) DisconnectConnection(id string) {
	if conn, ok := r.conns.Get(id); ok {
		r.teardownConn(context.Background(), conn)
	}
}

// watchSessionClose reaps a connection when its QUIC control session closes. The
// relay's control listener runs KeepAlivePeriod=5s / MaxIdleTimeout=15s on the
// same 5-tuple as the data path (quic.go), so a dead agent's session closes in
// ~15s and its Tunnel is deleted then. This is the primary, session-close-driven
// disconnect path (§2.2). Data-plane silence is not a liveness signal because
// a healthy tunnel can be idle for an arbitrary period.
func (r *Relay) watchSessionClose(sessCtx context.Context, conn *connection) {
	<-sessCtx.Done()
	id := conn.ID()
	if r.draining.Load() {
		// Control sessions close en masse when the drain's GOAWAY goes out,
		// but the datapath must keep forwarding through the lame duck. The
		// shutdown path reports the final counters once the lame duck ends
		// (flushFinalStats); the control-plane cleanup of the connections that
		// moved elsewhere belongs to the drain and adoption path.
		slog.Debug("Control session closed during drain; keeping connection",
			slog.String("connID", id))
		return
	}
	if cur, ok := r.conns.Get(id); !ok || cur != conn {
		return // already disconnected, reaped, or replaced by a reconnect
	}
	slog.Info("Agent control session closed, disconnecting", slog.String("connID", id))
	metrics.TunnelSessionClosures.Inc()
	r.teardownConn(context.Background(), conn)
}

func (r *Relay) handleDisconnect(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var request api.Request
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	conn, ok := r.conns.Get(request.ID)
	if !ok {
		http.Error(w, api.ConnectionNotFoundMessage, http.StatusNotFound)
		return
	}
	r.teardownConn(req.Context(), conn)
	w.WriteHeader(http.StatusOK)
}

// handleMetricsPush stores the metrics an agent pushed over its existing
// HTTP/3 connection, in Prometheus text exposition format. The connection ID
// comes from the request 4-tuple, through the same helper the connect handler
// uses, so the push needs no ID of its own and cannot name another connection.
// The body is read through metrics.DecodePush, which caps it.
func (r *Relay) handleMetricsPush(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	r.mu.Lock()
	store := r.metricsStore
	r.mu.Unlock()

	// A relay with no store is a normal deployment. Answer before reading the
	// body: there is nothing to keep, and an error status would make every
	// agent report a failure on every push.
	if store == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ident, err := r.connIdentityFromRequest(req)
	if err != nil {
		slog.Error("Failed to derive the connection identity", slog.Any("error", err))
		http.Error(w, "Failed to derive connection identity", http.StatusBadRequest)
		return
	}
	id := ident.id

	// The store drops metrics for an unknown ID without a word, so the relay's
	// own connection map is what makes an unknown connection visible to the
	// agent.
	if _, ok := r.conns.Get(id); !ok {
		http.Error(w, api.ConnectionNotFoundMessage, http.StatusNotFound)
		return
	}

	families, err := metrics.DecodePush(w, req)
	if err != nil {
		slog.Warn("Failed to parse pushed metrics",
			slog.String("connID", id),
			slog.Any("error", err))
		http.Error(w, "Invalid metrics body", http.StatusBadRequest)
		return
	}

	store.Push(id, families)
	w.WriteHeader(http.StatusOK)
}

// routesForConn computes the route set a connected agent should have
// installed: a single-IP route per assigned address (both families); in-overlay
// reach to other endpoints homed on THIS relay (e.g. backplane services); the
// CIDRs reachable behind other live connections in the same network (so e.g.
// the backplane's TUN peer reaches a private endpoint behind another agent
// through the relay); and egress default routes when this relay is an egress
// gateway. IPv4 has no per-network prefix (the /32s come from a shared range),
// so v4 in-overlay reach is limited to the agent's own address; broader v4
// reach comes from the egress defaults. Addresses() is derived from the
// programmed state, so routes and the reported address set always agree.
//
// In-overlay reach comes from the /88s of the slots this relay serves the
// network from. A /88 is per-relay, which is what makes it usable: relays do not
// federate, so an agent connected to several of them needs each relay's space on
// that relay's own session, and needs a prefix narrow enough to pin a source
// address to. The network-wide /72 is the fallback for addresses outside the
// slot scheme — infrastructure endpoints, or whatever an OnConnect hook assigned
// itself — which no /88 covers. It is emitted per address and only for addresses
// that are not slot addresses, so a relay handing out slot addresses (every
// relay in-tree, cloud and standalone alike) never advertises it: every relay
// would advertise the same /72, leaving the agent one route it cannot resolve to
// a single session and the kernel free to source from the wrong relay.
func (r *Relay) routesForConn(conn *connection) []api.Route {
	var routes []api.Route
	for _, a := range conn.Addresses() {
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			continue
		}
		// We'll only advertise single-IP routes so extend the bitmask to max.
		if pfx.Addr().Is4() {
			pfx = netip.PrefixFrom(pfx.Addr(), 32)
		} else {
			pfx = netip.PrefixFrom(pfx.Addr(), 128)
		}
		routes = append(routes, api.Route{Destination: pfx.String()})
		// A slot address is already covered by its own /88 below, so the /72
		// would add nothing but a prefix every relay advertises identically.
		if _, _, isSlot := ipalloc.SlotOf(pfx); pfx.Addr().Is6() && !isSlot {
			routes = append(routes, api.Route{Destination: tunnet.NetworkPrefixOf(pfx.Addr()).String()})
		}
	}
	for _, slot := range r.servedSlots(conn) {
		routes = append(routes, api.Route{Destination: slot.String()})
	}
	r.conns.ForEach(func(_ string, other *connection) bool {
		if other.ID() == conn.ID() || other.Network() != conn.Network() {
			return true
		}
		for _, rt := range other.AdvertisedRoutes() {
			routes = append(routes, api.Route{Destination: rt.String()})
		}
		return true
	})
	if r.egressGateway {
		routes = append(routes,
			api.Route{Destination: "0.0.0.0/0"},
			api.Route{Destination: "::/0"})
	}
	return routes
}

// servedSlots returns the /88 of every slot this relay has minted an address
// from for conn's network, sorted and deduplicated.
//
// It is derived from the live connections rather than read off the slot
// allocator so it needs no plumbing through the connect hook, and so it cannot
// advertise a slot with nothing behind it: a slot appears here exactly while
// some connection on this relay holds an address in it, which is also exactly
// when the relay can forward to it. Addresses that predate slot addressing are
// skipped — SlotOf rejects them — so a mixed-scheme network degrades to the
// per-address /128 routes rather than advertising a bogus prefix.
func (r *Relay) servedSlots(conn *connection) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	var slots []netip.Prefix
	collect := func(c *connection) {
		for _, a := range c.Addresses() {
			pfx, err := netip.ParsePrefix(a)
			if err != nil || !pfx.Addr().Is6() {
				continue
			}
			if _, _, ok := ipalloc.SlotOf(pfx); !ok {
				continue
			}
			slot := ipalloc.SlotPrefixOf(pfx.Addr())
			if _, dup := seen[slot]; dup {
				continue
			}
			seen[slot] = struct{}{}
			slots = append(slots, slot)
		}
	}
	// conn is collected explicitly: on the connect path it is not registered in
	// r.conns yet, and its own slot is the one route it always needs.
	collect(conn)
	r.conns.ForEach(func(_ string, other *connection) bool {
		if other.Network() == conn.Network() {
			collect(other)
		}
		return true
	})
	slices.SortFunc(slots, func(a, b netip.Prefix) int {
		return a.Addr().Compare(b.Addr())
	})
	return slots
}

// handleRoutes returns the connection's current route set. Agents poll this
// to pick up CIDRs advertised by connections established after their own
// ConnectResponse snapshot (the control plane has no push channel).
func (r *Relay) handleRoutes(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	conn, ok := r.conns.Get(req.URL.Query().Get("id"))
	if !ok {
		http.Error(w, api.ConnectionNotFoundMessage, http.StatusNotFound)
		return
	}

	resp := api.RoutesResponse{Routes: r.routesForConn(conn)}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (r *Relay) handleUpdateKeys(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	var request api.Request
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	conn, ok := r.conns.Get(request.ID)
	if !ok {
		http.Error(w, api.ConnectionNotFoundMessage, http.StatusNotFound)
		return
	}

	vni := conn.VNI()
	if vni == nil {
		slog.Warn("Connection has no VNI assigned", slog.String("connID", request.ID))
		http.Error(w, "Connection is not ready", http.StatusBadRequest)
		return
	}

	// Rotation: advance the epoch under the connection's master. The advanced
	// SPI is a fresh KDF context, so the handler derives fresh keys without new
	// key material crossing the wire.
	keys, err := r.installEpoch(conn, *vni)
	if err != nil {
		slog.Error("Failed to rotate connection keys", slog.String("connID", request.ID), slog.Any("error", err))
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

		r.mu.Lock()
		validator := r.tokenValidator
		r.mu.Unlock()

		authz, err := validator.Validate(req.Context(), tunnelName, tokenStr)
		if err != nil {
			slog.Warn("Rejected tunnel credential", slog.String("tunnel", tunnelName), slog.Any("error", err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			r.closeConn(w, http3.ErrCodeRequestRejected, "unauthorized")
			return
		}
		if authz == nil {
			// A validator that authenticates but returns no authorization is a
			// bug; treat it as a rejection rather than silently unbounded access.
			slog.Error("Token validator returned no authorization", slog.String("tunnel", tunnelName))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			r.closeConn(w, http3.ErrCodeRequestRejected, "unauthorized")
			return
		}

		// Authenticated, call the next handler with the authorization attached.
		next(w, req.WithContext(withAuthzResult(req.Context(), authz)), ps)
	}
}

// authzResultKey is the context key under which withAuth stores the validated
// credential's *token.AuthzResult for handlers.
type authzResultKey struct{}

func withAuthzResult(ctx context.Context, authz *token.AuthzResult) context.Context {
	return context.WithValue(ctx, authzResultKey{}, authz)
}

// authzResultFrom returns the authorization attached by withAuth, if any.
func authzResultFrom(ctx context.Context) *token.AuthzResult {
	authz, _ := ctx.Value(authzResultKey{}).(*token.AuthzResult)
	return authz
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

func randomMasterSecret() (api.MasterSecret, error) {
	var m api.MasterSecret
	_, err := rand.Read(m[:])
	return m, err
}
