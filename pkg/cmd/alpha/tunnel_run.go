package alpha

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"
	"github.com/avast/retry-go/v4"
	"github.com/dpeckett/network"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/clientcmd"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/client/versioned"
	vpcclient "github.com/apoxy-dev/apoxy/client/versioned/typed/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// Watchdog tuning knobs
const (
	watchdogMaxSilence = 120 * time.Second
	watchdogInterval   = 5 * time.Second
	// relayRefreshInterval is how often the agent re-lists ready relays from the
	// apiserver to keep its connection pool current.
	relayRefreshInterval = 30 * time.Second
)

var (
	agentName          string            // agent identifier
	tunnelName         string            // VPC network name (--vpc)
	seedRelayAddr      string            // bootstrap relay (host:port)
	minConns           int               // min concurrent relay connections
	token              string            // tunnel auth token
	insecureSkipVerify bool              // skip TLS verification (testing only)
	socksListenAddr    string            // SOCKS listen address
	pcapPath           string            // optional pcap path
	healthAddr         string            // listen address for health endpoint (e.g. ":8080"); empty disables
	agentLabels        map[string]string // agent-declared labels for VPCService selection (--label)
	advertisedRoutes   []string          // CIDRs reachable behind this agent (--route)
	agentInstance      string            // stable per-process instance UUID, stamped in RunE
)

// connectionHealthCounter tracks how many relay sessions are currently live.
var connectionHealthCounter atomic.Int32

// agentConfig holds the per-agent identity and credential threaded through every
// relay session. It is built once in RunE from the parsed flags (after discovery
// fills in the token and the instance UUID is stamped) and passed explicitly to
// the session lifecycle funcs, so the connect path no longer reads package
// globals — which keeps the orchestration funcs cleanly unit-testable.
type agentConfig struct {
	Agent            string            // agent identifier (--agent)
	Network          string            // VPC network name (--vpc)
	Token            string            // tunnel auth token
	Labels           map[string]string // agent-declared labels (--label)
	AdvertisedRoutes []string          // CIDRs advertised to the relay (--route)
	Instance         string            // stable per-process instance UUID
}

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if minConns < 1 {
			return fmt.Errorf("--min-conns must be at least 1")
		}

		// Validate advertised routes up front so a typo fails fast rather than
		// being rejected by the relay mid-connect.
		if _, err := parsePrefixes(advertisedRoutes); err != nil {
			return fmt.Errorf("invalid --route: %w", err)
		}

		// The agent-instance UUID is stable for this process's lifetime; the
		// relay stamps it onto each Tunnel so multiple connections from one
		// process are attributable to the same instance.
		agentInstance = metrics.AgentProcessID()

		// relayLister, when set (kubernetes-discovery mode), returns the current
		// set of ready relay addresses serving the network. It seeds the initial
		// pool and is polled in the background so relays coming and going are
		// picked up without a restart. It stays nil in static (--relay-addr) mode.
		var relayLister func(context.Context) (sets.Set[string], error)
		var discoveredRelays sets.Set[string]

		// Attempt kubernetes-based discovery if no relayAddr/token provided.
		if seedRelayAddr == "" || token == "" {
			clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				clientcmd.NewDefaultClientConfigLoadingRules(),
				&clientcmd.ConfigOverrides{},
			)

			config, err := clientConfig.ClientConfig()
			if err != nil {
				return fmt.Errorf("loading kubeconfig: %w", err)
			}

			clientset, err := versioned.NewForConfig(config)
			if err != nil {
				return fmt.Errorf("creating clientset: %w", err)
			}

			// VPCNetwork carries the connect credential; ready Relay objects
			// carry the dialable underlay addresses. The relay no longer reports a
			// peer list in ConnectResponse (§2.3) — the agent discovers and tracks
			// relays directly from the apiserver.
			network, err := clientset.VpcV1alpha1().VPCNetworks().Get(cmd.Context(), tunnelName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("fetching VPCNetwork %q: %w", tunnelName, err)
			}
			if network.Status.Credentials == nil || network.Status.Credentials.Token == "" {
				return fmt.Errorf("network %q has no credentials configured", tunnelName)
			}
			token = network.Status.Credentials.Token

			// Re-fetch the network on every refresh so relabeling it (which changes
			// which relay selectors match) is picked up without an agent restart.
			vpcClient := clientset.VpcV1alpha1()
			networkName := network.Name
			relayLister = func(ctx context.Context) (sets.Set[string], error) {
				net, err := vpcClient.VPCNetworks().Get(ctx, networkName, metav1.GetOptions{})
				if err != nil {
					return nil, fmt.Errorf("fetching VPCNetwork %q: %w", networkName, err)
				}
				return discoverRelays(ctx, vpcClient, net)
			}

			discoveredRelays, err = relayLister(cmd.Context())
			if err != nil {
				return err
			}
			if discoveredRelays.Len() == 0 {
				return fmt.Errorf("no ready relays serving network %q", tunnelName)
			}
			seedRelayAddr = discoveredRelays.UnsortedList()[rand.IntN(discoveredRelays.Len())]
		}

		// Assemble the immutable per-agent config now that discovery (if any) has
		// populated the token. Threaded explicitly through the session lifecycle.
		cfg := agentConfig{
			Agent:            agentName,
			Network:          tunnelName,
			Token:            token,
			Labels:           agentLabels,
			AdvertisedRoutes: advertisedRoutes,
			Instance:         agentInstance,
		}

		g, ctx := errgroup.WithContext(cmd.Context())

		// Start health endpoint server if configured.
		if strings.TrimSpace(healthAddr) != "" {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", healthHandler)

			healthServer := &http.Server{
				Addr:    healthAddr,
				Handler: mux,
			}

			g.Go(func() error {
				slog.Info("Starting health endpoint server", slog.String("address", healthAddr))
				if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					slog.Error("Health server failed", slog.Any("error", err))
					return err
				}
				return nil
			})

			g.Go(func() error {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return healthServer.Shutdown(shutdownCtx)
			})
		}

		packetPlane, err := newPacketPlane()
		if err != nil {
			return err
		}
		defer packetPlane.Close()

		tlsConf := &tls.Config{InsecureSkipVerify: insecureSkipVerify}

		// Bootstrap against the seed relay to learn MTU/DNS/routes, keys, VNI, and the relay address pool.
		boot, err := bootstrapSession(ctx, cfg, seedRelayAddr, packetPlane.QuicMux, tlsConf)
		if err != nil {
			return err
		}

		// Initialize and start the router.
		r, handler, err := initRouter(
			ctx,
			g,
			boot.Connect,
			routerInitOpts{
				pcGeneve:        packetPlane.Geneve,
				socksListenAddr: socksListenAddr,
				pcapPath:        pcapPath,
			},
		)
		if err != nil {
			return err
		}
		defer r.Close()

		// Create a relay address pool that ensures we never connect to the same
		// relay from multiple slots at once. In discovery mode it starts from the
		// ready-relay set; in static mode it holds just the seed relay.
		poolAddrs := discoveredRelays
		if poolAddrs == nil {
			poolAddrs = sets.New[string](seedRelayAddr)
		}
		relayAddressPool := randalloc.NewRandAllocator(poolAddrs)

		// A slot can only hold a relay no other slot holds, so a pool smaller than
		// minConns leaves the surplus slots idle. In discovery mode that self-heals
		// as relays appear; in static mode (single seed) it never will, so surface
		// it rather than letting slots block silently.
		if poolAddrs.Len() < minConns {
			slog.Warn("Fewer relays available than --min-conns; surplus connection slots will idle until more relays appear",
				slog.Int("relays", poolAddrs.Len()),
				slog.Int("minConns", minConns))
		}

		// Keep the pool fresh from the apiserver (discovery mode only). A slot
		// whose session dies re-Acquires from the refreshed pool, so relays going
		// NotReady drop out and newly-Ready relays get picked up automatically.
		if relayLister != nil {
			g.Go(func() error {
				return refreshRelayPool(ctx, relayLister, relayAddressPool, relayRefreshInterval)
			})
		}

		// Spawn minConns independent connection slots.
		// Each slot:
		//   - acquires a unique relay from the allocator
		//   - connects & manages that session
		//   - when the session ends, releases the relay
		for i := 0; i < minConns; i++ {
			g.Go(func() error {
				return manageConnectionSlot(ctx, cfg, packetPlane.QuicMux, handler, r, relayAddressPool, tlsConf)
			})
		}

		return g.Wait()
	},
}

func init() {
	tunnelRunCmd.Flags().StringVarP(&agentName, "agent", "a", "", "The name of this agent.")
	tunnelRunCmd.Flags().StringVar(&tunnelName, "vpc", "", "The VPC network to connect to.")
	tunnelRunCmd.Flags().StringVarP(&seedRelayAddr, "relay-addr", "r", "", "Seed relay address (host:port), required if not using kubernetes-based discovery.")
	tunnelRunCmd.Flags().IntVar(&minConns, "min-conns", 1, "Minimum number of relays to maintain connections to (randomly selected from the discovered relay set).")
	tunnelRunCmd.Flags().StringVarP(&token, "token", "k", "", "The token to use for authenticating with the tunnel relays, required if not using kubernetes-based discovery.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification for relay connections.")
	tunnelRunCmd.Flags().StringVarP(&pcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")
	tunnelRunCmd.Flags().StringVar(&healthAddr, "health-addr", "localhost:8080", "Listen address for health endpoint (e.g. \":8080\"). Empty disables.")
	tunnelRunCmd.Flags().StringToStringVar(&agentLabels, "label", nil, "Agent-declared label (key=value) for VPCService selection; repeatable. Bounded by the credential's allowed label sets.")
	tunnelRunCmd.Flags().StringArrayVar(&advertisedRoutes, "route", nil, "CIDR reachable behind this agent, advertised to the relay; repeatable. Bounded by the credential's allowed routes.")

	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("agent"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("vpc"))

	tunnelCmd.AddCommand(tunnelRunCmd)
}

// packetPlane bundles the shared UDP socket and its derived logical planes:
// - Geneve/data plane (pcGeneve)
// - QUIC/control plane mux (pcQuicMux)
type packetPlane struct {
	Geneve  batchpc.BatchPacketConn
	QuicMux *conntrackpc.ConntrackPacketConn
	closers []func()
}

// newPacketPlane:
//   - creates a UDP socket bound to :0
//   - wraps it in a BatchPacketConn
//   - bifurcates into Geneve (data plane) and QUIC (control)
//   - wraps QUIC side in a conntrack multiplexer
func newPacketPlane() (*packetPlane, error) {
	return newPacketPlaneAt(":0")
}

// newPacketPlaneAt is newPacketPlane with an explicit UDP bind address (tests
// bind to loopback so the relay advertises a dialable address).
func newPacketPlaneAt(bindAddr string) (*packetPlane, error) {
	lis, err := net.ListenPacket("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	bpc, err := batchpc.New("udp", lis)
	if err != nil {
		lis.Close()
		return nil, fmt.Errorf("failed to create batch packet conn: %w", err)
	}

	pcGeneveInner, pcQuicInner := bifurcate.Bifurcate(bpc)
	pcQuicMuxInner := conntrackpc.New(pcQuicInner, conntrackpc.Options{})

	return &packetPlane{
		Geneve:  pcGeneveInner,
		QuicMux: pcQuicMuxInner,
		closers: []func(){
			func() { pcGeneveInner.Close() },
			func() { pcQuicMuxInner.Close() },
			func() { pcQuicInner.Close() },
		},
	}, nil
}

func (pp *packetPlane) Close() {
	for _, c := range pp.closers {
		c()
	}
}

type bootstrapInfo struct {
	Connect *api.ConnectResponse
}

// bootstrapSession connects to the seed relay, retrieves tunnel config and
// the relay address pool, disconnects, and returns that bootstrap data.
func bootstrapSession(
	ctx context.Context,
	cfg agentConfig,
	seedRelayAddr string,
	pcQuicMux *conntrackpc.ConntrackPacketConn,
	tlsConf *tls.Config,
) (*bootstrapInfo, error) {
	seedAddr := strings.TrimSpace(seedRelayAddr)

	seedResolved, err := resolveAddrPort(ctx, seedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve seed relay addr %q: %w", seedAddr, err)
	}

	seedPcQuic, err := pcQuicMux.Open(&net.UDPAddr{
		IP:   seedResolved.Addr().AsSlice(),
		Port: int(seedResolved.Port()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create multiplexed packet conn for seed relay %q: %w", seedAddr, err)
	}
	defer seedPcQuic.Close()

	client, err := api.NewClient(api.ClientOptions{
		BaseURL:          (&url.URL{Scheme: "https", Host: seedAddr}).String(),
		Agent:            cfg.Agent,
		TunnelName:       cfg.Network,
		Token:            cfg.Token,
		TLSConfig:        tlsConf,
		PacketConn:       seedPcQuic,
		Labels:           cfg.Labels,
		AdvertisedRoutes: cfg.AdvertisedRoutes,
		AgentInstance:    cfg.Instance,
	})
	if err != nil {
		return nil, fmt.Errorf("create seed API client: %w", err)
	}
	defer client.Close()

	slog.Info("Bootstrapping against seed relay", slog.String("relay", seedAddr))

	connectResp, err := client.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap connect to seed relay %q: %w", seedAddr, err)
	}

	// We're only using this connection for discovery. Close it gracefully.
	if err := client.Disconnect(ctx, connectResp.ID); err != nil {
		slog.Warn("Failed to disconnect bootstrap session",
			slog.String("id", connectResp.ID),
			slog.Any("error", err))
	}

	return &bootstrapInfo{Connect: connectResp}, nil
}

// discoverRelays lists ready relays whose network selector matches the given
// network and returns their dialable underlay addresses. A relay with a nil
// selector serves all networks (per RelaySpec).
func discoverRelays(ctx context.Context, vpc vpcclient.VpcV1alpha1Interface, network *vpcv1alpha1.VPCNetwork) (sets.Set[string], error) {
	relays, err := vpc.Relays().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing relays: %w", err)
	}
	addrs := sets.New[string]()
	for i := range relays.Items {
		relay := &relays.Items[i]
		if !relay.Status.Ready {
			continue
		}
		if relay.Spec.NetworkSelector != nil {
			sel, err := metav1.LabelSelectorAsSelector(relay.Spec.NetworkSelector)
			if err != nil {
				// One malformed Relay object must not poison discovery for the
				// whole fleet: failing the list here would freeze every agent's
				// pool refresh until the bad object is deleted.
				slog.Warn("Skipping relay with an invalid network selector",
					slog.String("relay", relay.Name),
					slog.Any("error", err))
				continue
			}
			if !sel.Matches(labels.Set(network.Labels)) {
				continue
			}
		}
		for _, a := range relay.Spec.Addresses {
			if a = strings.TrimSpace(a); a != "" {
				addrs.Insert(a)
			}
		}
	}
	return addrs, nil
}

// refreshRelayPool periodically re-lists ready relays and swaps them into the
// pool. An empty or failed refresh leaves the current pool untouched so a
// transient apiserver blip never strands the agent.
func refreshRelayPool(
	ctx context.Context,
	lister func(context.Context) (sets.Set[string], error),
	pool *randalloc.RandAllocator[string],
	interval time.Duration,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastApplied sets.Set[string]
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			addrs, err := lister(ctx)
			if err != nil {
				slog.Warn("Failed to refresh relay list; keeping current pool", slog.Any("error", err))
				continue
			}
			if addrs.Len() == 0 {
				slog.Warn("Relay refresh returned no ready relays; keeping current pool")
				continue
			}
			// Replace wakes every blocked connection slot, so skip the churn
			// when nothing changed (the common steady state).
			if lastApplied != nil && lastApplied.Equal(addrs) {
				continue
			}
			pool.Replace(addrs)
			lastApplied = addrs
		}
	}
}

type routerInitOpts struct {
	pcGeneve        batchpc.BatchPacketConn
	socksListenAddr string
	pcapPath        string
}

// initRouter creates and starts the ICXNetstackRouter / icx.Handler using the
// bootstrap response.
func initRouter(
	ctx context.Context,
	g *errgroup.Group,
	connectResp *api.ConnectResponse,
	opts routerInitOpts,
) (*router.ICXNetstackRouter, *icx.Handler, error) {
	routerOpts := []router.Option{
		router.WithPacketConn(opts.pcGeneve),
		router.WithTunnelMTU(connectResp.MTU),
	}

	if opts.socksListenAddr != "" {
		routerOpts = append(routerOpts, router.WithSocksListenAddr(opts.socksListenAddr))
	}
	if opts.pcapPath != "" {
		routerOpts = append(routerOpts, router.WithPcapPath(opts.pcapPath))
	}
	if connectResp.DNS != nil {
		routerOpts = append(routerOpts, router.WithResolveConfig(&network.ResolveConfig{
			Nameservers:   connectResp.DNS.Servers,
			SearchDomains: connectResp.DNS.SearchDomains,
			NDots:         connectResp.DNS.NDots,
		}))
	}

	r, err := router.NewICXNetstackRouter(routerOpts...)
	if err != nil {
		return nil, nil, err
	}

	h := r.Handler

	// Add routes.
	for _, rt := range connectResp.Routes {
		slog.Info("Adding route", slog.String("destination", rt.Destination))

		dst, err := netip.ParsePrefix(rt.Destination)
		if err != nil {
			slog.Warn("Failed to parse route prefix",
				slog.String("prefix", rt.Destination),
				slog.Any("error", err))
			continue
		}
		if err := r.AddRoute(dst); err != nil {
			slog.Warn("Failed to add route",
				slog.String("prefix", rt.Destination),
				slog.Any("error", err))
		}
	}

	// Start the router.
	g.Go(func() error { return r.Start(ctx) })

	return r, h, nil
}

// connectAndInitSession dials the relay, runs Connect, and returns the live
// api.Client, the ConnectResponse, and the handler. It also wires the relay
// into the handler via AddVirtualNetwork.
func connectAndInitSession(
	ctx context.Context,
	cfg agentConfig,
	pcQuic net.PacketConn,
	handler *icx.Handler,
	relayAddr string,
	tlsConf *tls.Config,
) (*api.Client, *api.ConnectResponse, *icx.Handler, error) {
	client, err := api.NewClient(api.ClientOptions{
		BaseURL:          (&url.URL{Scheme: "https", Host: relayAddr}).String(),
		Agent:            cfg.Agent,
		TunnelName:       cfg.Network,
		Token:            cfg.Token,
		TLSConfig:        tlsConf,
		PacketConn:       pcQuic,
		Labels:           cfg.Labels,
		AdvertisedRoutes: cfg.AdvertisedRoutes,
		AgentInstance:    cfg.Instance,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create API client: %w", err)
	}

	cleanupOnErr := func(e error) (*api.Client, *api.ConnectResponse, *icx.Handler, error) {
		_ = client.Close()
		return nil, nil, nil, e
	}

	slog.Info("Connecting to relay", slog.String("relay", relayAddr))

	connectResp, err := client.Connect(ctx)
	if err != nil {
		return cleanupOnErr(fmt.Errorf("connect to relay: %w", err))
	}

	remoteAddr, err := resolveAddrPort(ctx, relayAddr)
	if err != nil {
		return cleanupOnErr(fmt.Errorf("resolve relay addr %q: %w", relayAddr, err))
	}

	overlayAddrs, err := parsePrefixes(connectResp.Addresses)
	if err != nil {
		return cleanupOnErr(fmt.Errorf("parse assigned addresses: %w", err))
	}

	var allowedRoutes []icx.Route
	for _, route := range connectResp.Routes {
		dst, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			slog.Warn("Failed to parse route prefix",
				slog.String("prefix", route.Destination),
				slog.Any("error", err))
			continue
		}

		for _, addr := range overlayAddrs {
			allowedRoutes = append(allowedRoutes, icx.Route{
				Src: addr,
				Dst: dst,
			})
		}
	}

	if err := handler.AddVirtualNetwork(
		connectResp.VNI,
		netstack.ToFullAddress(remoteAddr),
		allowedRoutes,
	); err != nil {
		return cleanupOnErr(fmt.Errorf("add virtual network: %w", err))
	}

	slog.Info("Connected to relay",
		slog.String("relay", relayAddr),
		slog.String("id", connectResp.ID),
		slog.Int("vni", int(connectResp.VNI)),
		slog.Int("mtu", connectResp.MTU),
	)

	return client, connectResp, handler, nil
}

// closeSession best-effort disconnect + close of an active session.
func closeSession(client *api.Client, connID string) {
	if client == nil || connID == "" {
		return
	}
	disconnectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Disconnect(disconnectCtx, connID); err != nil {
		slog.Error("Failed to disconnect from tunnel",
			slog.String("id", connID),
			slog.Any("error", err))
	}
	slog.Info("Disconnected from tunnel", slog.String("id", connID))
	_ = client.Close()
}

// manageRelayConnectionOnce establishes and maintains a single relay session
// to the specified relayAddr over pcQuic. It will:
//
//   - retry Connect() until it succeeds or ctx is canceled
//   - once connected, run key rotation and watchdog concurrently
//   - whichever fails first ends the session
func manageRelayConnectionOnce(
	ctx context.Context,
	cfg agentConfig,
	pcQuic net.PacketConn,
	handler *icx.Handler,
	r *router.ICXNetstackRouter,
	relayAddr string,
	tlsConf *tls.Config,
) error {
	var (
		currentClient *api.Client
		currentConnID string
		connectResp   *api.ConnectResponse
		sessionAddrs  []netip.Prefix
	)

	// When this function returns, that relay session is down, so decrement
	// if we had actually marked it active.
	defer func() {
		// Remove any addrs we attached for this session.
		for _, a := range sessionAddrs {
			if err := r.DelAddr(a); err != nil {
				slog.Warn("Failed to remove address on disconnect",
					slog.String("address", a.String()),
					slog.Any("error", err))
			} else {
				slog.Info("Removed address", slog.String("address", a.String()))
			}
		}
		if currentConnID != "" {
			connectionHealthCounter.Add(-1)
		}
		closeSession(currentClient, currentConnID)
	}()

	// Keep retrying connect until context canceled.
	err := retry.Do(
		func() error {
			c, cr, _, err := connectAndInitSession(ctx, cfg, pcQuic, handler, relayAddr, tlsConf)
			if err != nil {
				return err
			}
			currentClient = c
			currentConnID = cr.ID
			connectResp = cr
			return nil
		},
		retry.Context(ctx),
		retry.OnRetry(func(n uint, err error) {
			slog.Warn("Reconnect attempt failed; backing off",
				slog.String("relay", relayAddr),
				slog.Uint64("attempt", uint64(n+1)),
				slog.Any("error", err))
		}),
		retry.LastErrorOnly(true),
	)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Error("Failed to (re)connect to relay",
			slog.String("relay", relayAddr),
			slog.Any("error", err))
		return fmt.Errorf("failed to connect to relay %q: %w", relayAddr, err)
	}

	// Successful session establishment: mark this connection active.
	connectionHealthCounter.Add(1)

	// Parse and attach the assigned addresses for this live session.
	if connectResp != nil {
		addrs, err := parsePrefixes(connectResp.Addresses)
		if err != nil {
			slog.Warn("Failed to parse assigned addresses", slog.Any("error", err))
		} else {
			sessionAddrs = addrs
			for _, a := range addrs {
				if err := r.AddAddr(a, nil); err != nil {
					slog.Warn("Failed to add address",
						slog.String("address", a.String()),
						slog.Any("error", err))
				} else {
					slog.Info("Added address", slog.String("address", a.String()))
				}
			}
		}
	}

	// Once connected, run key rotation and watchdog concurrently.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	g, gctx := errgroup.WithContext(sessionCtx)
	g.Go(func() error {
		return manageKeyRotation(
			gctx,
			handler,
			currentClient,
			currentConnID,
			connectResp.VNI,
			connectResp.Keys,
		)
	})
	g.Go(func() error {
		return relayWatchdog(
			gctx,
			handler,
			connectResp.VNI,
			watchdogMaxSilence,
			watchdogInterval,
		)
	})

	// Wait for either goroutine to return an error.
	waitErr := g.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if waitErr != nil && waitErr != context.Canceled {
		slog.Warn("Connection ended",
			slog.String("relay", relayAddr),
			slog.Any("error", waitErr))
	}
	return waitErr
}

// manageConnectionSlot owns one "connection slot" that we promised to keep
// active. It repeatedly:
//
//   - asks the relay address pool for an exclusive relay address
//   - opens a PacketConn to that relay
//   - runs manageRelayConnectionOnce
//   - when that session ends, releases the relay back to the pool
//
// If minConns > number of relays, extra goroutines will block in Acquire()
// until another slot releases a relay. This enforces "no two sessions to the
// same relay address" at any instant.
func manageConnectionSlot(
	ctx context.Context,
	cfg agentConfig,
	pcQuicMux *conntrackpc.ConntrackPacketConn,
	handler *icx.Handler,
	r *router.ICXNetstackRouter,
	relayAddressPool *randalloc.RandAllocator[string],
	tlsConf *tls.Config,
) error {
	for {
		// Block here until we get exclusive rights to a relay,
		// or until ctx is canceled.
		relayAddr, err := relayAddressPool.Acquire(ctx)
		if err != nil {
			return err // ctx canceled, etc.
		}

		slog.Info("Acquired relay slot",
			slog.String("relay", relayAddr))

		// We'll run the session in an inner func so we can defer cleanup
		// (pcQuic.Close) per-session but still always Release() after.
		err = func() error {
			// Resolve relay -> concrete IP:port.
			relayAddrParsed, err := resolveAddrPort(ctx, relayAddr)
			if err != nil {
				slog.Warn("failed to resolve relay, will pick a new relay",
					slog.String("relay", relayAddr),
					slog.Any("error", err))
				return nil // we'll just loop and Acquire again
			}

			// Open per-relay PacketConn off the shared mux.
			pcQuic, err := pcQuicMux.Open(&net.UDPAddr{
				IP:   relayAddrParsed.Addr().AsSlice(),
				Port: int(relayAddrParsed.Port()),
			})
			if err != nil {
				slog.Warn("failed to create multiplexed packet conn for relay, will pick a new relay",
					slog.String("relay", relayAddr),
					slog.Any("error", err))
				return nil // loop again
			}

			// Make sure we close the PacketConn when the session ends.
			defer pcQuic.Close()

			// Run the actual session lifecycle (watchdog, key rotation, etc). The
			// relay pool is refreshed out-of-band by refreshRelayPool, so no
			// per-connect pool update is needed here.
			sessErr := manageRelayConnectionOnce(ctx, cfg, pcQuic, handler, r, relayAddr, tlsConf)

			if ctx.Err() != nil {
				return ctx.Err()
			}

			if sessErr != nil && !errors.Is(sessErr, context.Canceled) {
				slog.Warn("Connection to relay ended; rotating to a new relay",
					slog.String("relay", relayAddr),
					slog.Any("error", sessErr))
			}
			return nil
		}()

		// Release the relay for other slots before the next loop iteration.
		relayAddressPool.Release(relayAddr)

		if err != nil {
			return err
		}

		// loop: grab a (maybe different) relay next time
	}
}

// manageKeyRotation applies initial keys and refreshes at half-life with retry
// on failures.
func manageKeyRotation(
	ctx context.Context,
	handler *icx.Handler,
	client *api.Client,
	connID string,
	vni uint,
	initial api.Keys,
) error {
	// applyKeys installs one epoch's keys, failing closed if the relay handed back
	// nothing usable. The agent is the Initiator; the relay installs the mirrored
	// Responder SPIs, so each epoch derives one distinct key per direction.
	applyKeys := func(k api.Keys) error {
		if k.MasterSecret == (api.MasterSecret{}) {
			return errors.New("relay returned an empty master secret")
		}
		rxSPI, txSPI, err := psp.EpochSPIs(psp.Initiator, k.Epoch)
		if err != nil {
			return fmt.Errorf("derive SPIs for epoch %d: %w", k.Epoch, err)
		}
		if err := handler.UpdateVirtualNetworkSecret(vni, [32]byte(k.MasterSecret), rxSPI, txSPI, k.ExpiresAt); err != nil {
			return fmt.Errorf("apply keys to router: %w", err)
		}
		return nil
	}

	// retryInterval is how long to wait before re-fetching keys after a failed
	// apply — short, so a transient failure does not leave the tunnel unkeyed for
	// half a key lifespan.
	const retryInterval = 10 * time.Second

	applyAndSchedule := func(k api.Keys) time.Duration {
		if err := applyKeys(k); err != nil {
			slog.Error("Failed to apply rotated keys; retrying soon", slog.Any("error", err))
			return retryInterval
		}
		remaining := time.Until(k.ExpiresAt)
		next := remaining / 2
		if next < retryInterval {
			next = retryInterval
		}
		return next
	}

	next := applyAndSchedule(initial)
	timer := time.NewTimer(next)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-timer.C:
			var upd *api.UpdateKeysResponse
			err := retry.Do(
				func() error {
					var err error
					upd, err = client.UpdateKeys(ctx, connID)
					return err
				},
				retry.Context(ctx),
				retry.Attempts(0), // keep trying until ctx canceled
				retry.OnRetry(func(n uint, err error) {
					slog.Warn("Key update failed; backing off",
						slog.Uint64("attempt", uint64(n+1)),
						slog.Any("error", err))
				}),
				retry.LastErrorOnly(true),
			)
			if err != nil {
				return err
			}

			slog.Info("Rotated tunnel keys",
				slog.Uint64("epoch", uint64(upd.Keys.Epoch)))

			timer.Reset(applyAndSchedule(upd.Keys))
		}
	}
}

// relayWatchdog monitors RX silence for a specific VNI and returns an error if
// we haven't received any packet from the remote in maxSilence.
// It polls at checkInterval and exits if ctx is canceled.
func relayWatchdog(
	ctx context.Context,
	handler *icx.Handler,
	vni uint,
	maxSilence time.Duration,
	checkInterval time.Duration,
) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			vnet, ok := handler.GetVirtualNetwork(vni)
			if !ok {
				// The VNI disappeared out from under us; treat as dead.
				return fmt.Errorf("relayWatchdog: VNI %d no longer present", vni)
			}

			lastRxNs := vnet.Stats.LastRXUnixNano.Load()
			now := time.Now()

			// If we've never received anything (0 == not set), this is suspicious,
			// but we don't want to instantly kill a brand new session.
			// We'll treat "never received" as "lastRx == connect time == now",
			// so it only trips after maxSilence has actually elapsed.
			var lastRx time.Time
			if lastRxNs == 0 {
				lastRx = now
			} else {
				lastRx = time.Unix(0, lastRxNs)
			}

			silence := now.Sub(lastRx)
			if silence > maxSilence {
				slog.Warn("relayWatchdog: RX silence threshold exceeded; declaring tunnel dead",
					slog.Uint64("vni", uint64(vni)),
					slog.Duration("silence", silence),
					slog.Duration("maxSilence", maxSilence),
					slog.Time("lastRx", lastRx),
				)
				return fmt.Errorf("rx silence (%s) exceeded max (%s)", silence, maxSilence)
			}
		}
	}
}

// resolveAddrPort resolves a host:port string into a netip.AddrPort by doing a
// short-lived UDP dial. This both resolves DNS and also captures the concrete
// remote address the OS actually chose.
func resolveAddrPort(ctx context.Context, relayAddr string) (netip.AddrPort, error) {
	// Create a short-lived UDP connection to the host:port.
	// This triggers the OS resolver and routing logic.
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", relayAddr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("probe dial failed for %q: %w", relayAddr, err)
	}
	defer conn.Close()

	// Extract the resolved remote address that the OS actually chose.
	ra := conn.RemoteAddr()
	udpAddr, ok := ra.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("unexpected remote addr type: %T", ra)
	}

	return netip.AddrPortFrom(netip.MustParseAddr(udpAddr.IP.String()), uint16(udpAddr.Port)), nil
}

// parsePrefixes parses a list of string addresses into netip.Prefixes.
func parsePrefixes(addrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address %q: %w", addr, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// healthHandler returns 200 OK when at least one tunnel connection is active,
// 503 otherwise. This is used by external health checks.
//
// Response codes:
//   - 200 OK: At least one tunnel connection is active
//   - 503 Service Unavailable: No active tunnel connections
//
// Body is plain text with a short summary.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	active := connectionHealthCounter.Load()

	if active > 0 {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK - %d active connection(s)\n", active)
		return
	}

	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w, "UNHEALTHY - no active connections\n")
}
