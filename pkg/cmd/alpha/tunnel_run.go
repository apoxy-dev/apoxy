package alpha

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/avast/retry-go/v4"
	"github.com/dpeckett/network"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

// Watchdog tuning knobs
const (
	watchdogMaxSilence = 120 * time.Second
	watchdogInterval   = 5 * time.Second
)

var (
	agentName          string // agent identifier
	tunnelName         string // tunnel identifier
	seedRelayAddr      string // bootstrap relay (host:port)
	minConns           int    // min concurrent relay connections
	token              string // tunnel auth token
	insecureSkipVerify bool   // skip TLS verification (testing only)
	socksListenAddr    string // SOCKS listen address
	pcapPath           string // optional pcap path
	healthAddr         string // listen address for health endpoint (e.g. ":8080"); empty disables
)

// connectionHealthCounter tracks how many relay sessions are currently live.
var connectionHealthCounter atomic.Int32

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if minConns < 1 {
			return fmt.Errorf("--min-conns must be at least 1")
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
		boot, err := bootstrapSession(ctx, seedRelayAddr, packetPlane.QuicMux, tlsConf)
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

		// Create an allocator that ensures we never connect to the same relay
		// from multiple slots at once.
		alloc := randalloc.NewRandAllocator(boot.RelayAddresses)

		// Spawn minConns independent connection slots.
		// Each slot:
		//   - acquires a unique relay from the allocator
		//   - connects & manages that session
		//   - when the session ends, releases the relay
		for i := 0; i < minConns; i++ {
			g.Go(func() error {
				return manageConnectionSlot(ctx, packetPlane.QuicMux, handler, alloc, tlsConf)
			})
		}

		return g.Wait()
	},
}

func init() {
	tunnelRunCmd.Flags().StringVarP(&agentName, "agent", "a", "", "The name of this agent.")
	tunnelRunCmd.Flags().StringVarP(&tunnelName, "name", "n", "", "The logical name of the tunnel to connect to.")
	tunnelRunCmd.Flags().StringVarP(&seedRelayAddr, "relay-addr", "r", "", "Seed relay address (host:port). The client bootstraps here, then uses the returned relay list.")
	tunnelRunCmd.Flags().IntVar(&minConns, "min-conns", 1, "Minimum number of relays to maintain connections to (randomly selected from the server-provided list).")
	tunnelRunCmd.Flags().StringVarP(&token, "token", "k", "", "The token to use for authenticating with the tunnel relays.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification for relay connections.")
	tunnelRunCmd.Flags().StringVarP(&pcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")
	tunnelRunCmd.Flags().StringVar(&healthAddr, "health-addr", "localhost:8080", "Listen address for health endpoint (e.g. \":8080\"). Empty disables.")

	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("agent"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("name"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("relay-addr"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("token"))

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
	lis, err := net.ListenPacket("udp", ":0")
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
	Connect        *api.ConnectResponse
	RelayAddresses sets.Set[string]
}

// bootstrapSession connects to the seed relay, retrieves tunnel config and
// the relay address pool, disconnects, and returns that bootstrap data.
func bootstrapSession(
	ctx context.Context,
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
		BaseURL:    (&url.URL{Scheme: "https", Host: seedAddr}).String(),
		Agent:      agentName,
		TunnelName: tunnelName,
		Token:      token,
		TLSConfig:  tlsConf,
		PacketConn: seedPcQuic,
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

	// Build a deduped set of relay addresses (seed + server-provided).
	addrSet := sets.New[string]()

	trimmedSeed := strings.TrimSpace(seedAddr)
	if trimmedSeed != "" {
		addrSet.Insert(trimmedSeed)
	}
	for _, a := range connectResp.RelayAddresses {
		a = strings.TrimSpace(a)
		if a != "" {
			addrSet.Insert(a)
		}
	}

	return &bootstrapInfo{
		Connect:        connectResp,
		RelayAddresses: addrSet,
	}, nil
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

	// Add assigned addresses.
	for _, addrStr := range connectResp.Addresses {
		slog.Info("Adding address", slog.String("address", addrStr))

		addr, err := netip.ParsePrefix(addrStr)
		if err != nil {
			slog.Warn("Failed to parse address",
				slog.String("address", addrStr),
				slog.Any("error", err))
			continue
		}

		if err := r.AddAddr(addr, nil); err != nil {
			slog.Warn("Failed to add address",
				slog.String("address", addrStr),
				slog.Any("error", err))
		}
	}

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
	pcQuic net.PacketConn,
	handler *icx.Handler,
	relayAddr string,
	tlsConf *tls.Config,
) (*api.Client, *api.ConnectResponse, *icx.Handler, error) {
	client, err := api.NewClient(api.ClientOptions{
		BaseURL:    (&url.URL{Scheme: "https", Host: relayAddr}).String(),
		Agent:      agentName,
		TunnelName: tunnelName,
		Token:      token,
		TLSConfig:  tlsConf,
		PacketConn: pcQuic,
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

	for _, route := range connectResp.Routes {
		dst, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			slog.Warn("Failed to parse route prefix",
				slog.String("prefix", route.Destination),
				slog.Any("error", err))
			continue
		}
		overlayAddrs = append(overlayAddrs, dst)
	}

	if err := handler.AddVirtualNetwork(
		connectResp.VNI,
		netstack.ToFullAddress(remoteAddr),
		overlayAddrs,
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
//
// It also increments/decrements connectionHealthCounter so that /healthz
// can report whether we currently have any active sessions.
func manageRelayConnectionOnce(
	ctx context.Context,
	pcQuic net.PacketConn,
	handler *icx.Handler,
	relayAddr string,
	tlsConf *tls.Config,
) error {
	var (
		currentClient *api.Client
		currentConnID string
		connectResp   *api.ConnectResponse
	)

	// When this function returns, that relay session is down, so decrement
	// if we had actually marked it active.
	defer func() {
		if currentConnID != "" {
			connectionHealthCounter.Add(-1)
		}
		closeSession(currentClient, currentConnID)
	}()

	// Keep retrying connect until context canceled.
	err := retry.Do(
		func() error {
			c, cr, _, err := connectAndInitSession(ctx, pcQuic, handler, relayAddr, tlsConf)
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
//   - asks the allocator for an exclusive relay address
//   - opens a PacketConn to that relay
//   - runs manageRelayConnectionOnce
//   - when that session ends, releases the relay back to the allocator
//
// If minConns > number of relays, extra goroutines will block in Acquire()
// until another slot releases a relay. This enforces "no two sessions to the
// same relay address" at any instant.
func manageConnectionSlot(
	ctx context.Context,
	pcQuicMux *conntrackpc.ConntrackPacketConn,
	handler *icx.Handler,
	alloc *randalloc.RandAllocator[string],
	tlsConf *tls.Config,
) error {
	for {
		// Block here until we get exclusive rights to a relay,
		// or until ctx is canceled.
		relayAddr, err := alloc.Acquire(ctx)
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

			// Run the actual session lifecycle (watchdog, key rotation, etc).
			sessErr := manageRelayConnectionOnce(ctx, pcQuic, handler, relayAddr, tlsConf)

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
		alloc.Release(relayAddr)

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
	applyAndSchedule := func(k api.Keys) time.Duration {
		if err := handler.UpdateVirtualNetworkKeys(vni, k.Epoch, k.Recv, k.Send, k.ExpiresAt); err != nil {
			slog.Error("Failed to apply new keys to router", slog.Any("error", err))
		}
		remaining := time.Until(k.ExpiresAt)
		next := remaining / 2
		if next < 10*time.Second {
			next = 10 * time.Second
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
