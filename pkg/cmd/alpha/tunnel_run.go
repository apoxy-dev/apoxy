package alpha

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/avast/retry-go/v4"
	"github.com/dpeckett/network"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
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
)

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if minConns < 1 {
			return fmt.Errorf("--min-conns must be at least 1")
		}

		// One UDP socket shared between Geneve (data) and QUIC (control).
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return fmt.Errorf("failed to create UDP socket: %w", err)
		}
		defer pc.Close()

		pcGeneve, pcQuic := bifurcate.Bifurcate(pc)
		defer pcGeneve.Close()
		defer pcQuic.Close()

		// Share a single QUIC socket across multiple relays.
		pcQuicMultiplexed := conntrackpc.New(pcQuic, conntrackpc.Options{})
		defer pcQuicMultiplexed.Close()

		g, ctx := errgroup.WithContext(cmd.Context())

		var (
			routerOnce sync.Once
			routerErr  error
			r          *router.ICXNetstackRouter
			handler    *icx.Handler
		)

		// Lazily create router/handler on first successful Connect.
		getHandler := func(connectResp *api.ConnectResponse) (*icx.Handler, error) {
			routerOnce.Do(func() {
				routerOpts := []router.Option{
					router.WithPacketConn(pcGeneve),
					router.WithTunnelMTU(connectResp.MTU),
				}

				if socksListenAddr != "" {
					routerOpts = append(routerOpts, router.WithSocksListenAddr(socksListenAddr))
				}
				if pcapPath != "" {
					routerOpts = append(routerOpts, router.WithPcapPath(pcapPath))
				}
				if connectResp.DNS != nil {
					resolveConf := &network.ResolveConfig{
						Nameservers:   connectResp.DNS.Servers,
						SearchDomains: connectResp.DNS.SearchDomains,
						NDots:         connectResp.DNS.NDots,
					}
					routerOpts = append(routerOpts, router.WithResolveConfig(resolveConf))
				}

				r, routerErr = router.NewICXNetstackRouter(routerOpts...)
				if routerErr != nil {
					return
				}
				handler = r.Handler

				for _, addrStr := range connectResp.Addresses {
					slog.Info("Adding address", slog.String("address", addrStr))

					addr, err := netip.ParsePrefix(addrStr)
					if err != nil {
						slog.Warn("Failed to parse address", slog.String("address", addrStr), slog.Any("error", err))
						continue
					}

					if err := r.AddAddr(addr, nil); err != nil {
						slog.Warn("Failed to add address", slog.String("address", addrStr), slog.Any("error", err))
					}
				}

				for _, route := range connectResp.Routes {
					slog.Info("Adding route", slog.String("destination", route.Destination))

					dst, err := netip.ParsePrefix(route.Destination)
					if err != nil {
						slog.Warn("Failed to parse route prefix", slog.String("prefix", route.Destination), slog.Any("error", err))
						continue
					}
					if err := r.AddRoute(dst); err != nil {
						slog.Warn("Failed to add route", slog.String("prefix", route.Destination), slog.Any("error", err))
					}
				}

				g.Go(func() error { return r.Start(ctx) })
			})
			return handler, routerErr
		}

		defer func() {
			if r != nil {
				_ = r.Close()
			}
		}()

		tlsConf := &tls.Config{InsecureSkipVerify: insecureSkipVerify}

		// Bootstrap via seed relay to fetch MTU/DNS/routes and the relay pool.
		seedAddr := strings.TrimSpace(seedRelayAddr)
		seedResolved, err := resolveAddrPort(ctx, seedAddr)
		if err != nil {
			return fmt.Errorf("failed to resolve seed relay addr %q: %w", seedAddr, err)
		}

		seedPcQuic, err := pcQuicMultiplexed.Open(&net.UDPAddr{
			IP:   seedResolved.Addr().AsSlice(),
			Port: int(seedResolved.Port()),
		})
		if err != nil {
			return fmt.Errorf("failed to create multiplexed packet conn for seed relay %q: %w", seedAddr, err)
		}
		defer seedPcQuic.Close()

		seedBaseURL := url.URL{Scheme: "https", Host: seedAddr}
		seedClient, err := api.NewClient(api.ClientOptions{
			BaseURL:    seedBaseURL.String(),
			Agent:      agentName,
			TunnelName: tunnelName,
			Token:      token,
			TLSConfig:  tlsConf,
			PacketConn: seedPcQuic,
		})
		if err != nil {
			return fmt.Errorf("create seed API client: %w", err)
		}

		slog.Info("Bootstrapping against seed relay", slog.String("relay", seedAddr))

		seedResp, err := seedClient.Connect(ctx)
		if err != nil {
			_ = seedClient.Close()
			return fmt.Errorf("bootstrap connect to seed relay %q: %w", seedAddr, err)
		}

		// Initialize router (MTU, DNS, routes) based on bootstrap response.
		if _, err := getHandler(seedResp); err != nil {
			_ = seedClient.Close()
			return fmt.Errorf("init router: %w", err)
		}

		// Close bootstrap session; steady-state connections are created below.
		if err := seedClient.Disconnect(ctx, seedResp.ID); err != nil {
			slog.Warn("Failed to disconnect bootstrap session", slog.String("id", seedResp.ID), slog.Any("error", err))
		}
		_ = seedClient.Close()

		// Build unique relay pool (ensure seed included once).
		pool := make([]string, 0, len(seedResp.RelayAddresses)+1)
		seen := map[string]struct{}{}
		add := func(a string) {
			a = strings.TrimSpace(a)
			if a == "" {
				return
			}
			if _, ok := seen[a]; ok {
				return
			}
			seen[a] = struct{}{}
			pool = append(pool, a)
		}
		for _, a := range seedResp.RelayAddresses {
			add(a)
		}
		add(seedAddr)

		if len(pool) == 0 {
			return fmt.Errorf("server did not return any relay addresses and seed was empty")
		}

		// Randomly pick up to minConns relays.
		rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		n := minConns
		if n > len(pool) {
			n = len(pool)
		}
		selected := pool[:n]

		slog.Info("Selected relays for steady-state connections",
			slog.Int("minConns", minConns),
			slog.Int("selected", len(selected)),
			slog.Any("relays", selected),
		)

		// One connection manager per relay.
		for _, relay := range selected {
			relay := relay
			g.Go(func() error {
				relayAddr, err := resolveAddrPort(ctx, relay)
				if err != nil {
					return fmt.Errorf("failed to resolve relay addr %q: %w", relay, err)
				}

				pcQuic, err := pcQuicMultiplexed.Open(&net.UDPAddr{
					IP:   relayAddr.Addr().AsSlice(),
					Port: int(relayAddr.Port()),
				})
				if err != nil {
					return fmt.Errorf("failed to create multiplexed packet conn for relay %q: %w", relay, err)
				}
				defer pcQuic.Close()

				return manageRelayConnection(ctx, pcQuic, getHandler, relay, tlsConf)
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

	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("agent"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("name"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("relay-addr"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("token"))

	tunnelCmd.AddCommand(tunnelRunCmd)
}

// manageRelayConnection keeps a single relay session alive (connect → rotate-keys → reconnect).
func manageRelayConnection(
	ctx context.Context,
	pcQuic net.PacketConn,
	getHandler func(*api.ConnectResponse) (*icx.Handler, error),
	relayAddr string,
	tlsConf *tls.Config,
) error {
	baseURL := url.URL{Scheme: "https", Host: relayAddr}

	var (
		currentClient *api.Client
		currentConnID string
	)

	// Best-effort disconnect/close of the active session.
	disconnectClient := func() {
		if currentClient == nil || currentConnID == "" {
			return
		}
		disconnectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := currentClient.Disconnect(disconnectCtx, currentConnID); err != nil {
			slog.Error("Failed to disconnect from tunnel", slog.String("id", currentConnID), slog.Any("error", err))
		}
		slog.Info("Disconnected from tunnel", slog.String("id", currentConnID))
		_ = currentClient.Close()
		currentClient = nil
		currentConnID = ""
	}
	defer disconnectClient()

	// Session lifecycle loop.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var (
			connectResp *api.ConnectResponse
			handler     *icx.Handler
		)

		// Connect with exponential backoff.
		err := retry.Do(
			func() error {
				client, err := api.NewClient(api.ClientOptions{
					BaseURL:    baseURL.String(),
					Agent:      agentName,
					TunnelName: tunnelName,
					Token:      token,
					TLSConfig:  tlsConf,
					PacketConn: pcQuic,
				})
				if err != nil {
					return fmt.Errorf("create API client: %w", err)
				}

				cleanupOnErr := func(e error) error {
					_ = client.Close()
					return e
				}

				slog.Info("Connecting to relay", slog.String("relay", relayAddr))

				connectResp, err = client.Connect(ctx)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("connect to relay: %w", err))
				}

				handler, err = getHandler(connectResp)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("init router: %w", err))
				}

				remoteAddr, err := resolveAddrPort(ctx, relayAddr)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("resolve relay addr %q: %w", relayAddr, err))
				}

				overlayAddrs, err := stringsToPrefixes(connectResp.Addresses)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("parse assigned addresses: %w", err))
				}

				for _, route := range connectResp.Routes {
					dst, err := netip.ParsePrefix(route.Destination)
					if err != nil {
						slog.Warn("Failed to parse route prefix", slog.String("prefix", route.Destination), slog.Any("error", err))
						continue
					}

					overlayAddrs = append(overlayAddrs, dst)
				}

				if err := handler.AddVirtualNetwork(connectResp.VNI, netstack.ToFullAddress(remoteAddr), overlayAddrs); err != nil {
					return cleanupOnErr(fmt.Errorf("add virtual network: %w", err))
				}

				currentClient = client
				currentConnID = connectResp.ID

				slog.Info("Connected to relay",
					slog.String("relay", relayAddr),
					slog.String("id", connectResp.ID),
					slog.Int("vni", int(connectResp.VNI)),
					slog.Int("mtu", connectResp.MTU),
				)

				return nil
			},
			retry.Context(ctx),
			retry.Attempts(0), // until ctx canceled
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
			slog.Error("Failed to (re)connect to relay", slog.String("relay", relayAddr), slog.Any("error", err))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// Live connection: rotate keys until failure or shutdown.
		waitErr := manageKeyRotation(ctx, handler, currentClient, currentConnID, connectResp.VNI, connectResp.Keys)

		disconnectClient()

		if ctx.Err() != nil {
			return ctx.Err()
		}
		if waitErr != nil && waitErr != context.Canceled {
			slog.Warn("Key rotation ended; will attempt to reconnect",
				slog.String("relay", relayAddr), slog.Any("error", waitErr))
		}
	}
}

// manageKeyRotation applies initial keys and refreshes at half-life with retry on failures.
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
				retry.Attempts(0), // until ctx canceled
				retry.OnRetry(func(n uint, err error) {
					slog.Warn("Key update failed; backing off",
						slog.Uint64("attempt", uint64(n+1)),
						slog.Any("error", err))
				}),
				retry.LastErrorOnly(true),
			)
			if err != nil {
				return err // includes context cancellation
			}
			slog.Info("Rotated tunnel keys", slog.Uint64("epoch", uint64(upd.Keys.Epoch)))
			timer.Reset(applyAndSchedule(upd.Keys))
		}
	}
}

// resolveAddrPort resolves "host:port" (IPv4/IPv6/hostname) to a concrete AddrPort, preferring IPv4.
func resolveAddrPort(ctx context.Context, hostport string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("split host/port: %w", err)
	}
	pn, err := net.LookupPort("udp", portStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("lookup port %q: %w", portStr, err)
	}
	port := uint16(pn)

	// Fast-path for literal IPs.
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, port), nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("lookup %q: %w", host, err)
	}
	var v4, v6 *netip.Addr
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			if ip.Is4() && v4 == nil {
				ipCopy := ip
				v4 = &ipCopy
			} else if ip.Is6() && v6 == nil {
				ipCopy := ip
				v6 = &ipCopy
			}
		}
	}
	switch {
	case v4 != nil:
		return netip.AddrPortFrom(*v4, port), nil
	case v6 != nil:
		return netip.AddrPortFrom(*v6, port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("no usable A/AAAA records for %q", host)
	}
}

func stringsToPrefixes(addrs []string) ([]netip.Prefix, error) {
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
