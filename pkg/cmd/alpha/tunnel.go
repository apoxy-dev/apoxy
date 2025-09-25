package alpha

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
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
	agentName          string
	tunnelName         string
	relayAddrs         []string
	token              string
	insecureSkipVerify bool
	socksListenAddr    string
	pcapPath           string
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnels",
	Long:  "Manage icx tunnels and connect to the remote Apoxy Edge fabric.",
}

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(relayAddrs) == 0 {
			return fmt.Errorf("no relay addresses provided; specify at least one via --relay-addrs")
		}

		// Create a single UDP socket and split for ICX/Geneve usage.
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return fmt.Errorf("failed to create UDP socket: %w", err)
		}
		defer pc.Close()

		pcGeneve, pcQuic := bifurcate.Bifurcate(pc)
		defer pcGeneve.Close()
		defer pcQuic.Close()

		pcQuicMultiplexed := conntrackpc.New(pcQuic, conntrackpc.Options{})
		defer pcQuicMultiplexed.Close()

		// Context and goroutines.
		g, ctx := errgroup.WithContext(cmd.Context())

		// Lazily initialize the router on first Connect().
		var (
			routerOnce sync.Once
			routerErr  error
			r          *router.ICXNetstackRouter
			handler    *icx.Handler
		)

		getHandler := func(connectResp *api.ConnectResponse) (*icx.Handler, error) {
			routerOnce.Do(func() {
				var routerOpts []router.Option
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

				r, routerErr = router.NewICXNetstackRouter(pcGeneve, connectResp.MTU, routerOpts...)
				if routerErr != nil {
					return
				}
				handler = r.Handler

				g.Go(func() error { return r.Start(ctx) })
			})
			return handler, routerErr
		}

		defer func() {
			// Best-effort close if the router was created.
			if r != nil {
				_ = r.Close()
			}
		}()

		// TLS config for all clients.
		tlsConf := &tls.Config{InsecureSkipVerify: insecureSkipVerify}

		// Connection manager per relay. Each goroutine independently keeps its relay connected,
		// registers its VN, rotates keys, and handles retry on failures.
		for _, raw := range relayAddrs {
			addr := strings.TrimSpace(raw)
			if addr == "" {
				continue
			}
			relay := addr
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

		// Wait for shutdown (any fatal error will bubble up).
		return g.Wait()
	},
}

func init() {
	tunnelRunCmd.Flags().StringVarP(&agentName, "agent", "a", "", "The name of this agent.")
	tunnelRunCmd.Flags().StringVarP(&tunnelName, "name", "n", "", "The logical name of the tunnel to connect to.")
	tunnelRunCmd.Flags().StringSliceVarP(&relayAddrs, "relay-addrs", "r", nil, "Comma-separated list of relay addresses (host:port) to connect to. May be specified multiple times.")
	tunnelRunCmd.Flags().StringVarP(&token, "token", "k", "", "The token to use for authenticating with the tunnel relays.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification for relay connections.")
	tunnelRunCmd.Flags().StringVarP(&pcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")

	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("agent"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("name"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("relay-addrs"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("token"))

	tunnelCmd.AddCommand(tunnelRunCmd)
}

// manageRelayConnection continually tries to connect to a single relay address, registers the VN on success,
// rotates keys, and cleans up on shutdown.
func manageRelayConnection(
	ctx context.Context,
	pcQuic net.PacketConn,
	getHandler func(*api.ConnectResponse) (*icx.Handler, error),
	relayAddr string,
	tlsConf *tls.Config,
) error {
	baseURL := url.URL{Scheme: "https", Host: relayAddr}

	// Helper to best-effort disconnect/close a live session.
	var (
		currentClient *api.Client
		currentConnID string
	)
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

	// Ensure we always clean up on function exit.
	defer disconnectClient()

	// This loop represents a full session lifecycle (connect -> rotate -> disconnect).
	// If the session ends (error or disconnect), we attempt to reconnect with retry-go.
	for {
		// Respect cancellation promptly.
		select {
		case <-ctx.Done():
			// Context canceled: clean up and exit.
			return ctx.Err()
		default:
		}

		var (
			connectResp *api.ConnectResponse
			handler     *icx.Handler
		)

		// Reconnect flow with exponential backoff and jitter.
		// If any step inside fails, we return an error from the retry func to back off and try again.
		err := retry.Do(
			func() error {
				var err error

				// Create client
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

				// If subsequent steps fail, make sure we close the client before the next retry attempt.
				cleanupOnErr := func(e error) error {
					_ = client.Close()
					return e
				}

				// Connect to relay
				slog.Info("Connecting to relay", slog.String("relay", relayAddr))

				connectResp, err = client.Connect(ctx)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("connect to relay: %w", err))
				}

				// Initialize router/handler on first successful connect
				handler, err = getHandler(connectResp)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("init router: %w", err))
				}

				// Resolve relay addr (supports hostname:port and ip:port)
				remoteAddr, err := resolveAddrPort(ctx, relayAddr)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("resolve relay addr %q: %w", relayAddr, err))
				}

				overlayAddrs, err := stringsToPrefixes(connectResp.Addresses)
				if err != nil {
					return cleanupOnErr(fmt.Errorf("parse assigned addresses: %w", err))
				}

				// Add VN to handler
				if err := handler.AddVirtualNetwork(connectResp.VNI, netstack.ToFullAddress(remoteAddr), overlayAddrs); err != nil {
					return cleanupOnErr(fmt.Errorf("add virtual network: %w", err))
				}

				// Success! Record live session and log.
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
			// Start with 1s, backoff exponentially, cap at 30s, with jitter.
			retry.Delay(1*time.Second),
			retry.MaxDelay(30*time.Second),
			retry.DelayType(retry.BackOffDelay),
			// Keep retrying until context is canceled.
			retry.Attempts(0),
			// Log each retry.
			retry.OnRetry(func(n uint, err error) {
				slog.Warn("Reconnect attempt failed; backing off",
					slog.String("relay", relayAddr),
					slog.Uint64("attempt", uint64(n+1)),
					slog.Any("error", err))
			}),
			retry.LastErrorOnly(true),
		)

		// If we exited retry because context is done, stop everything.
		if err != nil {
			// If ctx is done, return; otherwise, this is an unexpected terminal error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Shouldn't normally hit here due to Attempts(0)+Context(ctx), but guard anyway.
			slog.Error("Failed to (re)connect to relay", slog.String("relay", relayAddr), slog.Any("error", err))
			// Small sleep to avoid tight loop in a truly pathological case.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// From here on, we have a live client/connection; manage key rotation until it ends.
		waitErr := manageKeyRotation(ctx, handler, currentClient, connectResp.VNI, currentConnID, connectResp.Keys)

		// Cleanup this session: disconnect/close locally.
		disconnectClient()

		if ctx.Err() != nil {
			// Global shutdown.
			return ctx.Err()
		}

		// Rotation ended unexpectedly (e.g., error from UpdateKeys); log and reconnect.
		if waitErr != nil && waitErr != context.Canceled {
			slog.Warn("Key rotation ended; will attempt to reconnect",
				slog.String("relay", relayAddr), slog.Any("error", waitErr))
		}

		// Loop to reconnect (retry-go inside will handle backoff).
	}
}

// manageKeyRotation applies the initial keys and then rotates keys at half-life.
// When UpdateKeys fails, it uses avast/retry-go for exponential backoff retries.
func manageKeyRotation(
	ctx context.Context,
	handler *icx.Handler,
	client *api.Client,
	vni uint,
	connID string,
	initial api.Keys,
) error {
	// Helper to apply keys and compute the next refresh interval (half-life with a minimum floor).
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

	// Seed initial schedule from the keys we got on Connect.
	next := applyAndSchedule(initial)

	timer := time.NewTimer(next)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			// Attempt rotation with retry-go backoff. We retry until success or ctx cancellation.
			var upd *api.UpdateKeysResponse
			err := retry.Do(
				func() error {
					var err error
					upd, err = client.UpdateKeys(ctx, connID)
					if err != nil {
						return err
					}
					return nil
				},
				retry.Context(ctx),
				retry.Delay(1*time.Second),
				retry.MaxDelay(20*time.Second),
				retry.DelayType(retry.BackOffDelay),
				retry.Attempts(0), // keep retrying until context is canceled
				retry.OnRetry(func(n uint, err error) {
					slog.Warn("Key update failed; backing off",
						slog.Uint64("attempt", uint64(n+1)),
						slog.Any("error", err))
				}),
				retry.LastErrorOnly(true),
			)
			if err != nil {
				// Context canceled during retry or other terminal condition; exit.
				return err
			}

			slog.Info("Rotated tunnel keys", slog.Uint64("epoch", uint64(upd.Keys.Epoch)))
			timer.Reset(applyAndSchedule(upd.Keys))
		}
	}
}

// resolveAddrPort accepts "host:port" where host may be a hostname or IP
// (IPv4/IPv6, with or without brackets) and returns a concrete netip.AddrPort.
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

	// If host is already an IP, use it.
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, port), nil
	}

	// Resolve hostname. Prefer IPv4, then IPv6.
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
