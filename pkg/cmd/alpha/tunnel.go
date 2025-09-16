package alpha

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/dpeckett/network"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

var (
	agentName          string
	tunnelName         string
	relayAddr          string
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
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return fmt.Errorf("failed to create UDP socket: %w", err)
		}
		defer pc.Close()

		pcGeneve, pcQuic := bifurcate.Bifurcate(pc)
		defer pcGeneve.Close()
		defer pcQuic.Close()

		apiURL := url.URL{
			Scheme: "https",
			Host:   relayAddr,
		}
		if insecureSkipVerify {
			apiURL.Scheme = "http"
		}

		tlsConf := &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		}

		client, err := api.NewClient(api.ClientOptions{
			BaseURL:    apiURL.String(),
			Agent:      agentName,
			TunnelName: tunnelName,
			Token:      token,
			TLSConfig:  tlsConf,
		})
		if err != nil {
			return fmt.Errorf("failed to create tunnel API client: %w", err)
		}
		defer client.Close()

		connectResp, err := client.Connect(cmd.Context())
		if err != nil {
			return fmt.Errorf("failed to connect to tunnel relay: %w", err)
		}

		// Ensure we disconnect when the command exits
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

			err := client.Disconnect(ctx, connectResp.ID)
			cancel()
			if err != nil {
				slog.Error("Failed to disconnect from tunnel", slog.Any("error", err))
			}
		}()

		slog.Info("Connected to tunnel relay", slog.String("id", connectResp.ID),
			slog.Int("vni", int(connectResp.VNI)), slog.Int("mtu", connectResp.MTU))

		var routerOpts []router.Option

		if connectResp.DNS != nil {
			resolveConf := &network.ResolveConfig{
				Nameservers:   connectResp.DNS.Servers,
				SearchDomains: connectResp.DNS.SearchDomains,
				NDots:         connectResp.DNS.NDots,
			}
			routerOpts = append(routerOpts, router.WithResolveConfig(resolveConf))
		}

		if socksListenAddr != "" {
			routerOpts = append(routerOpts, router.WithSocksListenAddr(socksListenAddr))
		}

		if pcapPath != "" {
			routerOpts = append(routerOpts, router.WithPcapPath(pcapPath))
		}

		r, err := router.NewICXNetstackRouter(pcGeneve, connectResp.MTU, routerOpts...)
		if err != nil {
			return fmt.Errorf("failed to create ICX netstack router: %w", err)
		}
		defer r.Close()

		remoteAddr, err := netip.ParseAddrPort(relayAddr)
		if err != nil {
			return fmt.Errorf("failed to parse relay address: %w", err)
		}

		overlayAddrs, err := stringsToPrefixes(connectResp.Addresses)
		if err != nil {
			return fmt.Errorf("failed to parse assigned addresses: %w", err)
		}

		if err := r.Handler.AddVirtualNetwork(connectResp.VNI, netstack.ToFullAddress(remoteAddr), overlayAddrs); err != nil {
			return fmt.Errorf("failed to add virtual network to ICX handler: %w", err)
		}

		g, ctx := errgroup.WithContext(cmd.Context())

		g.Go(func() error {
			// Rotate keys at half-life; retry with a short backoff on failure.
			apply := func(k api.Keys) time.Duration {
				// Apply new keys to the ICX handler.
				if err := r.Handler.UpdateVirtualNetworkKeys(connectResp.VNI, k.Epoch, k.Recv, k.Send, k.ExpiresAt); err != nil {
					slog.Error("Failed to apply new keys to router", slog.Any("error", err))
				}

				// Compute next refresh: half of remaining lifetime.
				remaining := time.Until(k.ExpiresAt)
				next := remaining / 2
				// Clamp to a sensible minimum to avoid tight loops.
				if next < 10*time.Second {
					next = 10 * time.Second
				}
				return next
			}

			// Seed initial schedule from the keys we got on Connect.
			next := apply(connectResp.Keys)

			timer := time.NewTimer(next)
			defer timer.Stop()

			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					// Try to rotate keys.
					upd, err := client.UpdateKeys(ctx, connectResp.ID)
					if err != nil {
						slog.Warn("Key update failed; retrying soon", slog.Any("error", err))
						timer.Reset(5 * time.Second)
						continue
					}

					slog.Info("Rotated tunnel keys", slog.Uint64("epoch", uint64(upd.Keys.Epoch)))
					timer.Reset(apply(upd.Keys))
				}
			}
		})

		g.Go(func() error {
			return r.Start(ctx)
		})

		return g.Wait()
	},
}

func init() {
	tunnelRunCmd.Flags().StringVarP(&agentName, "agent", "a", "", "The name of this agent.")
	tunnelRunCmd.Flags().StringVarP(&tunnelName, "name", "n", "", "The name of the tunnel to connect to.")
	tunnelRunCmd.Flags().StringVarP(&relayAddr, "relay-addr", "r", "", "The address of the tunnel relay to connect to.")
	tunnelRunCmd.Flags().StringVarP(&token, "token", "k", "", "The token to use for authenticating with the tunnel relay.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification.")
	tunnelRunCmd.Flags().StringVarP(&pcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("agent"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("name"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("relay-addr"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("token"))

	tunnelCmd.AddCommand(tunnelRunCmd)
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
