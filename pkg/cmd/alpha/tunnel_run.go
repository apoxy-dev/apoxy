package alpha

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/apoxy-dev/apoxy/client/versioned"
	vpcclient "github.com/apoxy-dev/apoxy/client/versioned/typed/vpc/v1alpha1"
	apoxyconfig "github.com/apoxy-dev/apoxy/config"
	tunnelagent "github.com/apoxy-dev/apoxy/pkg/tunnel/agent"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
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
	tunMode            bool              // kernel TUN datapath instead of netstack+SOCKS (--tun)
	tunIfaceName       string            // TUN interface name (--tun-ifname)
	healthAddr         string            // listen address for health endpoint (e.g. ":8080"); empty disables
	agentLabels        map[string]string // agent-declared labels for VPCService selection (--label)
	advertisedRoutes   []string          // CIDRs reachable behind this agent (--route)
)

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
		for _, r := range advertisedRoutes {
			if _, err := netip.ParsePrefix(r); err != nil {
				return fmt.Errorf("invalid --route: %w", err)
			}
		}

		// relayLister, when set (discovery mode), returns the current set of
		// ready relay addresses serving the network. It seeds the initial
		// pool and is polled in the background so relays coming and going are
		// picked up without a restart. It stays nil in static (--relay-addr) mode.
		var relayLister func(context.Context) (sets.Set[string], error)
		var discoveredRelays sets.Set[string]

		// Discover relays and the connect credential from the project
		// apiserver if no relayAddr/token provided. The CLI's own configured
		// client (apoxy auth login / config file) is preferred; a kubeconfig
		// is the fallback for agents running inside a cluster where the
		// project APIs are aggregated (apoxy k8s install).
		if seedRelayAddr == "" || token == "" {
			var vpcClient vpcclient.VpcV1alpha1Interface
			if c, err := apoxyconfig.DefaultAPIClient(); err == nil {
				vpcClient = c.VpcV1alpha1()
			} else {
				// DefaultAPIClient fails when there is no config, no current
				// project, or no credential (ErrNoCredentials) — all states
				// where the kubeconfig/in-cluster path is the right answer.
				slog.Info("No usable apoxy client config, falling back to kubeconfig discovery", slog.Any("reason", err))
				clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
					clientcmd.NewDefaultClientConfigLoadingRules(),
					&clientcmd.ConfigOverrides{},
				)

				config, kerr := clientConfig.ClientConfig()
				if kerr != nil {
					return fmt.Errorf("no apoxy config (%w) and loading kubeconfig failed: %w", err, kerr)
				}

				clientset, kerr := versioned.NewForConfig(config)
				if kerr != nil {
					return fmt.Errorf("creating clientset: %w", kerr)
				}
				vpcClient = clientset.VpcV1alpha1()
			}

			// VPCNetwork carries the connect credential; ready Relay objects
			// carry the dialable underlay addresses. The relay no longer reports a
			// peer list in ConnectResponse (§2.3) — the agent discovers and tracks
			// relays directly from the apiserver.
			network, err := vpcClient.VPCNetworks().Get(cmd.Context(), tunnelName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("fetching VPCNetwork %q: %w", tunnelName, err)
			}
			if network.Status.Credentials == nil || network.Status.Credentials.Token == "" {
				return fmt.Errorf("network %q has no credentials configured", tunnelName)
			}
			token = network.Status.Credentials.Token

			relayLister = tunnelagent.NewRelayLister(vpcClient, network.Name)

			discoveredRelays, err = relayLister(cmd.Context())
			if err != nil {
				return err
			}
			if discoveredRelays.Len() == 0 {
				return fmt.Errorf("no ready relays serving network %q", tunnelName)
			}
		}

		g, ctx := errgroup.WithContext(cmd.Context())

		// Start health endpoint server if configured.
		if strings.TrimSpace(healthAddr) != "" {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", tunnelagent.HealthHandler)

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

		g.Go(func() error {
			return tunnelagent.Run(ctx, tunnelagent.Config{
				Agent:            agentName,
				Network:          tunnelName,
				Token:            token,
				Labels:           agentLabels,
				AdvertisedRoutes: advertisedRoutes,
				// The agent-instance UUID is stable for this process's
				// lifetime; the relay stamps it onto each Tunnel so multiple
				// connections from one process are attributable to the same
				// instance.
				Instance:        metrics.AgentProcessID(),
				SeedRelayAddr:   seedRelayAddr,
				SeedRelays:      discoveredRelays,
				RelayLister:     relayLister,
				MinConns:        minConns,
				TLSConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
				SocksListenAddr: socksListenAddr,
				PcapPath:        pcapPath,
				TunMode:         tunMode,
				TunIfaceName:    tunIfaceName,
			})
		})

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
	tunnelRunCmd.Flags().BoolVar(&tunMode, "tun", false, "Use a kernel TUN device for the overlay datapath instead of the in-process netstack + SOCKS proxy. Any process in the same network namespace can then reach overlay destinations by plain kernel route. Linux only; requires NET_ADMIN and /dev/net/tun.")
	tunnelRunCmd.Flags().StringVar(&tunIfaceName, "tun-ifname", "apoxy0", "Name of the TUN interface created in --tun mode.")
	tunnelRunCmd.Flags().StringVar(&healthAddr, "health-addr", "localhost:8080", "Listen address for health endpoint (e.g. \":8080\"). Empty disables.")
	tunnelRunCmd.Flags().StringToStringVar(&agentLabels, "label", nil, "Agent-declared label (key=value) for VPCService selection; repeatable. Bounded by the credential's allowed label sets.")
	tunnelRunCmd.Flags().StringArrayVar(&advertisedRoutes, "route", nil, "CIDR reachable behind this agent, advertised to the relay; repeatable. Bounded by the credential's allowed routes.")

	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("agent"))
	cobra.CheckErr(tunnelRunCmd.MarkFlagRequired("vpc"))

	tunnelCmd.AddCommand(tunnelRunCmd)
}
