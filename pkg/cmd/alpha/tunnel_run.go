package alpha

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/clientcmd"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/apoxy-dev/apoxy/client/versioned"
	vpcclient "github.com/apoxy-dev/apoxy/client/versioned/typed/vpc/v1alpha1"
	apoxyconfig "github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
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
	adminAddr          string            // listen address for the underlay-only admin endpoint; empty disables
	healthAddr         string            // deprecated alias for adminAddr
	agentLabels        map[string]string // agent-declared labels for VPCService selection (--label)
	advertisedRoutes   []string          // CIDRs reachable behind this agent (--route)
	noTUI              bool              // disable the interactive connection display
)

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if minConns < 1 {
			return fmt.Errorf("--min-conns must be at least 1")
		}
		resolvedAdminAddr, err := resolveAdminAddr(
			adminAddr,
			healthAddr,
			cmd.Flags().Changed("admin-addr"),
			cmd.Flags().Changed("health-addr"),
		)
		if err != nil {
			return err
		}

		// Validate advertised routes up front so a typo fails fast rather than
		// being rejected by the relay mid-connect.
		for _, r := range advertisedRoutes {
			if _, err := netip.ParsePrefix(r); err != nil {
				return fmt.Errorf("invalid --route: %w", err)
			}
		}
		cmd.SilenceUsage = true

		resolvedAgentName, resolvedTunnelName, generatedName := resolveTunnelDefaults(agentName, tunnelName)
		useTUI := !noTUI && !apoxyconfig.Verbose && utils.IsInteractive()
		status := newTunnelRunStatus(
			cmd.OutOrStdout(), resolvedAgentName, resolvedTunnelName, generatedName, minConns, useTUI,
		)
		defer status.Close()
		if useTUI {
			logger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
			defer slog.SetDefault(logger)
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
			network, err := vpcClient.VPCNetworks().Get(cmd.Context(), resolvedTunnelName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("fetching VPCNetwork %q: %w", resolvedTunnelName, err)
			}
			if network.Status.Credentials == nil || network.Status.Credentials.Token == "" {
				return fmt.Errorf("network %q has no credentials configured", resolvedTunnelName)
			}
			token = network.Status.Credentials.Token

			relayLister = tunnelagent.NewRelayLister(vpcClient, network.Name)

			discoveredRelays, err = relayLister(cmd.Context())
			if err != nil {
				return err
			}
			if discoveredRelays.Len() == 0 {
				return fmt.Errorf("no ready relays serving network %q", resolvedTunnelName)
			}
		}

		connectionTracker := tunnelagent.NewConnectionTracker(minConns)
		g, ctx := errgroup.WithContext(cmd.Context())

		var adminPort uint16
		if resolvedAdminAddr != "" {
			adminListener, err := net.Listen("tcp", resolvedAdminAddr)
			if err != nil {
				return fmt.Errorf("failed to bind admin listener %q: %w", resolvedAdminAddr, err)
			}
			tcpAddr, ok := adminListener.Addr().(*net.TCPAddr)
			if !ok || tcpAddr.Port < 1 || tcpAddr.Port > 65535 {
				_ = adminListener.Close()
				return fmt.Errorf("admin listener returned invalid TCP address %q", adminListener.Addr())
			}
			adminPort = uint16(tcpAddr.Port)
			adminServer := &http.Server{
				Handler:           newTunnelAdminHandler(connectionTracker),
				ReadHeaderTimeout: 5 * time.Second,
			}

			g.Go(func() error {
				slog.Info("Starting tunnel admin server", slog.String("address", adminListener.Addr().String()))
				if err := adminServer.Serve(adminListener); err != nil && err != http.ErrServerClosed {
					slog.Error("Tunnel admin server failed", slog.Any("error", err))
					return err
				}
				return nil
			})

			g.Go(func() error {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return adminServer.Shutdown(shutdownCtx)
			})
		}

		g.Go(func() error {
			return tunnelagent.Run(ctx, tunnelagent.Config{
				Agent:            resolvedAgentName,
				Network:          resolvedTunnelName,
				Token:            token,
				Labels:           agentLabels,
				AdvertisedRoutes: advertisedRoutes,
				// The agent-instance UUID is stable for this process's
				// lifetime; the relay stamps it onto each Tunnel so multiple
				// connections from one process are attributable to the same
				// instance.
				Instance:           metrics.AgentProcessID(),
				SeedRelayAddr:      seedRelayAddr,
				SeedRelays:         discoveredRelays,
				RelayLister:        relayLister,
				MinConns:           minConns,
				ConnectionTracker:  connectionTracker,
				TLSConfig:          &tls.Config{InsecureSkipVerify: insecureSkipVerify},
				SocksListenAddr:    socksListenAddr,
				PcapPath:           pcapPath,
				TunMode:            tunMode,
				TunIfaceName:       tunIfaceName,
				AdminPort:          adminPort,
				ConnectionObserver: status.Observe,
			})
		})

		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	},
}

func resolveAdminAddr(admin, health string, adminChanged, healthChanged bool) (string, error) {
	if adminChanged && healthChanged {
		return "", fmt.Errorf("--admin-addr and deprecated --health-addr cannot be used together")
	}
	if healthChanged {
		return strings.TrimSpace(health), nil
	}
	return strings.TrimSpace(admin), nil
}

func newTunnelAdminHandler(tracker *tunnelagent.ConnectionTracker) http.Handler {
	adminRegistry := prometheus.NewRegistry()
	adminRegistry.MustRegister(
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "tunnel_agent_connections_active",
				Help: "Current number of live relay sessions for this tunnel agent.",
			},
			func() float64 { return float64(tracker.ActiveConnections()) },
		),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "tunnel_agent_connections_required",
				Help: "Relay sessions required for this tunnel agent to report ready.",
			},
			func() float64 { return float64(tracker.RequiredConnections()) },
		),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "tunnel_agent_ready",
				Help: "Whether this tunnel agent has its required relay sessions.",
			},
			func() float64 {
				if tracker.Ready() {
					return 1
				}
				return 0
			},
		),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/livez", tunnelagent.LivenessHandler)
	mux.HandleFunc("/readyz", tracker.ReadinessHandler)
	// Keep the old path as a readiness alias while callers move to /readyz.
	mux.HandleFunc("/healthz", tracker.ReadinessHandler)
	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.Gatherers{ctrlmetrics.Registry, adminRegistry},
		promhttp.HandlerOpts{},
	))
	return mux
}

func resolveTunnelDefaults(name, network string) (resolvedName, resolvedNetwork string, generated bool) {
	resolvedName = strings.TrimSpace(name)
	if resolvedName == "" {
		resolvedName = utils.DockerName()
		generated = true
	}
	resolvedNetwork = strings.TrimSpace(network)
	if resolvedNetwork == "" {
		resolvedNetwork = "default"
	}
	return resolvedName, resolvedNetwork, generated
}

func init() {
	tunnelRunCmd.Flags().StringVarP(&agentName, "name", "n", "", "Tunnel name (default: a random Docker-style name).")
	tunnelRunCmd.Flags().StringVarP(&agentName, "agent", "a", "", "Deprecated alias for --name.")
	cobra.CheckErr(tunnelRunCmd.Flags().MarkDeprecated("agent", "use --name instead"))
	tunnelRunCmd.Flags().StringVar(&tunnelName, "vpc", "default", "The VPC network to connect to.")
	tunnelRunCmd.Flags().StringVarP(&seedRelayAddr, "relay-addr", "r", "", "Seed relay address (host:port), required if not using kubernetes-based discovery.")
	tunnelRunCmd.Flags().IntVar(&minConns, "min-conns", 1, "Minimum number of relays to maintain connections to (randomly selected from the discovered relay set).")
	tunnelRunCmd.Flags().StringVarP(&token, "token", "k", "", "The token to use for authenticating with the tunnel relays, required if not using kubernetes-based discovery.")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification for relay connections.")
	tunnelRunCmd.Flags().StringVarP(&pcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")
	tunnelRunCmd.Flags().BoolVar(&tunMode, "tun", false, "Use a kernel TUN device for the overlay datapath instead of the in-process netstack + SOCKS proxy. Any process in the same network namespace can then reach overlay destinations by plain kernel route. Linux only; requires NET_ADMIN and /dev/net/tun.")
	tunnelRunCmd.Flags().StringVar(&tunIfaceName, "tun-ifname", "apoxy0", "Name of the TUN interface created in --tun mode.")
	tunnelRunCmd.Flags().StringVar(&adminAddr, "admin-addr", "", "Listen address for underlay-only /livez, /readyz, and /metrics endpoints. Empty disables.")
	tunnelRunCmd.Flags().StringVar(&healthAddr, "health-addr", "", "Deprecated alias for --admin-addr.")
	cobra.CheckErr(tunnelRunCmd.Flags().MarkDeprecated("health-addr", "use --admin-addr instead"))
	tunnelRunCmd.Flags().StringToStringVar(&agentLabels, "label", nil, "Agent-declared label (key=value) for VPCService selection; repeatable. Bounded by the credential's allowed label sets.")
	tunnelRunCmd.Flags().StringArrayVar(&advertisedRoutes, "route", nil, "CIDR reachable behind this agent, advertised to the relay; repeatable. Bounded by the credential's allowed routes.")
	tunnelRunCmd.Flags().BoolVar(&noTUI, "no-tui", false, "Disable the interactive connection display.")

	tunnelCmd.AddCommand(tunnelRunCmd)
}
