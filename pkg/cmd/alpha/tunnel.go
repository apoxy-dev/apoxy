package alpha

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/kex"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
	"github.com/apoxy-dev/icx"
	"github.com/dpeckett/network"
	"github.com/spf13/cobra"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	token              string
	insecureSkipVerify bool
	socksListenAddr    string
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnels",
	Long:  "Manage icx tunnels and connect to the remote Apoxy Edge fabric.",
}

var tunnelRunCmd = &cobra.Command{
	Use:   "run [address:port]",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Address/port of the tunnel relay to connect to.
		address := args[0]

		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return fmt.Errorf("failed to create UDP socket: %w", err)
		}
		defer pc.Close()

		localAddr := pc.LocalAddr().(*net.UDPAddr)

		pcGeneve, pcQuic := bifurcate.Bifurcate(pc)
		defer pcGeneve.Close()
		defer pcQuic.Close()

		kexURL := url.URL{
			Scheme: "https",
			Host:   address,
		}
		if insecureSkipVerify {
			kexURL.Scheme = "http"
		}

		tlsConf := &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		}

		kexClient := kex.NewClient(kexURL.String(), token, tlsConf, pcQuic)

		connectResp, err := kexClient.Connect(cmd.Context(), "")
		if err != nil {
			return fmt.Errorf("failed to connect to tunnel relay: %w", err)
		}

		// Ensure we disconnect when the command exits
		defer func() {
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)

			err := kexClient.Disconnect(ctx, connectResp.NetworkID)
			cancel()
			if err != nil {
				fmt.Printf("Failed to disconnect from tunnel: %v\n", err)
			}
		}()

		// TODO (dpeckett): Start a timer to periodically renew keys.

		handler, err := icx.NewHandler(
			icx.WithLocalAddr(netstack.ToFullAddress(localAddr)),
			icx.WithVirtMAC(tcpip.GetRandMacAddr()), icx.WithLayer3VirtFrames())
		if err != nil {
			return fmt.Errorf("failed to create ICX handler: %w", err)
		}

		// TODO (dpeckett): register networks from the connect response.

		// TODO (dpeckett): set initial keys based on the connect response.

		l2Geneve, err := l2pc.NewL2PacketConn(pcGeneve)
		if err != nil {
			return fmt.Errorf("failed to create L2 packet connection: %w", err)
		}
		defer l2Geneve.Close()

		var resolveConf *network.ResolveConfig
		if connectResp.DNS != nil {
			resolveConf = &network.ResolveConfig{
				Nameservers:   connectResp.DNS.Servers,
				SearchDomains: connectResp.DNS.SearchDomains,
				NDots:         connectResp.DNS.NDots,
			}
		}

		net, err := netstack.NewICXNetwork(handler, l2Geneve, connectResp.MTU, resolveConf, "")
		if err != nil {
			return fmt.Errorf("failed to create ICX network: %w", err)
		}
		defer net.Close()

		// TODO (dpeckett): Start a SOCKS5 proxy and wait for shutdown signals
		// (probably as part of a router abstraction).

		return nil
	},
}

func init() {
	tunnelRunCmd.Flags().StringVar(&token, "token", "", "The token to use for authenticating with the tunnel relay.")
	tunnelRunCmd.MarkFlagRequired("token")
	tunnelRunCmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification.")
	tunnelRunCmd.Flags().StringVar(&socksListenAddr, "socks-addr", "localhost:1080", "Listen address for SOCKS proxy.")

	tunnelCmd.AddCommand(tunnelRunCmd)
}
