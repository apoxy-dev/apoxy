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

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage icx tunnels",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var connectTunnelCmd = &cobra.Command{
	Use:   "connect [tunnel address]",
	Short: "Connect to an icx tunnel",
	Long:  `Establish a connection to the specified icx tunnel.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		address := args[0]

		token, err := cmd.Flags().GetString("token")
		if err != nil {
			return err
		}

		insecureSkipVerify, err := cmd.Flags().GetBool("insecure-skip-verify")
		if err != nil {
			return err
		}

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
			return fmt.Errorf("failed to connect to tunnel control server: %w", err)
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

		// TODO (dpeckett): Start a SOCKS5 proxy and wait for shutdown signals.

		return nil
	},
}

func init() {
	connectTunnelCmd.Flags().String("token", "", "The token to use for authenticating with the tunnel server.")
	connectTunnelCmd.MarkFlagRequired("token")
	connectTunnelCmd.Flags().Bool("insecure-skip-verify", false, "Skip TLS certificate verification.")

	tunnelCmd.AddCommand(connectTunnelCmd)
}
