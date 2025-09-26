package alpha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/alphadose/haxmap"
	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

var (
	relayName     string // the name for the relay
	relayTunnel   string // the name of the tunnel to serve
	extIfaceName  string // the external interface name
	listenAddress string // the address to listen on for incoming connections
)

var tunnelRelayCmd = &cobra.Command{
	Use:    "relay",
	Short:  "Run a development mode tunnel relay",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		routerOpts := []router.Option{
			router.WithExternalInterface(extIfaceName),
		}

		rtr, err := router.NewICXNetlinkRouter(routerOpts...)
		if err != nil {
			return fmt.Errorf("failed to create router: %w", err)
		}

		pc, err := net.ListenPacket("udp", listenAddress)
		if err != nil {
			return fmt.Errorf("failed to create UDP listener: %w", err)
		}

		idHasher := hasher.NewHasher([]byte("C0rr3ct-Horse-Battery-Staple_But_Salty_1x9Q7p3Z"))

		_, cert, err := cryptoutils.GenerateSelfSignedTLSCert(relayName)
		if err != nil {
			return fmt.Errorf("failed to generate self-signed TLS cert: %w", err)
		}

		relay := tunnel.NewRelay(relayName, pc, cert, rtr.Handler, idHasher, rtr)

		slog.Info("Configuring relay", slog.String("tunnelName", relayTunnel), slog.String("listenAddress", listenAddress), slog.String("externalInterface", extIfaceName))

		relay.SetCredentials(relayTunnel, "letmein")
		relay.SetRelayAddresses(relayTunnel, []string{pc.LocalAddr().String()})

		systemULA := tunnet.NewULA(cmd.Context(), tunnet.SystemNetworkID)
		agentIPAM, err := systemULA.IPAM(cmd.Context(), 96)
		if err != nil {
			return fmt.Errorf("failed to create system ULA IPAM: %w", err)
		}

		vpool := vni.NewVNIPool()

		type connectionMetadata struct {
			prefix netip.Prefix
			vni    uint
		}
		connections := haxmap.New[string, connectionMetadata]()

		relay.SetOnConnect(func(_ context.Context, agentName string, conn controllers.Connection) error {
			slog.Info("Connected", slog.String("agent", agentName), slog.String("connID", conn.ID()))

			pfx, err := agentIPAM.Allocate()
			if err != nil {
				return fmt.Errorf("failed to allocate prefix: %w", err)
			}

			slog.Info("Allocated prefix for connection",
				slog.String("agent", agentName), slog.String("connID", conn.ID()),
				slog.String("prefix", pfx.String()))

			conn.SetOverlayAddress(pfx.String())

			vni, err := vpool.Allocate()
			if err != nil {
				return fmt.Errorf("failed to allocate VNI: %w", err)
			}

			slog.Info("Allocated VNI for connection",
				slog.String("agent", agentName), slog.String("connID", conn.ID()),
				slog.Int("vni", int(vni)))

			if err := conn.SetVNI(vni); err != nil {
				return fmt.Errorf("failed to set VNI on connection: %w", err)
			}

			connections.Set(conn.ID(), connectionMetadata{prefix: pfx, vni: vni})

			return nil
		})

		relay.SetOnDisconnect(func(_ context.Context, agentName, id string) error {
			if cm, ok := connections.Get(id); ok {
				if err := agentIPAM.Release(cm.prefix); err != nil {
					slog.Error("Failed to release prefix", err,
						slog.String("agent", agentName), slog.String("connID", id),
						slog.String("prefix", cm.prefix.String()))
				}

				vpool.Release(cm.vni)

				connections.Del(id)

				slog.Info("Disconnected", slog.String("agent", agentName), slog.String("connID", id))
			} else {
				return fmt.Errorf("unknown connection ID: %s", id)
			}

			return nil
		})

		if err := relay.Start(cmd.Context()); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("failed to start relay: %w", err)
		}

		return nil
	},
}

func init() {
	tunnelRelayCmd.Flags().StringVarP(&relayName, "name", "n", "dev", "The name of the relay.")
	tunnelRelayCmd.Flags().StringVarP(&relayTunnel, "tunnel-name", "t", "dev", "The name of the tunnel to serve.")
	tunnelRelayCmd.Flags().StringVar(&extIfaceName, "ext-iface", "eth0", "External interface name.")
	tunnelRelayCmd.Flags().StringVar(&listenAddress, "listen-addr", ":6081", "The address to listen on for incoming connections.")

	tunnelCmd.AddCommand(tunnelRelayCmd)
}
