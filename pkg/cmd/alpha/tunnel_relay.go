package alpha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"

	"github.com/alphadose/haxmap"
	"github.com/spf13/cobra"

	"github.com/apoxy-dev/icx"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/vni"
)

var (
	relayName            string // the name for the relay
	relayTunnel          string // the name of the tunnel to serve
	extIfaceName         string // the external interface name
	listenAddress        string // the address to listen on for incoming connections
	userMode             bool   // whether to use user-mode routing (no special privileges required)
	relaySocksListenAddr string // when using user-mode routing, the address to listen on for SOCKS5 connections
	relayPcapPath        string // optional pcap path
)

var tunnelRelayCmd = &cobra.Command{
	Use:    "relay",
	Short:  "Run a development mode tunnel relay",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		routerOpts := []router.Option{
			router.WithExternalInterface(extIfaceName),
			router.WithEgressGateway(true),
			router.WithSocksListenAddr(relaySocksListenAddr), // only used in user-mode
		}

		if relayPcapPath != "" {
			routerOpts = append(routerOpts, router.WithPcapPath(relayPcapPath))
		}

		// One UDP socket shared between Geneve (data) and QUIC (control).
		lis, err := net.ListenPacket("udp", listenAddress)
		if err != nil {
			return fmt.Errorf("failed to create UDP listener: %w", err)
		}

		pc, err := batchpc.New("udp", lis)
		if err != nil {
			return fmt.Errorf("failed to create batch packet conn: %w", err)
		}

		pcGeneve, pcQuic := bifurcate.Bifurcate(pc)
		defer pcGeneve.Close()
		defer pcQuic.Close()

		var rtr router.Router
		var handler *icx.Handler
		if userMode {
			routerOpts = append(routerOpts, router.WithPacketConn(pcGeneve))

			r, err := router.NewICXNetstackRouter(routerOpts...)
			if err != nil {
				return fmt.Errorf("failed to create router: %w", err)
			}
			rtr = r
			handler = r.Handler
		} else {
			r, err := router.NewICXNetlinkRouter(routerOpts...)
			if err != nil {
				return fmt.Errorf("failed to create router: %w", err)
			}
			rtr = r
			handler = r.Handler
		}

		idHasher := hasher.NewHasher([]byte("C0rr3ct-Horse-Battery-Staple_But_Salty_1x9Q7p3Z"))

		_, cert, err := cryptoutils.GenerateSelfSignedTLSCert(relayName)
		if err != nil {
			return fmt.Errorf("failed to generate self-signed TLS cert: %w", err)
		}

		relay := tunnel.NewRelay(relayName, pcQuic, cert, handler, idHasher, rtr)

		slog.Info("Configuring relay", slog.String("tunnelName", relayTunnel), slog.String("listenAddress", listenAddress), slog.String("externalInterface", extIfaceName))

		relay.SetCredentials(relayTunnel, "letmein")
		relay.SetRelayAddresses(relayTunnel, []string{pcQuic.LocalAddr().String()})
		relay.SetEgressGateway(true)

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

			if err := conn.SetOverlayAddress(pfx.String()); err != nil {
				agentIPAM.Release(pfx)
				return fmt.Errorf("failed to set overlay address on connection: %w", err)
			}

			vni, err := vpool.Allocate()
			if err != nil {
				return fmt.Errorf("failed to allocate VNI: %w", err)
			}

			slog.Info("Allocated VNI for connection",
				slog.String("agent", agentName), slog.String("connID", conn.ID()),
				slog.Int("vni", int(vni)))

			if err := conn.SetVNI(cmd.Context(), vni); err != nil {
				return fmt.Errorf("failed to set VNI on connection: %w", err)
			}

			connections.Set(conn.ID(), connectionMetadata{prefix: pfx, vni: vni})

			return nil
		})

		relay.SetOnDisconnect(func(_ context.Context, agentName, id string) error {
			if cm, ok := connections.Get(id); ok {
				if err := agentIPAM.Release(cm.prefix); err != nil {
					slog.Error("Failed to release prefix", slog.Any("error", err),
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
	tunnelRelayCmd.Flags().StringVar(&listenAddress, "listen-addr", "127.0.0.1:6081", "The address to listen on for incoming connections.")
	tunnelRelayCmd.Flags().BoolVar(&userMode, "user-mode", runtime.GOOS != "linux", "Use user-mode routing (no special privileges required).")
	tunnelRelayCmd.Flags().StringVar(&relaySocksListenAddr, "socks-addr", "localhost:1080", "When using user-mode routing, the address to listen on for SOCKS5 connections.")
	tunnelRelayCmd.Flags().StringVarP(&relayPcapPath, "pcap", "p", "", "Path to an optional packet capture file to write.")

	tunnelCmd.AddCommand(tunnelRelayCmd)
}
