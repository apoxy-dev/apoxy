package router

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/tunnel"
	"github.com/apoxy-dev/icx/veth"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

const (
	icxDefaultPort = 6081
	extPathMTU     = 1500
)

var (
	_ Router = (*ICXNetlinkRouter)(nil)
)

type ICXNetlinkRouter struct {
	Handler       *icx.Handler
	vethDev       *veth.Handle
	ingressFilter *xdp.Program
	pcapFile      *os.File
	tun           *tunnel.Tunnel
	closeOnce     sync.Once
}

func NewICXNetlinkRouter(opts ...Option) (*ICXNetlinkRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	phy, err := netlink.LinkByName(options.extIfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", options.extIfaceName, err)
	}

	addrs, err := addrsForInterface(phy, icxDefaultPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", options.extIfaceName, err)
	}

	localAddr, err := selectSourceAddr(addrs)
	if err != nil {
		return nil, fmt.Errorf("failed to select source address: %w", err)
	}

	numQueues, err := tunnel.NumQueues(phy)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of TX queues for interface %s: %w", options.extIfaceName, err)
	}

	vethDev, err := veth.Create(options.tunIfaceName, numQueues, icx.MTU(extPathMTU))
	if err != nil {
		return nil, fmt.Errorf("failed to create veth device: %w", err)
	}

	virtMAC := tcpip.LinkAddress(vethDev.Link.Attrs().HardwareAddr)

	handlerOpts := []icx.HandlerOption{
		icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(virtMAC),
	}
	if options.sourcePortHashing {
		handlerOpts = append(handlerOpts, icx.WithSourcePortHashing())
	}

	handler, err := icx.NewHandler(handlerOpts...)
	if err != nil {
		_ = vethDev.Close()
		return nil, fmt.Errorf("failed to create handler: %w", err)
	}

	ingressFilter, err := filter.Bind(addrs...)
	if err != nil {
		_ = vethDev.Close()
		return nil, fmt.Errorf("failed to create ingress filter: %w", err)
	}

	var pcapFile *os.File
	var pcapWriter *pcapgo.Writer
	if options.pcapPath != "" {
		pcapFile, err = os.Create(options.pcapPath)
		if err != nil {
			_ = vethDev.Close()
			_ = ingressFilter.Close()
			return nil, fmt.Errorf("failed to create pcap file: %w", err)
		}

		pcapWriter = pcapgo.NewWriter(pcapFile)
		if err := pcapWriter.WriteFileHeader(uint32(math.MaxUint16), layers.LinkTypeEthernet); err != nil {
			return nil, fmt.Errorf("failed to write PCAP header: %w", err)
		}
	}

	tun, err := tunnel.NewTunnel(options.extIfaceName, vethDev.Peer.Attrs().Name, ingressFilter, handler, pcapWriter)
	if err != nil {
		_ = vethDev.Close()
		_ = ingressFilter.Close()
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	return &ICXNetlinkRouter{
		Handler:       handler,
		vethDev:       vethDev,
		ingressFilter: ingressFilter,
		pcapFile:      pcapFile,
		tun:           tun,
	}, nil
}

func (r *ICXNetlinkRouter) Close() error {
	var firstErr error
	r.closeOnce.Do(func() {
		if err := r.tun.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := r.vethDev.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := r.ingressFilter.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := r.pcapFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}

// Start initializes the router and starts forwarding traffic.
// It's a blocking call that should be run in a separate goroutine.
func (r *ICXNetlinkRouter) Start(ctx context.Context) error {
	if err := r.tun.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("failed to start tunnel: %w", err)
	}

	return nil
}

// AddAddr adds a tun with an associated address to the router.
func (r *ICXNetlinkRouter) AddAddr(addr netip.Prefix, tun connection.Connection) error {
	// TODO (dpeckett): implement
	return nil
}

// ListAddrs returns a list of all addresses currently managed by the router.
func (r *ICXNetlinkRouter) ListAddrs() ([]netip.Prefix, error) {
	// TODO (dpeckett): implement
	return nil, nil
}

// DelAddr removes a tun by its addr from the router.
func (r *ICXNetlinkRouter) DelAddr(addr netip.Prefix) error {
	// TODO (dpeckett): implement
	return nil
}

// AddRoute adds a dst prefix to be routed through the given tunnel connection.
// If multiple tunnels are provided, the router will distribute traffic across them
// uniformly.
func (r *ICXNetlinkRouter) AddRoute(dst netip.Prefix) error {
	// TODO (dpeckett): implement
	return nil
}

// Del removes a routing associations for a given destination prefix and Connection name.
// New matching flows will stop being routed through the tunnel immediately while
// existing flows may continue to use the tunnel for some draining period before
// getting re-routed via a different tunnel or dropped (if no tunnel is available for
// the given dst).
func (r *ICXNetlinkRouter) DelRoute(dst netip.Prefix) error {
	// TODO (dpeckett): implement
	return nil
}

// ListRoutes returns a list of all routes currently managed by the router.
func (r *ICXNetlinkRouter) ListRoutes() ([]TunnelRoute, error) {
	// TODO (dpeckett): implement
	return nil, nil
}

// LocalAddresses returns the list of local addresses that are assigned to the router.
func (r *ICXNetlinkRouter) LocalAddresses() ([]netip.Prefix, error) {
	// TODO (dpeckett): implement
	return nil, nil
}

func addrsForInterface(link netlink.Link, port int) ([]net.Addr, error) {
	nlAddrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface: %w", err)
	}

	var addrs []net.Addr
	for _, addr := range nlAddrs {
		if addr.IP == nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   addr.IP,
			Port: port,
		})
	}

	return addrs, nil
}

func selectSourceAddr(addrs []net.Addr) (*tcpip.FullAddress, error) {
	var localUDP *net.UDPAddr
	bestScore := -1
	for _, a := range addrs {
		if ua, ok := a.(*net.UDPAddr); ok && ua.IP != nil {
			score := 0
			if ua.IP.IsGlobalUnicast() {
				// Prefer IPv4 over IPv6 for most underlays unless otherwise configured.
				if ua.IP.To4() != nil {
					score = 3
				} else {
					score = 2
				}
			} else {
				// Still consider non-global addresses as a last resort.
				score = 1
			}
			if score > bestScore {
				bestScore = score
				localUDP = ua
			}
		}
	}

	if localUDP == nil {
		return nil, fmt.Errorf("no valid UDP address found")
	}

	return netstack.ToFullAddress(netip.MustParseAddrPort(localUDP.String())), nil
}
