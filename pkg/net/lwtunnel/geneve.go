package lwtunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	// Using custom protocol number to differentiate from other routes.
	rtProtocol = 0x61
)

// geneveOptions holds the configuration for a Geneve tunnel interface.
type geneveOptions struct {
	// Name of the Geneve interface.
	dev string
	// Virtual Network Identifier to use for the tunnel.
	vni uint32
	// UDP port for Geneve header.
	port uint16
	// MTU for the Geneve interface.
	mtu int
}

// Geneve manages Geneve tunnel interfaces and routes.
type Geneve struct {
	opts *geneveOptions
}

// defaultGeneveOptions returns a default Geneve configuration.
func defaultGeneveOptions() *geneveOptions {
	return &geneveOptions{
		dev:  "gnv0",
		vni:  0x61,
		port: 6081,
		mtu:  1380,
	}
}

type option func(*geneveOptions)

// WithDevName sets the name of the Geneve interface.
func WithDevName(dev string) option {
	return func(o *geneveOptions) {
		o.dev = dev
	}
}

// WithVNI sets the Virtual Network Identifier to use for the tunnel.
func WithVNI(vni uint32) option {
	return func(o *geneveOptions) {
		o.vni = vni
	}
}

// WithPort sets the UDP port for Geneve header.
func WithPort(port uint16) option {
	return func(o *geneveOptions) {
		o.port = port
	}
}

// WithMTU sets the MTU for the Geneve interface.
func WithMTU(mtu int) option {
	return func(o *geneveOptions) {
		o.mtu = mtu
	}
}

// NewGeneve creates a new Geneve tunnel manager.
func NewGeneve(opts ...option) *Geneve {
	setOpts := defaultGeneveOptions()
	for _, opt := range opts {
		opt(setOpts)
	}
	return &Geneve{
		opts: setOpts,
	}
}

func (r *Geneve) hwAddr(addr netip.Addr) net.HardwareAddr {
	// Use last 3 bytes of the ipv4/ipv6 address and a reserved private OUI prefix.
	if addr.Is4() {
		return net.HardwareAddr(append([]byte{0x52, 0x54, 0x00}, addr.AsSlice()[1:]...))
	}
	return net.HardwareAddr(append([]byte{0x52, 0x54, 0x00}, addr.AsSlice()[13:]...))
}

// SetUp sets up the Geneve tunnel. Can be called multiple times.
func (r *Geneve) SetUp(_ context.Context, privAddr netip.Addr) error {
	// Create Geneve interface without a specific remote -
	// this allows us to route to multiple remotes using Linux's
	// lwtunnel infrastructure (https://github.com/torvalds/linux/blob/e347810e84094078d155663acbf36d82efe91f95/net/core/lwtunnel.c).
	hwAddr := r.hwAddr(privAddr)
	geneve := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         r.opts.dev,
			MTU:          r.opts.mtu,
			HardwareAddr: hwAddr,
		},
		// No ID and Remote set - this creates an "external" Geneve device.
		FlowBased: true, // external
	}

	slog.Info("Setting up Geneve interface",
		slog.String("dev", r.opts.dev),
		slog.Int("mtu", r.opts.mtu),
		slog.String("hwaddr", hwAddr.String()),
	)

	_, err := netlink.LinkByName(r.opts.dev)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		if err := netlink.LinkAdd(geneve); err != nil {
			return fmt.Errorf("failed to add Geneve interface: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	if err := netlink.LinkSetUp(geneve); err != nil {
		return fmt.Errorf("failed to bring up Geneve interface: %w", err)
	}

	slog.Info("Successfully setup Geneve interface", slog.String("dev", r.opts.dev))

	return nil
}

// SetAddr adds an IPv6 overlay address to the Geneve interface. This is
// optional and only needed for originating end of the tunnel to assign
// an inner source IP address.
func (r *Geneve) SetAddr(_ context.Context, ula netip.Addr) error {
	slog.Info("Setting up Geneve link address",
		slog.String("dev", r.opts.dev),
		slog.String("addr", ula.String()),
	)

	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	addr, err := netlink.ParseAddr(ula.String() + "/128")
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("failed to list addresses: %w", err)
	}
	for _, existing := range addrs {
		if existing.Equal(*addr) {
			slog.Info("IPv6 address already configured", slog.Any("addr", existing))
			return nil
		}
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IPv6 address: %w", err)
	}

	slog.Info("Successfully configured IPv6 address", slog.Any("addr", addr))

	return nil
}

// Cleanup removes the Geneve interface.
func (r *Geneve) Cleanup() error {
	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		// Interface doesn't exist, nothing to do.
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete Geneve interface: %w", err)
	}

	slog.Info("Successfully deleted Geneve interface", slog.String("dev", r.opts.dev))

	return nil
}

// routeAdd adds a route to the overlay addr via NVE.
func (r *Geneve) routeAdd(_ context.Context, ula tunnet.NetULA, nve netip.Addr) error {
	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	// Create a /96 route for the overlay IPv6 prefix which tells the kernel:
	// "to reach this overlay IP, encapsulate and send to this VTEP"
	// This is equivalent to the following iproute2 command:
	// ip route add <overlayIP>/96 encap ip id <gnvVNI> dst <nve> dev <gnvDev>
	ulaAddr := ula.FullPrefix().Addr()
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Family:    netlink.FAMILY_V6,
		Dst: &net.IPNet{
			IP:   ulaAddr.AsSlice(),
			Mask: net.CIDRMask(ula.FullPrefix().Bits(), 128),
		},
		Encap: &IPEncap{
			ID:     r.opts.vni,
			Remote: nve.AsSlice(),
		},
		Scope:    netlink.SCOPE_UNIVERSE,
		Protocol: rtProtocol,
	}

	if err := netlink.RouteAdd(route); err != nil {
		if strings.Contains(err.Error(), "exists") {
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("failed to replace route: %w", err)
			}
		} else {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	slog.Info("Configured route",
		slog.Any("dst", ula),
		slog.Any("encap_id", r.opts.vni),
		slog.String("encap_remote", nve.String()),
	)

	hwAddr := r.hwAddr(nve)
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           ulaAddr.AsSlice(),
		HardwareAddr: hwAddr,
	}); err != nil {
		return fmt.Errorf("failed to add neighbor entry: %w", err)
	}

	slog.Info("Neighbor entry set",
		slog.String("remote", ulaAddr.String()),
		slog.String("hwAddr", hwAddr.String()),
	)

	// Via is needed so that kernel can use the same dst hwaddr for the entire ula prefix.
	// Can't set via during route creation because the route to gw does not yet exist.
	route.Gw = ulaAddr.AsSlice()
	if err := netlink.RouteChange(route); err != nil {
		return fmt.Errorf("failed to change route with gw %v: %w", route.Gw, err)
	}

	slog.Info("Configured route gw",
		slog.Any("dst", ula),
		slog.String("gw", ulaAddr.String()),
		slog.Any("encap_id", r.opts.vni),
		slog.String("encap_remote", nve.String()),
	)

	return nil
}

func (r *Geneve) routeDel(_ context.Context, dst netip.Prefix) error {
	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   dst.Addr().AsSlice(),
			Mask: net.CIDRMask(dst.Bits(), 128),
		},
	}

	if err := netlink.RouteDel(route); err != nil {
		if err == syscall.ENOENT {
			return nil
		}
		return fmt.Errorf("failed to delete route: %w", err)
	}

	return nil
}

// routeList returns the current IPv6 routes for the Geneve interface.
func (r *Geneve) routeList(_ context.Context) (sets.Set[netip.Prefix], error) {
	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return nil, fmt.Errorf("failed to get Geneve link: %w", err)
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V6,
		&netlink.Route{
			Protocol: rtProtocol,
		},
		netlink.RT_FILTER_PROTOCOL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	out := sets.New[netip.Prefix]()
	for _, route := range routes {
		if link.Attrs().Index != route.LinkIndex {
			slog.Debug("Skipping route with mismatching link index",
				slog.Any("dst", route.Dst),
				slog.Int("linkIndex", link.Attrs().Index),
				slog.Int("routeLinkIndex", route.LinkIndex),
			)
			continue
		}

		bits, _ := route.Dst.Mask.Size()
		dst := netip.PrefixFrom(
			netip.AddrFrom16([16]byte(route.Dst.IP.To16())),
			bits,
		)

		slog.Debug("Route found", slog.String("dst", dst.String()))

		out.Insert(dst)
	}

	return out, nil
}

// Endpoint represents a tunnel route.
type Endpoint struct {
	// Dst is the destination prefix that should be sent over the tunnel.
	Dst tunnet.NetULA
	// Remote is a VTEP/VNE address of a remote tunnel endpoint.
	Remote netip.Addr
}

// SyncEndpoints syncs tunnel endpoints. Endpoints that are missing from eps
// are removed immediately.
func (r *Geneve) SyncEndpoints(ctx context.Context, eps []Endpoint) error {
	curRoutes, err := r.routeList(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current routes: %w", err)
	}
	updRoutes := sets.New[netip.Prefix]()
	for _, ep := range eps {
		updRoutes.Insert(ep.Dst.FullPrefix())
	}

	// Only add routes that don't already exist.
	for _, ep := range eps {
		if curRoutes.Has(ep.Dst.FullPrefix()) {
			continue
		}
		if err := r.routeAdd(ctx, ep.Dst, ep.Remote); err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	// Remove routes that are no longer needed.
	for _, route := range curRoutes.Difference(updRoutes).UnsortedList() {
		if err := r.routeDel(ctx, route); err != nil {
			return fmt.Errorf("failed to delete route: %w", err)
		}
	}

	return nil
}
