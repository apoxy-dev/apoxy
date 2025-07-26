package lwtunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/log"
	clog "sigs.k8s.io/controller-runtime/pkg/log"

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

func (r *Geneve) hwAddr(ula tunnet.NetULA) net.HardwareAddr {
	// Use 2-byte endpoint portion of the ULA address [11:13].
	// TODO(dilyevsky): Make this strongly typed.
	return net.HardwareAddr([]byte{0x0A, 0x00, 0x00, 0x00, ula.EndpointID[0], ula.EndpointID[1]})
}

// ensureDevice creates the Geneve link if it doesn't exist.
func (r *Geneve) ensureDevice(ctx context.Context, ula tunnet.NetULA) error {
	log := clog.FromContext(ctx)

	link, err := netlink.LinkByName(r.opts.dev)
	if err == nil {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to bring up Geneve interface: %w", err)
		}
		return nil
	}

	log.Info("Creating Geneve interface", "dev", r.opts.dev)

	// Create Geneve interface without a specific remote -
	// this allows us to route to multiple remotes using Linux's
	// lwtunnel infrastructure (https://github.com/torvalds/linux/blob/e347810e84094078d155663acbf36d82efe91f95/net/core/lwtunnel.c).
	geneve := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         r.opts.dev,
			MTU:          r.opts.mtu,
			HardwareAddr: r.hwAddr(ula),
		},
		// No ID and Remote set - this creates an "external" Geneve device.
		FlowBased: true, // external
	}

	if err := netlink.LinkAdd(geneve); err != nil {
		return fmt.Errorf("failed to add Geneve interface: %w", err)
	}

	if err := netlink.LinkSetUp(geneve); err != nil {
		return fmt.Errorf("failed to bring up Geneve interface: %w", err)
	}

	log.Info("Successfully created Geneve interface", "dev", r.opts.dev)

	if err := r.setAddr(ctx, geneve, ula); err != nil {
		return fmt.Errorf("failed to configure device address: %w", err)
	}

	return nil
}

// setAddr adds an IPv6 address to the Geneve interface.
func (r *Geneve) setAddr(ctx context.Context, link netlink.Link, ula tunnet.NetULA) error {
	log := clog.FromContext(ctx)

	addr, err := netlink.ParseAddr(ula.FullPrefix().String())
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}

	af := netlink.FAMILY_V6
	if addr.IP.To4() != nil {
		af = netlink.FAMILY_V4
	}
	addrs, err := netlink.AddrList(link, af)
	if err != nil {
		return fmt.Errorf("failed to list addresses: %w", err)
	}
	for _, existing := range addrs {
		if existing.Equal(*addr) {
			log.Info("IPv6 address already configured", "addr", existing)
			return nil
		}
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IPv6 address: %w", err)
	}

	log.Info("Successfully configured IPv6 address", "addr", addr)

	return nil
}

// cleanupGeneve removes the Geneve interface.
func (r *Geneve) cleanupGeneve(ctx context.Context) error {
	log := clog.FromContext(ctx)

	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		// Interface doesn't exist, nothing to do.
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete Geneve interface: %w", err)
	}

	log.Info("Successfully deleted Geneve interface", "dev", r.opts.dev)

	return nil
}

// routeAdd adds a route to the overlay addr via NVE.
func (r *Geneve) routeAdd(ctx context.Context, ula tunnet.NetULA, nve netip.Addr) error {
	log := clog.FromContext(ctx)

	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	// Create a /96 route for the overlay IPv6 prefix which tells the kernel:
	// "to reach this overlay IP, encapsulate and send to this VTEP"
	// This is equivalent to the following iproute2 command:
	// ip route add <overlayIP>/96 encap ip id <gnvVNI> dst <nve> dev <gnvDev>
	ulaAddr := ula.FullPrefix().Addr()
	af, mask := netlink.FAMILY_V6, 128
	if ulaAddr.Is4() {
		af, mask = netlink.FAMILY_V4, 32
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Family:    af,
		Dst: &net.IPNet{
			IP:   ulaAddr.AsSlice(),
			Mask: net.CIDRMask(ula.FullPrefix().Bits(), mask),
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

	log.Info("Configured route", "af", af, "dst", ula, "encap_id",
		r.opts.vni, "encap_remote", nve.String())

	hwAddr := r.hwAddr(ula)
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           ulaAddr.AsSlice(),
		HardwareAddr: hwAddr,
	}); err != nil {
		return fmt.Errorf("failed to add neighbor entry: %w", err)
	}

	log.Info("Neighbor entry set", "remote", ulaAddr, "hwAddr", hwAddr)

	// Via is needed so that kernel can use the same dst hwaddr for the entire ula prefix.
	// Can't set via during route creation because the route to gw does not yet exist.
	route.Gw = ulaAddr.AsSlice()
	if err := netlink.RouteChange(route); err != nil {
		return fmt.Errorf("failed to change route with gw %v: %w", route.Gw, err)
	}

	log.Info("Configured route gw",
		"af", af, "dst", ula, "gw", ulaAddr,
		"encap_id", r.opts.vni, "encap_remote", nve)

	return nil
}

func (r *Geneve) routeDel(ctx context.Context, dst netip.Prefix) error {
	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	mask := 128
	if dst.Addr().Is4() {
		mask = 32
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   dst.Addr().AsSlice(),
			Mask: net.CIDRMask(dst.Bits(), mask),
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

// routeList returns the current routes for the Geneve interface.
func (r *Geneve) routeList(ctx context.Context) (sets.Set[netip.Prefix], error) {
	log := log.FromContext(ctx)

	link, err := netlink.LinkByName(r.opts.dev)
	if err != nil {
		return nil, fmt.Errorf("failed to get Geneve link: %w", err)
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
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
		// TODO(dilyevsky): netlink doesn't currently support deserialization of encap type ip.
		//if route.Encap == nil || route.Encap.Type() != nl.LWTUNNEL_ENCAP_IP {
		//	log.Info("Skipping route with no/mismatching encap", "dst", route.Dst, "encap", route.Encap)
		//	continue
		//}

		//encap, ok := route.Encap.(*IPEncap)
		//if !ok {
		//	log.Info("Skipping route with non-Geneve Encap", "dst", route.Dst)
		//	continue
		//}
		if link.Attrs().Index != route.LinkIndex {
			log.V(1).Info("Skipping route with mismatching link index", "dst", route.Dst, "linkIndex", link.Attrs().Index, "routeLinkIndex", route.LinkIndex)
			continue
		}

		var dst netip.Prefix
		bits, _ := route.Dst.Mask.Size()
		if route.Dst.IP.To16() != nil {
			dst = netip.PrefixFrom(
				netip.AddrFrom16([16]byte(route.Dst.IP.To16())),
				bits,
			)
		} else if route.Dst.IP.To4() != nil {
			dst = netip.PrefixFrom(
				netip.AddrFrom4([4]byte(route.Dst.IP.To4())),
				bits,
			)
		}

		log.Info("Route found", "dst", dst)

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

// SetUp sets up the Geneve tunnel. Can be called multiple times with different local addresses -
// old localAddr will be removed.
func (r *Geneve) SetUp(ctx context.Context, localAddr netip.Prefix) error {
	log := clog.FromContext(ctx)

	log.Info("Geneve tunnel setup")

	ula, err := tunnet.ULAFromPrefix(ctx, localAddr)
	if err != nil {
		return fmt.Errorf("failed to parse address: %w", err)
	}

	if err := r.ensureDevice(ctx, *ula); err != nil {
		return fmt.Errorf("failed to ensure Geneve interface: %w", err)
	}

	return nil
}

// SyncEndpoints syncs tunnel endpoints. Endpoints that are missing from eps
// are removed immediately.
func (r *Geneve) SyncEndpoints(ctx context.Context, eps []Endpoint) error {
	curRoutes, err := r.routeList(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current routes: %w", err)
	}
	updRoutes := sets.New[netip.Prefix]()
	for _, r := range eps {
		updRoutes.Insert(r.Dst.FullPrefix())
	}

	for _, route := range eps {
		if err := r.routeAdd(ctx, route.Dst, route.Remote); err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	for _, route := range curRoutes.Difference(updRoutes).UnsortedList() {
		if err := r.routeDel(ctx, route); err != nil {
			return fmt.Errorf("failed to delete route: %w", err)
		}
	}

	return nil
}
