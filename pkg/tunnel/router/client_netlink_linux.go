//go:build linux

package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	defaultRoutePriority = 1000
)

var (
	_ Router = (*ClientNetlinkRouter)(nil)
)

// NewClientNetlinkRouter creates a new client-side netlink-based tunnel router.
func NewClientNetlinkRouter(opts ...Option) (Router, error) {
	return newClientNetlinkRouter(opts...)
}

// ClientNetlinkRouter implements Router using Linux's netlink subsystem for client-side routing.
// It routes all prefixes advertised by connections to a TUN device using iptables.
type ClientNetlinkRouter struct {
	tunDev  tun.Device
	tunLink netlink.Link

	iptV4, iptV6 utiliptables.Interface

	// Muxed connection for handling multiple tunnel connections.
	mux *connection.MuxedConn

	options *routerOptions

	closeOnce sync.Once
	closed    chan struct{}
}

// savedDefaultRoute preserves existing system default routes.
type savedDefaultRoute struct {
	route   *netlink.Route
	existed bool
}

// newClientNetlinkRouter creates a new client-side netlink-based tunnel router.
func newClientNetlinkRouter(opts ...Option) (*ClientNetlinkRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	slog.Info("Create a TUN device", "name", options.tunIfaceName, "mtu", netstack.IPv6MinMTU)

	tunDev, err := tun.CreateTUN(options.tunIfaceName, netstack.IPv6MinMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	if options.pcapPath != "" {
		tunDev, err = tunnet.NewPcapDevice(tunDev, options.pcapPath)
		if err != nil {
			tunDev.Close()
			return nil, fmt.Errorf("failed to create pcap device: %w", err)
		}
	}

	// Get the actual tun name (may differ from requested name).
	actualTunName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to get TUN interface name: %w", err)
	}

	tunLink, err := netlink.LinkByName(actualTunName)
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}

	// Configure local addresses on the TUN interface.
	for _, addr := range options.localAddresses {
		ip := addr.Addr()
		mask := net.CIDRMask(addr.Bits(), 128)
		if ip.Is4() {
			mask = net.CIDRMask(addr.Bits(), 32)
		}

		if err := netlink.AddrAdd(tunLink, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ip.AsSlice(),
				Mask: mask,
			},
		}); err != nil {
			tunDev.Close()
			return nil, fmt.Errorf("failed to add address to TUN interface: %w", err)
		}
		slog.Info("Added address to TUN interface", slog.String("addr", addr.String()))
	}

	if err := netlink.LinkSetUp(tunLink); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	return &ClientNetlinkRouter{
		tunDev:  tunDev,
		tunLink: tunLink,
		iptV4:   utiliptables.New(utilexec.New(), utiliptables.ProtocolIPv4),
		iptV6:   utiliptables.New(utilexec.New(), utiliptables.ProtocolIPv6),
		mux:     connection.NewMuxedConn(),
		options: options,
		closed:  make(chan struct{}),
	}, nil
}

// setupIptables configures iptables rules for client tunnel routing.
func (r *ClientNetlinkRouter) setupIptables() error {
	tunName := r.tunLink.Attrs().Name

	// TODO: Set conntrack rules for route switching.
	// # Ensure connections maintain their original path
	// iptables -A OUTPUT -o tun0 -m conntrack --ctorigdst tun0 -j ACCEPT
	// iptables -A OUTPUT -o eth0 -m conntrack --ctorigdst eth0 -j ACCEPT
	//
	// # Drop packets trying to switch interfaces mid-connection
	// iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j DROP
	//
	// for _, ipt := range []utiliptables.Interface{r.iptV4, r.iptV6} {
	// 	...
	// }

	slog.Info("Client iptables rules configured", slog.String("tun_iface", tunName))

	return nil
}

// cleanupIptables removes iptables rules created by this router.
func (r *ClientNetlinkRouter) cleanupIptables() error {
	tunName := r.tunLink.Attrs().Name

	// TODO: Cleanup conntrack rules for route switching.
	// # Ensure connections maintain their original path
	// iptables -D OUTPUT -o tun0 -m conntrack --ctorigdst tun0 -j ACCEPT
	// iptables -D OUTPUT -o eth0 -m conntrack --ctorigdst eth0 -j ACCEPT
	// # Drop packets trying to switch interfaces mid-connection
	// iptables -D OUTPUT -m conntrack --ctstate ESTABLISHED -j DROP
	// for _, ipt := range []utiliptables.Interface{r.iptV4, r.iptV6} {
	//
	// }

	slog.Info("Client iptables rules cleaned up", slog.String("tun_iface", tunName))

	return nil
}

// Start initializes the router and starts forwarding traffic.
func (r *ClientNetlinkRouter) Start(ctx context.Context) error {
	slog.Info("Starting client netlink router")
	defer slog.Debug("Client netlink router stopped")

	if err := r.setupIptables(); err != nil {
		return fmt.Errorf("failed to setup iptables: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-gctx.Done()
		slog.Debug("Closing client router")
		return r.Close()
	})

	g.Go(func() error {
		return connection.Splice(r.tunDev, r.mux)
	})

	return g.Wait()
}

// Add adds a dst route to the tunnel using the provided connection.
func (r *ClientNetlinkRouter) Add(dst netip.Prefix, conn connection.Connection) error {
	slog.Info("Adding client route", slog.String("prefix", dst.String()))

	af := netlink.FAMILY_V6
	if dst.Addr().Is4() {
		af = netlink.FAMILY_V4
	}
	mask := net.CIDRMask(dst.Bits(), 128)
	if dst.Addr().Is4() {
		mask = net.CIDRMask(dst.Bits(), 32)
	}
	route := &netlink.Route{
		LinkIndex: r.tunLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   dst.Addr().AsSlice(),
			Mask: mask,
		},
		Scope: netlink.SCOPE_LINK,
	}

	isDefault := r.isDefaultRoute(dst)
	if isDefault {
		var err error
		route.Priority, err = r.setDefaultRouteMetric(dst.Addr().Is4())
		if err != nil {
			return fmt.Errorf("failed to save existing default route: %w", err)
		}

		// Adjust priority so that our route has precedence over the existing default route.
		route.Priority -= 1
		route.Scope = netlink.SCOPE_UNIVERSE

		gws := r.getGWs(dst.Addr().Is4())
		if len(gws) == 0 {
			return fmt.Errorf("no suitable gateway found for default route from connection")
		}
		var ecmpGWs []net.IP
		if len(gws) > 1 {
			// Set up equal cost multi-path routing with equal weights.
			route.MultiPath = make([]*netlink.NexthopInfo, len(gws))
			for i, gw := range gws {
				route.MultiPath[i] = &netlink.NexthopInfo{
					LinkIndex: r.tunLink.Attrs().Index,
					Gw:        gw,
					Hops:      1,
				}
				ecmpGWs = append(ecmpGWs, gw)
			}
		}

		if len(r.options.preserveDefaultGwDsts) > 0 {
			slog.Info("Preserving default gateway routes for prefixes",
				slog.Any("prefixes", r.options.preserveDefaultGwDsts))

			var (
				defaultGW        net.IP
				defaultLinkIndex int
			)
			routes, err := netlink.RouteList(nil, af)
			if err != nil {
				return fmt.Errorf("failed to list routes to find default gateway: %w", err)
			}

			for _, route := range routes {
				if route.Dst == nil ||
					(af == netlink.FAMILY_V4 && route.Dst.String() == "0.0.0.0/0") ||
					(af == netlink.FAMILY_V6 && route.Dst.String() == "::/0") {
					defaultGW = route.Gw
					defaultLinkIndex = route.LinkIndex
					break
				}
			}

			if defaultGW == nil {
				return fmt.Errorf("could not find default gateway for preserved routes")
			}

			for _, dst := range r.options.preserveDefaultGwDsts {
				if (af == netlink.FAMILY_V4 && !dst.Addr().Is4()) ||
					(af == netlink.FAMILY_V6 && !dst.Addr().Is6()) {
					continue
				}

				maskSize := 128
				if dst.Addr().Is4() {
					maskSize = 32
				}
				route := &netlink.Route{
					Dst: &net.IPNet{
						IP:   dst.Addr().AsSlice(),
						Mask: net.CIDRMask(dst.Bits(), maskSize),
					},
					Gw:        defaultGW,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: defaultLinkIndex,
				}
				if err := netlink.RouteChange(route); err != nil {
					return fmt.Errorf("failed to add default route: %w", err)
				}
			}
		}

		slog.Info("Adding default route",
			slog.String("prefix", dst.String()),
			slog.String("gateway", route.Gw.String()),
			slog.Any("ecmp_gws", ecmpGWs))
	}

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	r.mux.AddConnection(dst, conn)

	slog.Info("Client route added successfully",
		slog.String("prefix", dst.String()),
		slog.Bool("is_default", isDefault))

	return nil
}

// isDefaultRoute checks if the given prefix is a default route.
func (r *ClientNetlinkRouter) isDefaultRoute(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.String() == "0.0.0.0/0"
	}
	return prefix.String() == "::/0"
}

// getGWs returns the appropriate gateway IPs.
func (r *ClientNetlinkRouter) getGWs(isIPv4 bool) []net.IP {
	var gws []net.IP
	for _, addr := range r.options.localAddresses {
		if addr.Addr().Is4() == isIPv4 && addr.Addr().IsGlobalUnicast() {
			gws = append(gws, addr.Addr().AsSlice())
		}
	}
	return gws
}

// Del removes a routing association for a given destination prefix and connection name.
func (r *ClientNetlinkRouter) Del(dst netip.Prefix, name string) error {
	return r.DelAll(dst) // For client router, we don't support multiple connections per prefix
}

// removeKernelRoute removes a route from the kernel routing table.
func (r *ClientNetlinkRouter) removeKernelRoute(dst netip.Prefix, isDefault bool) error {
	mask := net.CIDRMask(dst.Bits(), 128)
	if dst.Addr().Is4() {
		mask = net.CIDRMask(dst.Bits(), 32)
	}

	route := &netlink.Route{
		LinkIndex: r.tunLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   dst.Addr().AsSlice(),
			Mask: mask,
		},
	}

	if isDefault {
		route.Scope = netlink.SCOPE_UNIVERSE
	} else {
		route.Scope = netlink.SCOPE_LINK
	}

	return netlink.RouteDel(route)
}

// DelAll removes all routing associations for a given destination prefix.
func (r *ClientNetlinkRouter) DelAll(dst netip.Prefix) error {
	slog.Info("Removing client route", slog.String("prefix", dst.String()))

	isDefault := r.isDefaultRoute(dst)

	if err := r.mux.RemoveConnection(dst); err != nil {
		slog.Warn("Failed to remove connection from mux", slog.String("prefix", dst.String()), slog.Any("error", err))
	}

	if err := r.removeKernelRoute(dst, isDefault); err != nil {
		slog.Warn("Failed to remove kernel route", slog.String("prefix", dst.String()), slog.Any("error", err))
	}

	slog.Info("Client route removed successfully",
		slog.String("prefix", dst.String()),
		slog.Bool("was_default", isDefault))

	return nil
}

// ListRoutes returns a list of all routes currently managed by the router.
func (r *ClientNetlinkRouter) ListRoutes() ([]TunnelRoute, error) {
	family := netlink.FAMILY_ALL
	routes, err := netlink.RouteList(r.tunLink, family)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	var tunnelRoutes []TunnelRoute
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}

		ip, ok := netip.AddrFromSlice(route.Dst.IP)
		if !ok {
			continue
		}

		bits, _ := route.Dst.Mask.Size()
		prefix := netip.PrefixFrom(ip, bits)

		tunID := "client"
		if r.isDefaultRoute(prefix) {
			tunID = "client-default"
		}

		tunnelRoutes = append(tunnelRoutes, TunnelRoute{
			Dst:   prefix,
			TunID: tunID,
			State: TunnelRouteStateActive,
		})
	}

	return tunnelRoutes, nil
}

// setDefaultRouteMetric sets the default route metric if not already set.
// Returns the metrics value.
func (r *ClientNetlinkRouter) setDefaultRouteMetric(isIPv4 bool) (int, error) {
	family := netlink.FAMILY_V6
	if isIPv4 {
		family = netlink.FAMILY_V4
	}

	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return 0, fmt.Errorf("failed to list routes: %w", err)
	}

	for _, route := range routes {
		if route.Dst == nil ||
			(isIPv4 && route.Dst.String() == "0.0.0.0/0") ||
			(!isIPv4 && route.Dst.String() == "::/0") {

			// If metrics doesn't exist, set it to a default value.
			if route.Priority == 0 {
				route.Priority = defaultRoutePriority
				if err := netlink.RouteChange(&route); err != nil {
					return 0, fmt.Errorf("failed to update default route metric: %w", err)
				}
			}

			return route.Priority, nil
		}
	}

	return 0, nil
}

// LocalAddresses returns the list of local addresses that are assigned to the router.
func (r *ClientNetlinkRouter) LocalAddresses() ([]netip.Prefix, error) {
	return r.options.localAddresses, nil
}

// Close releases any resources associated with the router.
func (r *ClientNetlinkRouter) Close() error {
	var firstErr error
	r.closeOnce.Do(func() {
		close(r.closed)

		// Close muxed connection
		if err := r.mux.Close(); err != nil {
			slog.Error("Failed to close mux", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close mux: %w", err)
			}
		}

		// Clean up iptables rules
		if err := r.cleanupIptables(); err != nil {
			slog.Error("Failed to cleanup iptables", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to cleanup iptables: %w", err)
			}
		}

		// Close TUN device
		if err := r.tunDev.Close(); err != nil {
			slog.Error("Failed to close TUN device", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close TUN device: %w", err)
			}
		}
	})

	return firstErr
}
