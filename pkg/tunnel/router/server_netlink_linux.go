//go:build linux

package router

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

var (
	_ Router = (*NetlinkRouter)(nil)
)

// NetlinkRouter implements Router using Linux's netlink subsystem.
type NetlinkRouter struct {
	extLink       netlink.Link
	extIPv6Prefix netip.Prefix

	cksumRecalc bool

	tunDev  tun.Device
	tunLink netlink.Link

	iptV4, iptV6 utiliptables.Interface

	mux *connection.MuxedConn

	closeOnce sync.Once
}

// NewNetlinkRouter creates a new netlink-based tunnel router.
func NewNetlinkRouter(opts ...Option) (*NetlinkRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	extLink, err := netlink.LinkByName(options.extIfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get external interface: %w", err)
	}

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

	if !options.extIPv6Prefix.IsValid() {
		tunDev.Close()
		return nil, fmt.Errorf("external IPv6 prefix is not valid")
	}

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

	return &NetlinkRouter{
		extLink:       extLink,
		extIPv6Prefix: options.extIPv6Prefix,

		cksumRecalc: options.cksumRecalc,

		tunDev:  tunDev,
		tunLink: tunLink,

		iptV4: utiliptables.New(utilexec.New(), utiliptables.ProtocolIPv4),
		iptV6: utiliptables.New(utilexec.New(), utiliptables.ProtocolIPv6),

		mux: connection.NewMuxedConn(),
	}, nil
}

const (
	ChainA3yTunRules utiliptables.Chain = "A3Y-TUN-RULES"
)

func (r *NetlinkRouter) setupDNAT() error {
	exists, err := r.iptV6.EnsureChain(utiliptables.TableNAT, ChainA3yTunRules)
	if err != nil {
		return fmt.Errorf("failed to ensure %s chain: %w", ChainA3yTunRules, err)
	}
	if exists { // Jump and forwarding rules should be already set up.
		return nil
	}

	extName := r.extLink.Attrs().Name
	tunName := r.tunLink.Attrs().Name

	slog.Info("Setting up jump rule",
		slog.String("ext_iface", extName),
		slog.String("ext_addr", r.extIPv6Prefix.Addr().String()))

	// Traffic arriving at the designated external interface will be processed by the A3Y-TUN-RULES chain.
	jRuleSpec := []string{"-d", r.extIPv6Prefix.Addr().String(), "-i", extName, "-j", string(ChainA3yTunRules)}
	if _, err := r.iptV6.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPrerouting, jRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure jump rule: %w", err)
	}

	// Setup forwarding rules between the external and tunnel interfaces.
	fwdRuleSpecs := [][]string{
		{"-i", extName, "-o", tunName, "-j", "ACCEPT"},
		{"-i", tunName, "-o", extName, "-j", "ACCEPT"},
	}
	slog.Info("Setting up forwarding rules", slog.String("ext_iface", extName), slog.String("tun_iface", tunName))
	for _, ruleSpec := range fwdRuleSpecs {
		if _, err := r.iptV6.EnsureRule(utiliptables.Append, utiliptables.TableFilter, utiliptables.ChainForward, ruleSpec...); err != nil {
			return fmt.Errorf("failed to ensure forwarding rule: %w", err)
		}
	}

	// Setup NAT for traffic returning from the tunnel.
	masqRuleSpec := []string{"-o", extName, "-j", "MASQUERADE"}
	slog.Info("Setting up masquerade rule", slog.String("ext_iface", extName))
	if _, err := r.iptV4.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting, masqRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure masquerade rule: %w", err)
	}
	if _, err := r.iptV6.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting, masqRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure masquerade rule: %w", err)
	}

	return nil
}

// Start initializes the router and starts forwarding traffic.
func (r *NetlinkRouter) Start(ctx context.Context) error {
	slog.Info("Starting TUN muxer")
	defer slog.Debug("TUN muxer stopped")

	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}

	if err := r.setupDNAT(); err != nil {
		return fmt.Errorf("failed to setup DNAT: %w", err)
	}

	// Create error group with context
	g, gctx := errgroup.WithContext(ctx)

	// Setup cleanup handler
	g.Go(func() error {
		<-gctx.Done()
		slog.Debug("Closing router")
		return r.Close()
	})

	// Start the splicing operation
	g.Go(func() error {
		var opts []connection.SpliceOption
		if r.cksumRecalc {
			opts = append(opts, connection.WithChecksumRecalculation())
		}
		return connection.Splice(r.tunDev, r.mux, opts...)
	})

	return g.Wait()
}

func probability(n int) string {
	return fmt.Sprintf("%0.10f", 1.0/float64(n))
}

func (r *NetlinkRouter) syncDNATChain() error {
	natChains := proxyutil.NewLineBuffer()
	natChains.Write(utiliptables.MakeChainLine(ChainA3yTunRules))

	natRules := proxyutil.NewLineBuffer()
	peers := r.mux.Prefixes()
	for i, peer := range peers {
		if peer.Addr().Is4() { // Skipping IPv4 peers - only IPv6 tunnel ingress is supported.
			continue
		}
		natRules.Write(
			"-A", string(ChainA3yTunRules),
			"-m", "statistic",
			"--mode", "random",
			"--probability", probability(len(peers)-i),
			"-j", "DNAT",
			"--to-destination", peer.Addr().String(),
		)
	}

	iptNewData := bytes.NewBuffer(nil)
	iptNewData.WriteString("*nat\n")
	iptNewData.Write(natChains.Bytes())
	iptNewData.Write(natRules.Bytes())
	iptNewData.WriteString("COMMIT\n")

	if err := r.iptV6.Restore(
		utiliptables.TableNAT,
		iptNewData.Bytes(),
		utiliptables.NoFlushTables,
		utiliptables.RestoreCounters,
	); err != nil {
		return fmt.Errorf("failed to execute iptables-restore: %w", err)
	}

	return nil
}

// Add adds a dst route to the tunnel.
func (r *NetlinkRouter) Add(peer netip.Prefix, conn connection.Connection) error {
	slog.Debug("Adding route", slog.String("prefix", peer.String()))

	mask := net.CIDRMask(peer.Bits(), 128)
	if peer.Addr().Is4() {
		mask = net.CIDRMask(peer.Bits(), 32)
	}
	route := &netlink.Route{
		LinkIndex: r.tunLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: mask,
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	r.mux.AddConnection(peer, conn)
	if err := r.syncDNATChain(); err != nil {
		return fmt.Errorf("failed to sync DNAT chain: %w", err)
	}

	return nil
}

func (r *NetlinkRouter) Del(dst netip.Prefix, _ string) error {
	return r.DelAll(dst) // TODO: implement multi-conn routing.
}

// DelAll removes a route for dst.
func (r *NetlinkRouter) DelAll(dst netip.Prefix) error {
	slog.Debug("Removing route", slog.String("prefix", dst.String()))

	if err := r.mux.RemoveConnection(dst); err != nil {
		slog.Error("failed to remove connection", slog.Any("error", err))
	}
	if err := r.syncDNATChain(); err != nil {
		return fmt.Errorf("failed to sync DNAT chain: %w", err)
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
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}

	return nil
}

// ListRoutes returns a list of all routes in the tunnel.
func (r *NetlinkRouter) ListRoutes() ([]TunnelRoute, error) {
	ps := r.mux.Prefixes()
	rts := make([]TunnelRoute, 0, len(ps))
	for _, p := range ps {
		rts = append(rts, TunnelRoute{
			Dst: p,
			// TODO: Add connID,
			State: TunnelRouteStateActive,
		})
	}
	return rts, nil
}

// GetMuxedConnection returns the muxed connection for adding/removing connections.
func (r *NetlinkRouter) GetMuxedConnection() *connection.MuxedConn {
	return r.mux
}

// Close releases any resources associated with the router.
func (r *NetlinkRouter) Close() error {
	var firstErr error
	r.closeOnce.Do(func() {
		if err := r.mux.Close(); err != nil {
			slog.Error("Failed to close mux", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close mux: %w", err)
			}
		}

		if err := r.tunDev.Close(); err != nil {
			slog.Error("Failed to close TUN device", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close TUN device: %w", err)
			}
		}
	})
	return firstErr
}

// LocalAddresses returns the list of local addresses that are assigned to the router.
func (r *NetlinkRouter) LocalAddresses() ([]netip.Prefix, error) {
	if r.tunLink == nil {
		return nil, nil
	}

	addrs, err := netlink.AddrList(r.tunLink, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for link: %w", err)
	}

	var prefixes []netip.Prefix
	for _, addr := range addrs {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			slog.Warn("Failed to convert IP address", slog.String("ip", addr.IP.String()))
			continue
		}
		if !ip.IsGlobalUnicast() { // Skip non-global unicast addresses.
			slog.Debug("Skipping non-global unicast address", slog.String("ip", addr.IP.String()))
			continue
		}

		bits, _ := addr.Mask.Size()
		prefixes = append(prefixes, netip.PrefixFrom(ip, bits))
	}

	return prefixes, nil
}
