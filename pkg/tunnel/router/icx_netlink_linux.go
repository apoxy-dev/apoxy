package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/addrselect"
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/mac"
	"github.com/apoxy-dev/icx/tunnel"
	"github.com/apoxy-dev/icx/veth"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"


	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	icxDefaultPort = 6081
)

var (
	_ Router = (*ICXNetlinkRouter)(nil)
)

type ICXNetlinkRouter struct {
	Handler       *icx.Handler
	extLink       netlink.Link
	tunDev        *veth.Handle
	tunLink       netlink.Link
	ingressFilter *xdp.Program
	pcapFile      *os.File
	tun           *tunnel.Tunnel
	iptV4, iptV6  utiliptables.Interface
	extAddrs      addrselect.List
	closeOnce     sync.Once
}

func NewICXNetlinkRouter(opts ...Option) (*ICXNetlinkRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	extLink, err := netlink.LinkByName(options.extIfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", options.extIfaceName, err)
	}

	extAddrs, err := addrsForInterface(extLink, icxDefaultPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", options.extIfaceName, err)
	}

	numQueues, err := tunnel.NumQueues(extLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of TX queues for interface %s: %w", options.extIfaceName, err)
	}

	tunDev, err := veth.Create(options.tunIfaceName, numQueues, options.tunMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create veth device: %w", err)
	}

	tunLink, err := netlink.LinkByName(options.tunIfaceName)
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to get veth interface: %w", err)
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
			_ = tunDev.Close()
			return nil, fmt.Errorf("failed to add address to veth interface: %w", err)
		}
		slog.Info("Added address to veth interface", slog.String("addr", addr.String()))
	}

	virtMAC := tcpip.LinkAddress(tunDev.Link.Attrs().HardwareAddr)

	handlerOpts := []icx.HandlerOption{
		icx.WithVirtMAC(virtMAC),
		icx.WithKeepAliveInterval(25 * time.Second),
	}

	for _, addr := range extAddrs {
		fa := netstack.ToFullAddress(netip.MustParseAddrPort(addr.String()))
		fa.LinkAddr = tcpip.LinkAddress(extLink.Attrs().HardwareAddr)

		handlerOpts = append(handlerOpts,
			icx.WithLocalAddr(fa),
		)
	}

	if options.sourcePortHashing {
		handlerOpts = append(handlerOpts, icx.WithSourcePortHashing())
	}

	handler, err := icx.NewHandler(handlerOpts...)
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to create handler: %w", err)
	}

	ingressFilter, err := filter.Geneve(extAddrs...)
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to create ingress filter: %w", err)
	}

	var pcapFile *os.File
	var pcapWriter *pcapgo.Writer
	if options.pcapPath != "" {
		pcapFile, err = os.Create(options.pcapPath)
		if err != nil {
			_ = tunDev.Close()
			_ = ingressFilter.Close()
			return nil, fmt.Errorf("failed to create pcap file: %w", err)
		}

		pcapWriter = pcapgo.NewWriter(pcapFile)
		if err := pcapWriter.WriteFileHeader(uint32(math.MaxUint16), layers.LinkTypeEthernet); err != nil {
			return nil, fmt.Errorf("failed to write PCAP header: %w", err)
		}
	}

	tun, err := tunnel.NewTunnel(
		handler,
		tunnel.WithPhyName(options.extIfaceName),
		tunnel.WithVirtName(tunDev.Peer.Attrs().Name),
		tunnel.WithPhyFilter(ingressFilter),
		tunnel.WithPcapWriter(pcapWriter),
	)
	if err != nil {
		_ = tunDev.Close()
		_ = ingressFilter.Close()
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	var extAddrsList addrselect.List
	for _, addr := range extAddrs {
		extAddrsList = append(extAddrsList, netstack.ToFullAddress(netip.MustParseAddrPort(addr.String())))
	}

	return &ICXNetlinkRouter{
		Handler:       handler,
		extLink:       extLink,
		tunDev:        tunDev,
		tunLink:       tunLink,
		ingressFilter: ingressFilter,
		pcapFile:      pcapFile,
		tun:           tun,
		iptV4:         utiliptables.New(utiliptables.ProtocolIPv4),
		iptV6:         utiliptables.New(utiliptables.ProtocolIPv6),
		extAddrs:      extAddrsList,
	}, nil
}

func (r *ICXNetlinkRouter) Close() error {
	var firstErr error
	r.closeOnce.Do(func() {
		if err := r.teardownDNAT(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to teardown DNAT: %w", err)
		}

		if err := r.tun.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close tunnel: %w", err)
		}

		if err := r.tunDev.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close veth device: %w", err)
		}

		if err := r.ingressFilter.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close ingress filter: %w", err)
		}

		if r.pcapFile != nil {
			if err := r.pcapFile.Close(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("failed to close pcap file: %w", err)
			}
		}
	})
	return firstErr
}

// Start initializes the router and starts forwarding traffic.
// It's a blocking call that should be run in a separate goroutine.
func (r *ICXNetlinkRouter) Start(ctx context.Context) error {
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}

	if err := r.setupDNAT(); err != nil {
		return fmt.Errorf("failed to setup DNAT: %w", err)
	}

	if err := r.tun.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("failed to start tunnel: %w", err)
	}

	return nil
}

// AddAddr adds a tun with an associated address to the router.
func (r *ICXNetlinkRouter) AddAddr(_ netip.Prefix, _ connection.Connection) error {
	// Virtual networks are managed externally, so we just need to
	// sync the DNAT rules to include the new address.

	if err := r.syncDNATChain(); err != nil {
		return fmt.Errorf("failed to sync DNAT chain: %w", err)
	}

	return nil
}

// DelAddr removes a tun by its addr from the router.
func (r *ICXNetlinkRouter) DelAddr(_ netip.Prefix) error {
	// Virtual networks are managed externally, so we just need to
	// sync the DNAT rules to remove the address.

	if err := r.syncDNATChain(); err != nil {
		return fmt.Errorf("failed to sync DNAT chain: %w", err)
	}

	return nil
}

// AddRoute adds a dst prefix to be routed through the given tunnel connection.
// If multiple tunnels are provided, the router will distribute traffic across them
// uniformly.
func (r *ICXNetlinkRouter) AddRoute(dst netip.Prefix) error {
	slog.Info("Adding route", slog.String("addr", dst.String()))

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
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	slog.Info("Route added", slog.String("dst", dst.String()))

	return nil
}

// Del removes a routing associations for a given destination prefix and Connection name.
// New matching flows will stop being routed through the tunnel immediately while
// existing flows may continue to use the tunnel for some draining period before
// getting re-routed via a different tunnel or dropped (if no tunnel is available for
// the given dst).
func (r *ICXNetlinkRouter) DelRoute(dst netip.Prefix) error {
	slog.Debug("Removing route", slog.String("prefix", dst.String()))

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

	slog.Info("Route removed", slog.String("dst", dst.String()))
	return nil
}

// ResolveMAC resolves the MAC address for the given peer address.
func (r *ICXNetlinkRouter) ResolveMAC(ctx context.Context, peerAddr netip.AddrPort) (tcpip.LinkAddress, error) {
	peerFullAddr := netstack.ToFullAddress(peerAddr)

	localFullAddr := r.extAddrs.Select(peerFullAddr)

	slog.Debug("Resolving MAC address",
		slog.String("local", localFullAddr.Addr.String()),
		slog.String("peer", peerFullAddr.Addr.String()),
	)

	linkAddr, err := mac.Resolve(ctx, r.extLink, localFullAddr, peerFullAddr.Addr)
	if err != nil {
		return "", fmt.Errorf("failed to resolve peer MAC address: %w", err)
	}

	slog.Info("Resolved peer MAC address",
		slog.String("local", localFullAddr.Addr.String()),
		slog.String("peer", peerFullAddr.Addr.String()),
		slog.String("mac", linkAddr.String()),
	)

	return linkAddr, nil
}

func (r *ICXNetlinkRouter) setupDNAT() error {
	exists, err := r.iptV6.EnsureChain(utiliptables.TableNAT, ChainA3yTunRules)
	if err != nil {
		return fmt.Errorf("failed to ensure %s chain: %w", ChainA3yTunRules, err)
	}
	if exists { // Jump and forwarding rules should be already set up.
		return nil
	}

	extName := r.extLink.Attrs().Name
	tunName := r.tunLink.Attrs().Name

	_, extIPv6Prefix := getExternalIPPrefixes(extName)

	if extIPv6Prefix.IsValid() {
		slog.Info("Setting up jump rule",
			slog.String("ext_iface", extName),
			slog.String("ext_addr", extIPv6Prefix.Addr().String()))

		// Traffic arriving at the designated external interface will be processed by the A3Y-TUN-RULES chain.
		jRuleSpec := []string{"-d", extIPv6Prefix.Addr().String(), "-i", extName, "-j", string(ChainA3yTunRules)}
		if _, err := r.iptV6.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPrerouting, jRuleSpec...); err != nil {
			return fmt.Errorf("failed to ensure jump rule: %w", err)
		}
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

func (r *ICXNetlinkRouter) syncDNATChain() error {
	natChains := proxyutil.NewLineBuffer()
	natChains.Write(utiliptables.MakeChainLine(ChainA3yTunRules))

	natRules := proxyutil.NewLineBuffer()

	peers := r.Handler.ListVirtualNetworks()

	slog.Info("Syncing DNAT rules", slog.Int("num_peers", len(peers)))

	for i, peer := range peers {
		slog.Info("Adding DNAT rules for peer", slog.String("peer", peer.RemoteAddr.Addr.String()))

		for _, route := range peer.AllowedRoutes {
			if route.Dst.Addr().Is4() { // Skipping IPv4 peers - only IPv6 tunnel ingress is supported.
				continue
			}
			natRules.Write(
				"-A", string(ChainA3yTunRules),
				"-m", "statistic",
				"--mode", "random",
				"--probability", probability(len(peers)-i),
				"-j", "DNAT",
				"--to-destination", route.Dst.Addr().String(),
			)
		}
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

func (r *ICXNetlinkRouter) teardownDNAT() error {
	var firstErr error

	extName := r.extLink.Attrs().Name
	tunName := r.tunLink.Attrs().Name

	_, extIPv6Prefix := getExternalIPPrefixes(extName)

	// Remove the v6 PREROUTING jump rule (if we added it).
	if extIPv6Prefix.IsValid() {
		jRuleSpec := []string{"-d", extIPv6Prefix.Addr().String(), "-i", extName, "-j", string(ChainA3yTunRules)}
		if err := r.iptV6.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPrerouting, jRuleSpec...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to delete v6 jump rule: %w", err)
		}
	}

	// Remove the FORWARD rules (we added them via iptV6 in setup).
	fwdRuleSpecs := [][]string{
		{"-i", extName, "-o", tunName, "-j", "ACCEPT"},
		{"-i", tunName, "-o", extName, "-j", "ACCEPT"},
	}
	for _, ruleSpec := range fwdRuleSpecs {
		if err := r.iptV6.DeleteRule(utiliptables.TableFilter, utiliptables.ChainForward, ruleSpec...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to delete v6 forward rule %v: %w", ruleSpec, err)
		}
	}

	// Remove POSTROUTING MASQUERADE (v4 + v6).
	masqRuleSpec := []string{"-o", extName, "-j", "MASQUERADE"}
	if err := r.iptV4.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPostrouting, masqRuleSpec...); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to delete v4 masquerade rule: %w", err)
	}
	if err := r.iptV6.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPostrouting, masqRuleSpec...); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to delete v6 masquerade rule: %w", err)
	}

	// Flush & delete the apoxy chain.
	if err := r.iptV6.FlushChain(utiliptables.TableNAT, ChainA3yTunRules); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to flush chain %s: %w", ChainA3yTunRules, err)
	}
	if err := r.iptV6.DeleteChain(utiliptables.TableNAT, ChainA3yTunRules); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to delete chain %s: %w", ChainA3yTunRules, err)
	}

	return firstErr
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

func getExternalIPPrefixes(extIfaceName string) (extIPv4Prefix, extIPv6Prefix netip.Prefix) {
	extAddrs, err := tunnet.GetGlobalUnicastAddresses(extIfaceName, false)
	if err != nil {
		slog.Warn("Failed to get local IPv4 address",
			slog.String("ext_iface", extIfaceName), slog.Any("error", err))
	} else {
		for _, addr := range extAddrs {
			if addr.Addr().Is4() {
				extIPv4Prefix = addr
				break
			}
		}
		for _, addr := range extAddrs {
			if addr.Addr().Is6() {
				extIPv6Prefix = addr
				break
			}
		}
	}

	return
}
