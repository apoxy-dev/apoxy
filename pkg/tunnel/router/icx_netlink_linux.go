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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/addrselect"
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/mac"
	"github.com/apoxy-dev/icx/queues"
	"github.com/apoxy-dev/icx/veth"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
	ingressFilter *filter.Program
	pcapFile      *os.File
	tun           *forwarder.Forwarder
	iptV4, iptV6  utiliptables.Interface
	extAddrs      addrselect.List
	closeOnce     sync.Once

	dnatMu   sync.Mutex
	dnatDsts map[netip.Addr]struct{}
}

func NewICXNetlinkRouter(opts ...Option) (*ICXNetlinkRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	if err := ensureIptablesBackend(); err != nil {
		return nil, fmt.Errorf("failed to select iptables backend: %w", err)
	}

	extLink, err := netlink.LinkByName(options.extIfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", options.extIfaceName, err)
	}

	extAddrs, err := addrsForInterface(extLink, icxDefaultPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", options.extIfaceName, err)
	}

	numQueues, err := queues.NumQueues(extLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of TX queues for interface %s: %w", options.extIfaceName, err)
	}

	// A previous run that died without cleanup (crash, SIGKILL) leaves the
	// veth pair behind and veth.Create is not idempotent, so sweep any
	// leftover link first. Deleting one end of a veth pair removes both.
	if old, err := netlink.LinkByName(options.tunIfaceName); err == nil {
		if err := netlink.LinkDel(old); err != nil {
			return nil, fmt.Errorf("failed to delete leftover interface %q: %w", options.tunIfaceName, err)
		}
		slog.Info("Deleted leftover tunnel interface from previous run",
			slog.String("name", options.tunIfaceName))
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

	tun, err := forwarder.NewForwarder(
		handler,
		forwarder.WithPhyName(options.extIfaceName),
		forwarder.WithVirtName(tunDev.Peer.Attrs().Name),
		forwarder.WithPhyFilter(ingressFilter),
		forwarder.WithPcapWriter(pcapWriter),
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
	// Replace, not Add: this router is the sole owner of the device's routes,
	// and a stale route for the same /96 (leaked by a crashed predecessor on
	// the persistent veth, or by an aborted connect racing this one) must not
	// permanently brick the prefix with EEXIST (2026-08-03 incident).
	if err := netlink.RouteReplace(route); err != nil {
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
	// Ensure the chain exists, then (re)ensure every rule unconditionally. Every
	// rule below is applied through the idempotent EnsureRule (an iptables -C
	// check precedes the add), so re-running is a no-op when the rules are
	// already present. We must not early-return on an existing chain: the relay
	// runs with host networking, so the chain and its rules persist in the node
	// netns across pod restarts, and a guard keyed on chain existence would skip
	// any rule added in a newer relay version (e.g. the overlay no-masquerade
	// RETURN below) forever after the first deploy.
	if _, err := r.iptV6.EnsureChain(utiliptables.TableNAT, ChainA3yTunRules); err != nil {
		return fmt.Errorf("failed to ensure %s chain: %w", ChainA3yTunRules, err)
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

	// Exclude overlay-bound traffic from source NAT. Decapped transit frames are
	// re-routed out the tunnel interface so the icx datapath can re-encapsulate
	// them toward the destination peer; any masquerade on that path — the node's
	// CNI masq-all-non-cluster rule (the overlay CIDR is not a cluster prefix) or
	// our own egress rule below — would rewrite the inner source to a node
	// address, which the destination agent then drops as an invalid tunnel
	// source. Prepend so it wins over the node's masquerade rules.
	noMasqRuleSpec := []string{"-o", tunName, "-j", "RETURN"}
	slog.Info("Setting up no-masquerade rule for overlay traffic", slog.String("tun_iface", tunName))
	if _, err := r.iptV4.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting, noMasqRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure no-masquerade rule: %w", err)
	}
	if _, err := r.iptV6.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting, noMasqRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure no-masquerade rule: %w", err)
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
	r.dnatMu.Lock()
	defer r.dnatMu.Unlock()

	natChains := proxyutil.NewLineBuffer()
	natChains.Write(utiliptables.MakeChainLine(ChainA3yTunRules))

	natRules := proxyutil.NewLineBuffer()

	peers := r.Handler.ListVirtualNetworks()

	dsts := make(map[netip.Addr]struct{})
	for i, peer := range peers {
		// Under source learning the remote endpoint may not be learned yet.
		peerAddr := "<unlearned>"
		if ra := peer.RemoteAddr(); ra != nil {
			peerAddr = ra.Addr.String()
		}
		slog.Debug("Adding DNAT rules for peer", slog.String("peer", peerAddr))

		for _, route := range peer.AllowedRoutes() {
			if route.Dst.Addr().Is4() { // Skipping IPv4 peers - only IPv6 tunnel ingress is supported.
				continue
			}
			dsts[route.Dst.Addr()] = struct{}{}
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

	// Only surface syncs that actually change the DNAT destination set;
	// no-op resyncs (e.g. session churn behind the same addresses) stay at Debug.
	var added, removed []string
	for d := range dsts {
		if _, ok := r.dnatDsts[d]; !ok {
			added = append(added, d.String())
		}
	}
	for d := range r.dnatDsts {
		if _, ok := dsts[d]; !ok {
			removed = append(removed, d.String())
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		sort.Strings(added)
		sort.Strings(removed)
		slog.Info("Syncing DNAT rules",
			slog.Int("num_peers", len(peers)),
			slog.Any("added", added),
			slog.Any("removed", removed))
	} else {
		slog.Debug("Syncing DNAT rules", slog.Int("num_peers", len(peers)))
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

	r.dnatDsts = dsts

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

	// Remove the POSTROUTING overlay no-masquerade RETURN rule (v4 + v6).
	noMasqRuleSpec := []string{"-o", tunName, "-j", "RETURN"}
	if err := r.iptV4.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPostrouting, noMasqRuleSpec...); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to delete v4 no-masquerade rule: %w", err)
	}
	if err := r.iptV6.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPostrouting, noMasqRuleSpec...); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to delete v6 no-masquerade rule: %w", err)
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

// xtablesBinaryNames are the binaries utiliptables execs via PATH; a backend
// shim must cover all of them so every call lands on the same backend.
var xtablesBinaryNames = []string{
	"iptables", "iptables-save", "iptables-restore",
	"ip6tables", "ip6tables-save", "ip6tables-restore",
}

// iptablesBackendOnce guards the process-global PATH mutation below: routers
// may be constructed concurrently, and prepending twice is at best redundant.
var (
	iptablesBackendOnce sync.Once
	iptablesBackendErr  error
)

// ensureIptablesBackend points the iptables binaries that utiliptables execs
// (resolved via PATH) at the xtables backend the host is actually using.
// Container images hard-wire the plain binary names to one backend (the envoy
// base picks legacy), while the host netns this router runs in may be
// programmed through the other by kube-proxy or the CNI's masquerade agent.
// Rules never compose across backends — the kernel evaluates the legacy and
// nft hooks independently — so e.g. our "-o <tun> -j RETURN" no-masquerade
// exemption written to the legacy table cannot stop an nft MASQUERADE from
// rewriting overlay transit traffic. Detection mirrors the upstream
// kubernetes-sigs/iptables-wrappers script: prefer the backend holding
// kubelet's hint/canary chains, fall back to the one with more rules.
//
// A PATH shim is the only redirection utiliptables admits (its New() takes no
// exec injector and resolves bare binary names per call), and unlike an
// image-entrypoint fix it also covers `apoxy alpha tunnel relay` on arbitrary
// hosts. The mutation happens once per process, before any rule is written.
//
// Failure policy follows the evidence: when detection has proof of the host's
// backend (hint chains or programmed rules) and that backend can't be
// programmed from this image, constructing the router fails — writing rules
// into the other backend would leave the process looking healthy while its
// no-masq/DNAT rules are dead. When detection has no evidence (bare host,
// zero rules in both backends), the plain binaries are kept: they are the
// host's only backend there and any choice we impose would be a guess.
func ensureIptablesBackend() error {
	iptablesBackendOnce.Do(func() { iptablesBackendErr = selectIptablesBackend() })
	return iptablesBackendErr
}

func selectIptablesBackend() error {
	backend, evidence := detectHostIptablesBackend()
	if !evidence {
		return nil
	}

	if out, err := exec.Command("iptables", "--version").CombinedOutput(); err == nil {
		current := "legacy"
		if strings.Contains(string(out), "nf_tables") {
			current = "nft"
		}
		if current == backend {
			return nil
		}
	}

	targets := make(map[string]string, len(xtablesBinaryNames))
	for _, name := range xtablesBinaryNames {
		variant := xtablesVariantName(name, backend)
		target, err := exec.LookPath(variant)
		if err != nil {
			return fmt.Errorf("host uses the %s iptables backend but %s is not available: %w", backend, variant, err)
		}
		targets[name] = target
	}

	dir := filepath.Join(os.TempDir(), "a3y-xtables-"+backend)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create xtables shim dir: %w", err)
	}
	for name, target := range targets {
		link := filepath.Join(dir, name)
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			return fmt.Errorf("failed to create %s shim: %w", name, err)
		}
	}
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH")); err != nil {
		return fmt.Errorf("failed to prepend xtables shim dir to PATH: %w", err)
	}

	slog.Info("Selected host iptables backend", slog.String("backend", backend))
	return nil
}

// xtablesVariantName maps a plain xtables binary name to its backend-specific
// variant: the backend is inserted after the tool name, before any -save or
// -restore suffix (e.g. "iptables-save" + "nft" -> "iptables-nft-save").
func xtablesVariantName(name, backend string) string {
	tool, suffix, found := strings.Cut(name, "-")
	if !found {
		return name + "-" + backend
	}
	return tool + "-" + backend + "-" + suffix
}

// detectHostIptablesBackend returns "legacy" or "nft" depending on which
// xtables backend the surrounding netns is programmed through, plus whether
// there was actual evidence for the choice (kubelet hint chains or programmed
// rules) as opposed to a bare-host default.
func detectHostIptablesBackend() (string, bool) {
	// Kubelet stamps a hint chain into the mangle table of the backend the
	// node's Kubernetes components use; trust it when present.
	for _, backend := range []string{"nft", "legacy"} {
		for _, cmd := range []string{"iptables", "ip6tables"} {
			out, err := exec.Command(cmd+"-"+backend+"-save", "-t", "mangle").CombinedOutput()
			if err != nil {
				continue
			}
			if bytes.Contains(out, []byte("KUBE-IPTABLES-HINT")) || bytes.Contains(out, []byte("KUBE-KUBELET-CANARY")) {
				return backend, true
			}
		}
	}

	// No kubelet hint: pick the backend with more programmed rules. Equal
	// counts (typically a bare host with zero rules anywhere) carry no
	// evidence at all.
	count := func(backend string) int {
		n := 0
		for _, cmd := range []string{"iptables", "ip6tables"} {
			out, err := exec.Command(cmd + "-" + backend + "-save").CombinedOutput()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "-") {
					n++
				}
			}
		}
		return n
	}
	legacy, nft := count("legacy"), count("nft")
	if legacy > nft {
		return "legacy", true
	}
	return "nft", nft > legacy
}
