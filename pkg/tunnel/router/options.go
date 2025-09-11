package router

import (
	"net/netip"

	"github.com/dpeckett/network"
)

// Option represents a router configuration option.
type Option func(*routerOptions)

type routerOptions struct {
	extIPv6Prefix         netip.Prefix
	localAddresses        []netip.Prefix
	resolveConf           *network.ResolveConfig // If not set system default resolver is used
	pcapPath              string
	extIfaceName          string
	tunIfaceName          string
	socksListenAddr       string
	cksumRecalc           bool
	preserveDefaultGwDsts []netip.Prefix
	sourcePortHashing     bool
}

func defaultOptions() *routerOptions {
	return &routerOptions{
		extIfaceName:    "eth0",
		tunIfaceName:    "tun0",
		socksListenAddr: "localhost:1080",
		cksumRecalc:     false,
	}
}

// WithLocalAddresses sets the local addresses for the router.
func WithLocalAddresses(localAddresses []netip.Prefix) Option {
	return func(o *routerOptions) {
		o.localAddresses = localAddresses
	}
}

// WithExternalIPv6Prefix sets the external IPv6 prefix for the router.
func WithExternalIPv6Prefix(prefix netip.Prefix) Option {
	return func(o *routerOptions) {
		o.extIPv6Prefix = prefix
	}
}

// WithPcapPath sets the optional path to a packet capture file for the netstack router.
func WithPcapPath(path string) Option {
	return func(o *routerOptions) {
		o.pcapPath = path
	}
}

// WithResolveConfig sets the DNS configuration for the netstack router.
func WithResolveConfig(conf *network.ResolveConfig) Option {
	return func(o *routerOptions) {
		o.resolveConf = conf
	}
}

// WithExternalInterface sets the external interface name.
// Only valid for netlink routers.
func WithExternalInterface(name string) Option {
	return func(o *routerOptions) {
		o.extIfaceName = name
	}
}

// WithTunnelInterface sets the tunnel interface name.
// Only valid for netlink routers.
func WithTunnelInterface(name string) Option {
	return func(o *routerOptions) {
		o.tunIfaceName = name
	}
}

// WithSocksListenAddr sets the SOCKS listen address for the netstack router.
// Only valid for netstack routers.
func WithSocksListenAddr(addr string) Option {
	return func(o *routerOptions) {
		o.socksListenAddr = addr
	}
}

// WithChecksumRecalculation enables or disables checksum recalculation for the netstack router.
// Only valid for netstack routers.
func WithChecksumRecalculation(enable bool) Option {
	return func(o *routerOptions) {
		o.cksumRecalc = enable
	}
}

// WithPreserveDefaultGwDsts preserves default gateway routes for given destinations.
// Only valid for netlink routers.
func WithPreserveDefaultGwDsts(dsts []netip.Prefix) Option {
	return func(o *routerOptions) {
		o.preserveDefaultGwDsts = dsts
	}
}

// WithSourcePortHashing enables or disables source port hashing for routing decisions.
// Only valid for ICX routers.
func WithSourcePortHashing(enable bool) Option {
	return func(o *routerOptions) {
		o.sourcePortHashing = enable
	}
}
