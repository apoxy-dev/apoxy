package router

import (
	"net/netip"

	"github.com/dpeckett/network"
)

// Option represents a router configuration option.
type Option func(*routerOptions)

type routerOptions struct {
	localAddresses  []netip.Prefix
	resolveConf     *network.ResolveConfig // If not set system default resolver is used
	pcapPath        string
	extIfaceName    string
	tunIfaceName    string
	socksListenAddr string
}

func defaultOptions() *routerOptions {
	return &routerOptions{
		extIfaceName:    "eth0",
		tunIfaceName:    "tun0",
		socksListenAddr: "localhost:1080",
	}
}

// WithLocalAddresses sets the local addresses for the router.
func WithLocalAddresses(localAddresses []netip.Prefix) Option {
	return func(o *routerOptions) {
		o.localAddresses = localAddresses
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
