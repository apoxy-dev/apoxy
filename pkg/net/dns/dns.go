package dns

import (
	"fmt"
	"net"

	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/cache"
	"golang.org/x/sync/errgroup"
)

var (
	srv *dnsserver.Server
)

// Options configures the DNS server behavior.
type Options struct {
	// Plugins is a list of DNS plugins to add to the server chain.
	Plugins []plugin.Plugin
	// BlockNonGlobalIPs controls whether responses containing non-global unicast IPs
	// (private, loopback, ULA addresses) should be blocked and return NXDOMAIN.
	BlockNonGlobalIPs bool
}

func WithBlockNonGlobalIPs() func(*Options) {
	return func(o *Options) {
		o.BlockNonGlobalIPs = true
	}
}

func WithPlugins(p ...plugin.Plugin) func(*Options) {
	return func(o *Options) {
		o.Plugins = append(o.Plugins, p...)
	}
}

// ListenAndServe starts a DNS server with the given options.
func ListenAndServe(addr string, opts ...func(*Options)) error {
	var opt Options
	for _, optFn := range opts {
		optFn(&opt)
	}
	// runtime -> cache -> upstream
	up := &upstream{
		BlockNonGlobalIPs: opt.BlockNonGlobalIPs,
	}
	if err := up.LoadResolvConf(); err != nil {
		return err
	}

	upChain := cache.New()
	upChain.Next = up

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	c := &dnsserver.Config{
		Zone:        ".",
		Transport:   "dns",
		ListenHosts: []string{host},
		Port:        port,
		Debug:       true,
	}
	var stack plugin.Handler = upChain
	for i := len(opt.Plugins) - 1; i >= 0; i-- {
		stack = opt.Plugins[i](stack)
	}
	c.AddPlugin(func(next plugin.Handler) plugin.Handler { return stack })

	log.Infof("Starting DNS server on %v:%v", host, port)

	srv, err = dnsserver.NewServer("dns://"+addr, []*dnsserver.Config{c})
	if err != nil {
		return err
	}

	eg := errgroup.Group{}
	if udp, err := srv.ListenPacket(); err != nil {
		return fmt.Errorf("failed to listen on udp: %w", err)
	} else {
		eg.Go(func() error {
			return srv.ServePacket(udp)
		})
	}
	if tcp, err := srv.Listen(); err != nil {
		return fmt.Errorf("failed to listen on tcp: %w", err)
	} else {
		eg.Go(func() error {
			return srv.Serve(tcp)
		})
	}

	return eg.Wait()
}
