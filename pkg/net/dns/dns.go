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

// options holds the DNS server configuration.
type options struct {
	// plugins is a list of DNS plugins to add to the server chain.
	plugins []plugin.Plugin
	// blockNonGlobalIPs controls whether responses containing non-global unicast IPs
	// (private, loopback, ULA addresses) should be blocked and return NXDOMAIN.
	blockNonGlobalIPs bool
}

// Option configures the DNS server.
type Option func(*options)

// WithBlockNonGlobalIPs blocks responses containing non-global unicast IPs.
func WithBlockNonGlobalIPs() Option {
	return func(o *options) {
		o.blockNonGlobalIPs = true
	}
}

// WithPlugins adds DNS plugins to the server chain.
func WithPlugins(p ...plugin.Plugin) Option {
	return func(o *options) {
		o.plugins = append(o.plugins, p...)
	}
}

// ListenAndServe starts a DNS server with the given options.
func ListenAndServe(addr string, opts ...Option) error {
	var sOpts options
	for _, opt := range opts {
		opt(&sOpts)
	}
	// runtime -> cache -> upstream
	up := &upstream{
		BlockNonGlobalIPs: sOpts.blockNonGlobalIPs,
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
	for i := len(sOpts.plugins) - 1; i >= 0; i-- {
		stack = sOpts.plugins[i](stack)
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
