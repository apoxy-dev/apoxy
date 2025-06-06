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

// ListenAndServe starts a DNS server.
func ListenAndServe(addr string, plugins ...plugin.Plugin) error {
	// runtime -> cache -> upstream
	up := &upstream{}
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
	for i := len(plugins) - 1; i >= 0; i-- {
		stack = plugins[i](stack)
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
