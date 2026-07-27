package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/apoxy-dev/icx"
	"github.com/dpeckett/network"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
)

type routerInitOpts struct {
	pcGeneve        batchpc.BatchPacketConn
	socksListenAddr string
	pcapPath        string
	// tunMode selects the kernel TUN datapath (ICXTunRouter) over the default
	// in-process netstack + SOCKS one. Linux only.
	tunMode      bool
	tunIfaceName string
	tunNetns     string
}

// initRouter creates and starts the overlay router / icx.Handler using the
// bootstrap response. The datapath is either the in-process netstack (with a
// SOCKS listener) or, in tun mode, a kernel TUN device any process in the
// netns can route into.
func initRouter(
	ctx context.Context,
	g *errgroup.Group,
	connectResp *api.ConnectResponse,
	opts routerInitOpts,
) (router.Router, *icx.Handler, error) {
	routerOpts := []router.Option{
		router.WithPacketConn(opts.pcGeneve),
		router.WithTunnelMTU(connectResp.MTU),
	}

	var (
		r   router.Router
		h   *icx.Handler
		err error
	)
	if opts.tunMode {
		// DNS/pcap/SOCKS are netstack facilities; the TUN datapath delegates
		// name resolution and capture to the host network stack.
		if opts.pcapPath != "" {
			return nil, nil, fmt.Errorf("packet capture is not supported with the TUN datapath")
		}
		if opts.tunIfaceName != "" {
			routerOpts = append(routerOpts, router.WithTunnelInterface(opts.tunIfaceName))
		}
		if opts.tunNetns != "" {
			routerOpts = append(routerOpts, router.WithTunnelNetns(opts.tunNetns))
		}
		tr, terr := router.NewICXTunRouter(routerOpts...)
		if terr != nil {
			return nil, nil, terr
		}
		r, h = tr, tr.Handler
	} else {
		if opts.socksListenAddr != "" {
			routerOpts = append(routerOpts, router.WithSocksListenAddr(opts.socksListenAddr))
		}
		if opts.pcapPath != "" {
			routerOpts = append(routerOpts, router.WithPcapPath(opts.pcapPath))
		}
		if connectResp.DNS != nil {
			routerOpts = append(routerOpts, router.WithResolveConfig(&network.ResolveConfig{
				Nameservers:   connectResp.DNS.Servers,
				SearchDomains: connectResp.DNS.SearchDomains,
				NDots:         connectResp.DNS.NDots,
			}))
		}
		var nr *router.ICXNetstackRouter
		nr, err = router.NewICXNetstackRouter(routerOpts...)
		if err != nil {
			return nil, nil, err
		}
		r, h = nr, nr.Handler
	}

	// Add routes.
	for _, rt := range connectResp.Routes {
		slog.Info("Adding route", slog.String("destination", rt.Destination))

		dst, err := netip.ParsePrefix(rt.Destination)
		if err != nil {
			slog.Warn("Failed to parse route prefix",
				slog.String("prefix", rt.Destination),
				slog.Any("error", err))
			continue
		}
		// Egress default routes are a netstack-only facility: on the kernel
		// TUN datapath they would shadow the netns default route and pull all
		// traffic of the embedding process (e.g. the backplane) into the
		// overlay, so they are never installed on the device.
		if opts.tunMode && dst.Bits() == 0 {
			slog.Info("Skipping default route on TUN datapath", slog.String("destination", rt.Destination))
			continue
		}
		if err := r.AddRoute(dst); err != nil {
			slog.Warn("Failed to add route",
				slog.String("prefix", rt.Destination),
				slog.Any("error", err))
		}
	}

	// Start the router.
	g.Go(func() error { return r.Start(ctx) })

	return r, h, nil
}
