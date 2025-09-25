package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/apoxy-dev/icx"
	"github.com/dpeckett/network"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/socksproxy"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

var (
	_ Router = (*ICXNetstackRouter)(nil)
)

type ICXNetstackRouter struct {
	Handler   *icx.Handler
	phy       *l2pc.L2PacketConn
	net       *netstack.ICXNetwork
	proxy     *socksproxy.ProxyServer
	closeOnce sync.Once
}

func NewICXNetstackRouter(pc net.PacketConn, mtu int, opts ...Option) (*ICXNetstackRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	phy, err := l2pc.NewL2PacketConn(pc)
	if err != nil {
		return nil, fmt.Errorf("failed to create L2 packet connection phy: %w", err)
	}

	localUDPAddr := pc.LocalAddr().(*net.UDPAddr)

	localAddr := netip.AddrPortFrom(netip.MustParseAddr(localUDPAddr.IP.String()),
		uint16(localUDPAddr.Port))

	handler, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(localAddr)),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()), icx.WithLayer3VirtFrames())
	if err != nil {
		return nil, fmt.Errorf("failed to create ICX handler: %w", err)
	}

	net, err := netstack.NewICXNetwork(handler, phy, mtu, options.resolveConf, options.pcapPath)
	if err != nil {
		_ = phy.Close()
		return nil, fmt.Errorf("failed to create ICX network: %w", err)
	}

	proxy := socksproxy.NewServer(
		options.socksListenAddr,
		net.Network,
		network.Host(),
	)

	return &ICXNetstackRouter{
		Handler: handler,
		phy:     phy,
		net:     net,
		proxy:   proxy,
	}, nil
}

func (r *ICXNetstackRouter) Close() error {
	var err error
	r.closeOnce.Do(func() {
		if err = r.proxy.Close(); err != nil {
			err = fmt.Errorf("failed to close SOCKS proxy: %w", err)
			return
		}

		if err = r.net.Close(); err != nil {
			err = fmt.Errorf("failed to close ICX network: %w", err)
			return
		}

		err = r.phy.Close()
	})
	return err
}

// Start initializes the router and starts forwarding traffic.
// It's a blocking call that should be run in a separate goroutine.
func (r *ICXNetstackRouter) Start(ctx context.Context) error {
	_, socksListenPortStr, err := net.SplitHostPort(r.proxy.Addr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen address: %w", err)
	}

	socksListenPort, err := strconv.Atoi(socksListenPortStr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen port: %w", err)
	}

	slog.Info("Forwarding all inbound traffic to loopback interface")

	if err := r.net.ForwardTo(ctx, network.Filtered(&network.FilteredNetworkConfig{
		DeniedPorts: []uint16{uint16(socksListenPort)},
		Upstream:    network.Host(),
	})); err != nil {
		return fmt.Errorf("failed to forward to loopback: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		slog.Debug("Closing router")
		return r.Close()
	})

	g.Go(func() error {
		slog.Info("Splicing packets between netstack and ICX")

		// This will be terminated when the router is closed.
		if err := r.net.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("failed to splice packets: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		slog.Info("Starting SOCKS5 proxy", slog.String("listenAddr", r.proxy.Addr))

		if err := r.proxy.ListenAndServe(ctx); err != nil {
			slog.Error("SOCKS proxy error", slog.String("error", err.Error()))
		}

		return nil
	})

	return g.Wait()
}

// AddAddr adds a tun with an associated address to the router.
func (r *ICXNetstackRouter) AddAddr(addr netip.Prefix, tun connection.Connection) error {
	if err := r.net.AddAddr(addr); err != nil {
		return fmt.Errorf("failed to add address to ICX network: %w", err)
	}

	return nil
}

// DelAddr removes a tun by its addr from the router.
func (r *ICXNetstackRouter) DelAddr(addr netip.Prefix) error {
	if err := r.net.DelAddr(addr); err != nil {
		return fmt.Errorf("failed to remove address from ICX network: %w", err)
	}

	return nil
}

// AddRoute adds a dst prefix to be routed through the given tunnel connection.
// If multiple tunnels are provided, the router will distribute traffic across them
// uniformly.
func (r *ICXNetstackRouter) AddRoute(dst netip.Prefix) error {
	return nil
}

// Del removes a routing associations for a given destination prefix and Connection name.
// New matching flows will stop being routed through the tunnel immediately while
// existing flows may continue to use the tunnel for some draining period before
// getting re-routed via a different tunnel or dropped (if no tunnel is available for
// the given dst).
func (r *ICXNetstackRouter) DelRoute(dst netip.Prefix) error {
	return nil
}
