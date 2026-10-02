package vpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/dpeckett/network"
	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"

	apoxyconfig "github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/socksproxy"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
	"github.com/apoxy-dev/apoxy/pkg/vpc/hostcheck"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	driverNetstack = "netstack"
	driverTun      = "tun"
)

var transportModes = map[string]agent.TransportMode{
	"auto": agent.TransportAuto,
	"psp":  agent.TransportPSP,
	"quic": agent.TransportQUIC,
}

// connectOptions are the flags of vpc connect.
type connectOptions struct {
	name      string
	transport string
	driver    string
	routes    []string
	labels    map[string]string
	socksAddr string
	tunIfname string
	mtu       int
	relays    int
}

func connectCmd() *cobra.Command {
	var o connectOptions
	cmd := &cobra.Command{
		Use:   "connect [VPC]",
		Short: "Connect this host to a VPC network",
		Long: `Connect this host to a VPC network. The default network is "default".

The tun driver makes a kernel TUN device, so all processes on the host can
reach the VPC. The netstack driver needs no privileges. It gives a SOCKS5
proxy, and it forwards connections from the VPC to localhost.`,
		Args:   cobra.MaximumNArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			vpc := "default"
			if len(args) == 1 {
				vpc = args[0]
			}
			host, _ := os.Hostname()
			cfg, driver, err := o.agentConfig(host, tunAvailable())
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return runConnect(cmd.Context(), cmd.ErrOrStderr(), vpc, &o, cfg, driver)
		},
	}
	o.addFlags(cmd)
	return cmd
}

func (o *connectOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.name, "name", "", "Attachment name, a DNS label (default: the host name).")
	f.StringVar(&o.transport, "transport", "auto", "Data transport: auto, psp or quic. Auto uses psp, and quic when the path to the relay drops psp.")
	f.StringVar(&o.driver, "driver", "auto", "Data path: auto, netstack or tun. Auto uses tun when the process has NET_ADMIN, else netstack.")
	f.StringArrayVar(&o.routes, "route", nil, "CIDR that this host advertises into the VPC. Repeatable.")
	f.StringToStringVar(&o.labels, "label", nil, "Attachment label (key=value) for VPCService selection. Repeatable.")
	f.StringVar(&o.socksAddr, "socks-addr", "localhost:1080", "SOCKS5 listen address of the netstack driver. Empty disables the proxy.")
	f.StringVar(&o.tunIfname, "tun-ifname", "apoxy0", "Name of the TUN device of the tun driver.")
	f.IntVar(&o.relays, "relays", 2, "Relay sessions to keep, 1 to 3. One carries the traffic. The others are open on other relays and take over when it ends.")
	f.IntVar(&o.mtu, "mtu", 0, fmt.Sprintf("Device MTU, %d to %d. 0 uses the VPC MTU when the path to the relay carries it, else %d.", psp.DefaultMTU, psp.MaxMTU, psp.DefaultMTU))
}

// agentConfig maps the flags to the agent config and the driver. host is the
// host name, and canTun tells if the process can make a TUN device.
func (o *connectOptions) agentConfig(host string, canTun bool) (agent.Config, string, error) {
	var cfg agent.Config
	cfg.Name = o.name
	if cfg.Name == "" {
		cfg.Name = strings.ToLower(strings.SplitN(host, ".", 2)[0])
	}
	if err := identity.ValidateAgentName(cfg.Name); err != nil {
		return cfg, "", fmt.Errorf("%w; set --name", err)
	}
	mode, ok := transportModes[o.transport]
	if !ok {
		return cfg, "", fmt.Errorf("invalid --transport %q: use auto, psp or quic", o.transport)
	}
	cfg.TransportMode = mode
	driver := o.driver
	switch driver {
	case "auto":
		driver = driverNetstack
		if canTun {
			driver = driverTun
		}
	case driverNetstack:
	case driverTun:
		if runtime.GOOS != "linux" {
			return cfg, "", errors.New("the tun driver needs Linux")
		}
	default:
		return cfg, "", fmt.Errorf("invalid --driver %q: use auto, netstack or tun", o.driver)
	}
	if o.mtu != 0 && (o.mtu < psp.DefaultMTU || o.mtu > psp.MaxMTU) {
		return cfg, "", fmt.Errorf("invalid --mtu %d: use 0 or %d to %d", o.mtu, psp.DefaultMTU, psp.MaxMTU)
	}
	cfg.MTU = o.mtu
	for _, r := range o.routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return cfg, "", fmt.Errorf("invalid --route: %w", err)
		}
		cfg.Routes = append(cfg.Routes, p)
	}
	cfg.Labels = o.labels
	if o.relays < 1 || o.relays > 3 {
		return cfg, "", fmt.Errorf("invalid --relays %d: use 1 to 3", o.relays)
	}
	cfg.Sessions = o.relays
	return cfg, driver, nil
}

func runConnect(ctx context.Context, out io.Writer, vpc string, o *connectOptions, cfg agent.Config, driver string) error {
	c, err := apoxyconfig.DefaultAPIClient()
	if err != nil {
		return err
	}
	vc := c.VpcV1alpha1()
	cfg.Identity = identity.NewManager(credentialPath(c.ProjectID, vpc, cfg.Name), func(ctx context.Context) (*identity.Credential, error) {
		return identity.Enroll(ctx, vc.RESTClient(), vpc, cfg.Name)
	})
	// Enroll gives the relays. With a cached cert, the agent starts while the
	// apiserver is down.
	if err := cfg.Identity.Start(ctx); err != nil {
		return fmt.Errorf("failed to enroll in VPC %q: %w", vpc, err)
	}
	var addrs []string
	for _, r := range cfg.Identity.Current().Relays {
		addrs = append(addrs, r.Addresses...)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no ready relay serves VPC %q", vpc)
	}
	uc, err := listenUDP(addrs)
	if err != nil {
		return err
	}
	defer uc.Close()
	tr := &quic.Transport{Conn: uc}
	defer tr.Close()
	cfg.Transport = tr

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	h := &hostDevice{ctx: ctx, fail: cancel, out: out, conn: uc, driver: driver, tunName: o.tunIfname, socksAddr: o.socksAddr, routes: cfg.Routes}
	cfg.OnAttach = h.attach
	cfg.OnRoutes = h.route
	h.agent = agent.New(cfg)
	fmt.Fprintf(out, "Connecting to VPC %q as %q.\n", vpc, cfg.Name)
	if err := h.agent.Run(ctx); err != nil {
		return err
	}
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// listenUDP opens the agent socket in the address family of the relays.
func listenUDP(relays []string) (*net.UDPConn, error) {
	family, err := socketFamily(relays)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP(family, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open the agent socket: %w", err)
	}
	return uc, nil
}

// socketFamily returns udp4 or udp6 when the relays that resolve use one
// address family, and udp, a dual-stack socket, when they use both.
func socketFamily(relays []string) (string, error) {
	var has4, has6 bool
	var errs []error
	for _, r := range relays {
		ra, err := net.ResolveUDPAddr("udp", r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ra.IP.To4() != nil {
			has4 = true
		} else {
			has6 = true
		}
	}
	switch {
	case has4 && has6:
		return "udp", nil
	case has4:
		return "udp4", nil
	case has6:
		return "udp6", nil
	}
	return "", fmt.Errorf("failed to resolve the relays: %w", errors.Join(errs...))
}

// credentialPath is the disk cache of the agent cert.
func credentialPath(project uuid.UUID, vpc, name string) string {
	return filepath.Join(apoxyconfig.ApoxyDir(), "vpc", project.String(), vpc, name+".json")
}

// overlay is a running driver.
type overlay interface {
	// setAddr moves the device from the old overlay address to addr.
	setAddr(old, addr netip.Addr) error
	// route changes the routes of the prefixes of the other attachments.
	route(add, remove []netip.Prefix)
}

// hostDevice starts the driver at the first attach. The agent calls attach
// from one goroutine.
type hostDevice struct {
	ctx       context.Context
	fail      context.CancelCauseFunc
	out       io.Writer
	conn      *net.UDPConn
	driver    string
	tunName   string
	socksAddr string
	routes    []netip.Prefix // Advertised by this host.
	agent     *agent.Agent

	dev  overlay
	addr netip.Addr
}

func (h *hostDevice) attach(b *psp.Binding, addr netip.Addr, _ []netip.Prefix) {
	if h.dev != nil {
		if addr != h.addr {
			if err := h.dev.setAddr(h.addr, addr); err != nil {
				h.fail(fmt.Errorf("failed to set the overlay address %s: %w", addr, err))
				return
			}
			h.addr = addr
		}
		return
	}
	servers, search := h.agent.DNS()
	var err error
	if h.driver == driverTun {
		h.dev, err = startTun(h.ctx, h.fail, b, h.tunName, addr)
	} else {
		h.dev, err = h.startNetstack(b, addr, &network.ResolveConfig{Nameservers: servers, SearchDomains: search})
	}
	if err != nil {
		h.fail(err)
		return
	}
	h.addr = addr
	for _, w := range hostcheck.Check(h.conn, h.driver == driverTun) {
		fmt.Fprintf(h.out, "Warning: %s\n  Fix: %s\n", w.Problem, w.Fix)
	}
	fmt.Fprintf(h.out, "Connected with address %s, %s driver, device MTU %d.\n", addr, h.driver, b.DeviceMTU())
	if h.driver == driverTun && len(servers) > 0 {
		msg := "VPC DNS servers: " + strings.Join(servers, ", ")
		if len(search) > 0 {
			msg += "; search domains: " + strings.Join(search, ", ")
		}
		fmt.Fprintf(h.out, "%s. The tun driver does not change the host resolver.\n", msg)
	}
}

func (h *hostDevice) route(add, remove []netip.Prefix) {
	if h.dev != nil {
		h.dev.route(add, remove)
	}
}

// netstackDev is the user-space network of the netstack driver.
type netstackDev struct {
	ns *netstack.Stack
}

// startNetstack runs the binding on a user-space network. It forwards
// connections from the VPC, and serves SOCKS5 with the VPC DNS config.
func (h *hostDevice) startNetstack(b *psp.Binding, addr netip.Addr, dns *network.ResolveConfig) (overlay, error) {
	var denied []uint16
	if h.socksAddr != "" {
		_, port, err := net.SplitHostPort(h.socksAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid --socks-addr: %w", err)
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid --socks-addr port %q", port)
		}
		denied = []uint16{uint16(p)}
	}
	ns, err := netstack.NewStack(b.DeviceMTU(), "")
	if err != nil {
		return nil, err
	}
	n := &netstackDev{ns: ns}
	if err := n.setAddr(netip.Addr{}, addr); err != nil {
		ns.Close()
		return nil, err
	}
	fwd := &forwardNetwork{Network: network.Loopback(), host: network.Host(), routes: h.routes}
	if err := ns.ForwardTo(h.ctx, network.Filtered(&network.FilteredNetworkConfig{DeniedPorts: denied, Upstream: fwd})); err != nil {
		ns.Close()
		return nil, err
	}
	d, err := b.Netstack(ns.Endpoint)
	if err != nil {
		ns.Close()
		return nil, err
	}
	go func() {
		if err := d.Run(h.ctx); err != nil && h.ctx.Err() == nil {
			h.fail(fmt.Errorf("netstack driver failed: %w", err))
		}
	}()
	if h.socksAddr != "" {
		if len(dns.Nameservers) == 0 {
			dns = nil
		}
		proxy := socksproxy.NewServer(h.socksAddr, ns.Network(dns), network.Host())
		go func() {
			if err := proxy.ListenAndServe(h.ctx); err != nil && h.ctx.Err() == nil {
				h.fail(fmt.Errorf("SOCKS proxy failed: %w", err))
			}
		}()
	}
	return n, nil
}

// forwardNetwork dials the connections from the VPC. Connections to the
// routes that this host advertises go to the host network. Others go to the
// same port on localhost.
type forwardNetwork struct {
	network.Network // Loopback.
	host            network.Network
	routes          []netip.Prefix
}

func (n *forwardNetwork) DialContext(ctx context.Context, nw, addr string) (net.Conn, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil && n.routed(ap.Addr()) {
		return n.host.DialContext(ctx, nw, addr)
	}
	return n.Network.DialContext(ctx, nw, addr)
}

// routed reports whether a route covers addr. Overlay addresses go to localhost.
func (n *forwardNetwork) routed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if tunnet.ULAPrefix().Contains(addr) {
		return false
	}
	return slices.ContainsFunc(n.routes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// route does nothing. The netstack sends all packets to the binding.
func (n *netstackDev) route(_, _ []netip.Prefix) {}

func (n *netstackDev) setAddr(old, addr netip.Addr) error {
	if old.IsValid() {
		if err := n.ns.DelAddr(netip.PrefixFrom(old, old.BitLen())); err != nil {
			return err
		}
	}
	return n.ns.AddAddr(netip.PrefixFrom(addr, addr.BitLen()))
}
