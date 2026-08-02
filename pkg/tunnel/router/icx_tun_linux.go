package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	icxtun "github.com/apoxy-dev/icx/vtep/tun"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"

	apoxynetns "github.com/apoxy-dev/apoxy/pkg/netns"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"

	"github.com/apoxy-dev/icx"
)

// icxTunDeviceOffset is the read/write headroom the wireguard TUN device
// requires: CreateTUN opens the device with IFF_VNET_HDR, so writes must leave
// room for the virtio-net header. 16 matches wireguard's
// device.MessageTransportHeaderSize and the icx tun driver's own Open path.
const icxTunDeviceOffset = 16

var _ Router = (*ICXTunRouter)(nil)

// ICXTunRouter is the kernel-device agent datapath: it splices a /dev/net/tun
// device to the shared icx handler over the agent's existing Geneve packet
// conn, so any kernel-socket process in the same netns (e.g. the backplane's
// Envoy) reaches overlay destinations by plain kernel route. It is the VTEP
// counterpart of ICXNetstackRouter, which confines the overlay to an
// in-process netstack behind a SOCKS listener.
//
// The Geneve side stays on the caller-provided packet conn (the bifurcated
// socket shared with the QUIC control plane) rather than the icx driver's own
// socket: the relay transmits Geneve to the same 5-tuple it accepted the
// control session from, so data and control must share one socket.
// Requires NET_ADMIN and access to /dev/net/tun.
type ICXTunRouter struct {
	Handler *icx.Handler

	dp   *icxtun.Datapath
	link netlink.Link
	// nl scopes all address/route programming to the TUN's netns. It is the
	// namespace-bound handle when WithTunnelNetns is set, else a root-ns handle.
	nl *netlink.Handle
	// ns is the TUN's network namespace handle; None when in the root netns.
	ns        netns.NsHandle
	closeOnce sync.Once
	closeErr  error
}

// l2Underlay adapts the shared Geneve L2PacketConn to the icx tun driver's
// Underlay contract. Both sides speak full Ethernet+IP+UDP+Geneve phy frames;
// l2pc peels the outer headers onto the UDP socket on write and synthesizes
// them (outer source = real received peer, which is what source learning
// adopts) on read.
type l2Underlay struct {
	phy *l2pc.L2PacketConn
	// msgs is reused across WriteFrames calls (single writer: the datapath's
	// TX pump) to avoid a per-batch allocation.
	msgs []batchpc.Message
}

var _ icxtun.Underlay = (*l2Underlay)(nil)

func (u *l2Underlay) ReadFrame(buf []byte) (int, error) {
	return u.phy.ReadFrame(buf)
}

func (u *l2Underlay) WriteFrames(frames [][]byte) (int, error) {
	if cap(u.msgs) < len(frames) {
		u.msgs = make([]batchpc.Message, len(frames))
	}
	msgs := u.msgs[:len(frames)]
	for i, f := range frames {
		msgs[i].Buf = f
	}
	return u.phy.WriteBatchFrames(msgs, 0)
}

func (u *l2Underlay) Close() error {
	return u.phy.Close()
}

// NewICXTunRouter creates the TUN router: a fresh icx handler in layer-3 mode,
// a kernel TUN device named by WithTunnelInterface, and the icx tun datapath
// splicing them across the WithPacketConn socket. The device is created up
// with the tunnel MTU but carries no addresses or routes until AddAddr /
// AddRoute program them.
func NewICXTunRouter(opts ...Option) (*ICXTunRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	if options.pc == nil {
		return nil, fmt.Errorf("packet conn is required for ICX tun router")
	}

	phy, err := l2pc.NewL2PacketConn(options.pc)
	if err != nil {
		return nil, fmt.Errorf("failed to create L2 packet connection phy: %w", err)
	}

	handler, err := newL3Handler(options.pc, options.sourcePortHashing)
	if err != nil {
		_ = phy.Close()
		return nil, fmt.Errorf("failed to create ICX handler: %w", err)
	}

	// Resolve the TUN's network namespace and a netlink handle scoped to it.
	// The underlay packet conn was created before this point and keeps its
	// original namespace regardless of where the TUN lands.
	ns := netns.None()
	var nl *netlink.Handle
	if options.tunNetnsName != "" {
		ns, err = apoxynetns.EnsureNamed(options.tunNetnsName)
		if err != nil {
			_ = phy.Close()
			return nil, err
		}
		nl, err = netlink.NewHandleAt(ns)
	} else {
		nl, err = netlink.NewHandle()
	}
	if err != nil {
		_ = phy.Close()
		return nil, fmt.Errorf("failed to create netlink handle: %w", err)
	}

	var dev wgtun.Device
	if err := apoxynetns.Do(ns, func() error {
		var terr error
		dev, terr = createTunDevice(options.tunIfaceName, options.tunMTU)
		return terr
	}); err != nil {
		_ = phy.Close()
		return nil, err
	}

	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		_ = phy.Close()
		return nil, fmt.Errorf("failed to get TUN device name: %w", err)
	}

	link, err := nl.LinkByName(name)
	if err != nil {
		_ = dev.Close()
		_ = phy.Close()
		return nil, fmt.Errorf("failed to find TUN link %q: %w", name, err)
	}
	if err := nl.LinkSetMTU(link, options.tunMTU); err != nil {
		_ = dev.Close()
		_ = phy.Close()
		return nil, fmt.Errorf("failed to set MTU on %q: %w", name, err)
	}
	if err := nl.LinkSetUp(link); err != nil {
		_ = dev.Close()
		_ = phy.Close()
		return nil, fmt.Errorf("failed to bring up %q: %w", name, err)
	}
	// A freshly created namespace has loopback down; bring it up so sockets
	// created in the namespace (e.g. Envoy upstream binds) behave normally.
	if ns.IsOpen() {
		if lo, lerr := nl.LinkByName("lo"); lerr == nil {
			if lerr := nl.LinkSetUp(lo); lerr != nil {
				slog.Warn("Failed to bring up loopback in TUN netns", slog.Any("error", lerr))
			}
		}
	}

	dp, err := icxtun.New(icxtun.Config{
		Engine:       handler,
		Device:       dev,
		Underlay:     &l2Underlay{phy: phy},
		DeviceOffset: icxTunDeviceOffset,
		InnerMTU:     options.tunMTU,
	})
	if err != nil {
		_ = dev.Close()
		_ = phy.Close()
		return nil, fmt.Errorf("failed to create tun datapath: %w", err)
	}

	slog.Info("Created TUN overlay device",
		slog.String("name", name),
		slog.Int("mtu", options.tunMTU),
		slog.String("netns", options.tunNetnsName))

	return &ICXTunRouter{
		Handler: handler,
		dp:      dp,
		link:    link,
		nl:      nl,
		ns:      ns,
	}, nil
}

// createTunDevice opens a TUN device in the calling thread's current network
// namespace and disables kernel GSO/GRO offload so each device read returns a
// single <= MTU packet the icx encap buffers are sized for, mirroring the icx
// tun driver's own Open path.
func createTunDevice(name string, mtu int) (wgtun.Device, error) {
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device %q: %w", name, err)
	}
	f := dev.File()
	if f == nil {
		_ = dev.Close()
		return nil, fmt.Errorf("TUN device exposes no file descriptor; cannot disable offload")
	}
	if err := unix.IoctlSetInt(int(f.Fd()), unix.TUNSETOFFLOAD, 0); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("failed to disable TUN offload: %w", err)
	}
	return dev, nil
}

// Start runs the datapath pumps. It blocks until ctx is canceled or the
// datapath fails.
func (r *ICXTunRouter) Start(ctx context.Context) error {
	return r.dp.Run(ctx)
}

// Close stops the datapath and releases the TUN device and the underlying
// packet conn (via the datapath, which owns both), plus the netlink and netns
// handles. The named netns itself is left in place: Envoy holds sockets in it
// and a reconnecting session reuses it.
func (r *ICXTunRouter) Close() error {
	r.closeOnce.Do(func() {
		r.closeErr = r.dp.Close()
		r.nl.Close()
		if r.ns.IsOpen() {
			_ = r.ns.Close()
		}
	})
	return r.closeErr
}

// AddAddr assigns an overlay prefix to the TUN device. The kernel installs the
// connected route for the prefix, so anything in the same netns can route to
// the overlay immediately.
func (r *ICXTunRouter) AddAddr(addr netip.Prefix, _ connection.Connection) error {
	if err := r.nl.AddrReplace(r.link, nlAddr(addr)); err != nil {
		return fmt.Errorf("failed to add address %s to %q: %w", addr, r.link.Attrs().Name, err)
	}
	return nil
}

// DelAddr removes an overlay prefix from the TUN device.
func (r *ICXTunRouter) DelAddr(addr netip.Prefix) error {
	if err := r.nl.AddrDel(r.link, nlAddr(addr)); err != nil {
		return fmt.Errorf("failed to remove address %s from %q: %w", addr, r.link.Attrs().Name, err)
	}
	return nil
}

// AddRoute routes an overlay prefix out the TUN device (link scope). Replace
// semantics keep it idempotent against the kernel's own connected routes.
func (r *ICXTunRouter) AddRoute(dst netip.Prefix) error {
	if err := r.nl.RouteReplace(r.nlRoute(dst)); err != nil {
		return fmt.Errorf("failed to add route %s via %q: %w", dst, r.link.Attrs().Name, err)
	}
	return nil
}

// AddRouteSrc routes an overlay prefix out the TUN device with src as the
// route's preferred source address.
//
// The device carries one address per relay the agent is connected to, and the
// kernel would otherwise choose among them by longest matching prefix — which
// tracks the connection index, not the relay, so it routinely picks an address
// leased by a relay other than the one this prefix egresses to. Relays do not
// federate, so such a packet is dropped. Pinning the source takes the choice
// away from the kernel.
func (r *ICXTunRouter) AddRouteSrc(dst netip.Prefix, src netip.Addr) error {
	route := r.nlRoute(dst)
	route.Src = src.AsSlice()
	if err := r.nl.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to add route %s src %s via %q: %w",
			dst, src, r.link.Attrs().Name, err)
	}
	return nil
}

// DelRoute removes an overlay prefix route from the TUN device.
func (r *ICXTunRouter) DelRoute(dst netip.Prefix) error {
	if err := r.nl.RouteDel(r.nlRoute(dst)); err != nil {
		return fmt.Errorf("failed to remove route %s via %q: %w", dst, r.link.Attrs().Name, err)
	}
	return nil
}

func (r *ICXTunRouter) nlRoute(dst netip.Prefix) *netlink.Route {
	m := dst.Masked()
	return &netlink.Route{
		LinkIndex: r.link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   m.Addr().AsSlice(),
			Mask: net.CIDRMask(m.Bits(), m.Addr().BitLen()),
		},
		Scope: netlink.SCOPE_LINK,
	}
}

// nlAddr converts a prefix to a netlink address, keeping the host bits (an
// interface address is 10.0.0.5/24, not 10.0.0.0/24).
func nlAddr(p netip.Prefix) *netlink.Addr {
	a := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   p.Addr().AsSlice(),
			Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
		},
	}
	// Skip DAD on v6: the TUN is a point-to-point overlay whose addresses are
	// leased by a single allocator, so there is no peer to duplicate against.
	// With DAD on, a freshly added address sits tentative for ~1s and a
	// source-pinned route added against it fails EINVAL — which is exactly
	// the reconnect path, where the relay may hand the session a different
	// address than the one it held before.
	if p.Addr().Is6() {
		a.Flags = unix.IFA_F_NODAD
	}
	return a
}
