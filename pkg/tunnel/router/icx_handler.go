package router

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/apoxy-dev/icx"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// newL3Handler builds the icx handler shared by the packet-conn based routers
// (netstack and tun): layer-3 virt frames, keep-alives, and a local address per
// global unicast address when pc is bound to the unspecified address (the
// handler needs every address a peer might see as the outer source).
func newL3Handler(pc net.PacketConn, sourcePortHashing bool) (*icx.Handler, error) {
	handlerOpts := []icx.HandlerOption{
		icx.WithLayer3VirtFrames(),
		icx.WithKeepAliveInterval(25 * time.Second),
	}
	if sourcePortHashing {
		handlerOpts = append(handlerOpts, icx.WithSourcePortHashing())
	}

	localUDPAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || localUDPAddr == nil {
		return nil, fmt.Errorf("packet conn must be UDP")
	}

	localAddrPort := netip.AddrPortFrom(netip.MustParseAddr(localUDPAddr.IP.String()),
		uint16(localUDPAddr.Port))

	localAddrPorts := []netip.AddrPort{localAddrPort}
	if localAddrPort.Addr().IsUnspecified() {
		localAddrs, err := tunnet.GetAllGlobalUnicastAddresses(true)
		if err != nil {
			return nil, fmt.Errorf("failed to get local addresses: %w", err)
		}

		for _, addr := range localAddrs {
			localAddrPorts = append(localAddrPorts, netip.AddrPortFrom(addr.Addr(), localAddrPort.Port()))
		}
	}

	for _, addr := range localAddrPorts {
		handlerOpts = append(handlerOpts, icx.WithLocalAddr(netstack.ToFullAddress(addr)))
	}

	return icx.NewHandler(handlerOpts...)
}
