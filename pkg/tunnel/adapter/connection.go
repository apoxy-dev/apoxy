package adapter

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/icx"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Connection is a connection like abstraction over an icx virtual network.
type Connection struct {
	mu          sync.Mutex
	handler     *icx.Handler
	localAddr   *netip.AddrPort
	remoteAddr  *netip.AddrPort
	vni         *uint
	overlayAddr *netip.Prefix
}

// NewConnection creates a new Connection instance.
func NewConnection(handler *icx.Handler, localAddr, remoteAddr *netip.AddrPort) *Connection {
	return &Connection{
		handler:    handler,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.vni != nil {
		if err := c.handler.RemoveVirtualNetwork(*c.vni); err != nil {
			return err
		}
		c.vni = nil
		c.overlayAddr = nil
	}
	return nil
}

// ID is the unique identifier of the connection.
func (c *Connection) ID() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	encode := func(ap *netip.AddrPort) []byte {
		if ap == nil {
			return []byte{0} // marker for nil
		}
		var b []byte
		addr := ap.Addr()
		if addr.Is4() {
			b = append(b, 4) // family marker
			a := addr.As4()
			b = append(b, a[:]...)
		} else {
			b = append(b, 6) // family marker
			a := addr.As16()
			b = append(b, a[:]...)
		}
		p := ap.Port()
		b = append(b, byte(p>>8), byte(p)) // big-endian port
		return b
	}

	left := encode(c.localAddr)
	right := encode(c.remoteAddr)

	// Sort the pair to make the ID bidirectional
	var data []byte
	if string(left) < string(right) {
		data = append(left, right...)
	} else {
		data = append(right, left...)
	}

	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:16])
}

// Set the VNI assigned to this connection.
func (c *Connection) SetVNI(vni uint) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// No change
	if c.vni != nil && *c.vni == vni {
		return nil
	}

	// Remove existing VNI if set
	if c.vni != nil {
		if err := c.handler.RemoveVirtualNetwork(*c.vni); err != nil {
			return err
		}
		c.vni = nil
	}

	// Add new VNI
	var addrs []netip.Prefix
	if c.overlayAddr != nil {
		addrs = []netip.Prefix{*c.overlayAddr}
	}

	if err := c.handler.AddVirtualNetwork(vni, toFullAddress(c.remoteAddr), addrs); err != nil {
		return fmt.Errorf("failed to add virtual network %d: %w", vni, err)
	}
	c.vni = &vni

	return nil
}

// Set the overlay address/cidr assigned to this connection.
func (c *Connection) SetOverlayAddress(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	p, err := netip.ParsePrefix(addr)
	if err != nil {
		return fmt.Errorf("failed to parse overlay address %q: %w", addr, err)
	}

	// No change
	if c.overlayAddr != nil && (*c.overlayAddr).String() == p.String() {
		return nil
	}
	c.overlayAddr = &p

	// If a VNI is active, update its allowed prefixes in-place.
	if c.vni != nil {
		if err := c.handler.UpdateVirtualNetworkAddrs(*c.vni, []netip.Prefix{p}); err != nil {
			return fmt.Errorf("failed to update virtual network %d with address %q: %w", *c.vni, addr, err)
		}
	}

	return nil
}

func toFullAddress(addrPort *netip.AddrPort) *tcpip.FullAddress {
	if addrPort == nil {
		return nil
	}

	if addrPort.Addr().Is4() {
		addrv4 := addrPort.Addr().As4()
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addrv4[:]),
			Port: uint16(addrPort.Port()),
		}
	} else {
		addrv6 := addrPort.Addr().As16()
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addrv6[:]),
			Port: uint16(addrPort.Port()),
		}
	}
}
