package adapter

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/icx"
)

// Connection is a connection like abstraction over an icx virtual network.
type Connection struct {
	mu          sync.Mutex
	id          string
	handler     *icx.Handler
	localAddr   netip.AddrPort
	remoteAddr  netip.AddrPort
	vni         *uint
	overlayAddr *netip.Prefix
	keyEpoch    atomic.Uint32
}

// NewConnection creates a new Connection instance.
func NewConnection(id string, handler *icx.Handler, localAddr, remoteAddr netip.AddrPort) *Connection {
	return &Connection{
		id:         id,
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

func (c *Connection) ID() string {
	return c.id
}

func (c *Connection) VNI() *uint {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.vni
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

	if err := c.handler.AddVirtualNetwork(vni, netstack.ToFullAddress(c.remoteAddr), addrs); err != nil {
		return fmt.Errorf("failed to add virtual network %d: %w", vni, err)
	}
	c.vni = &vni

	return nil
}

// OverlayAddress returns the overlay address/cidr assigned to this connection.
func (c *Connection) OverlayAddress() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.overlayAddr != nil {
		return c.overlayAddr.String()
	}
	return ""
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

// IncrementKeyEpoch increments and returns the current key epoch for this connection.
func (c *Connection) IncrementKeyEpoch() uint32 {
	return c.keyEpoch.Add(1)
}
