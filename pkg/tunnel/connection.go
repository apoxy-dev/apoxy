package tunnel

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/icx"
)

var _ controllers.Connection = (*connection)(nil)

// connection is a connection like abstraction over an icx virtual network.
type connection struct {
	mu          sync.Mutex
	id          string
	handler     *icx.Handler
	router      router.Router
	localAddr   netip.AddrPort
	remoteAddr  netip.AddrPort
	vni         *uint
	overlayAddr *netip.Prefix
	keyEpoch    atomic.Uint32
}

// Close tears down the VNI and removes any router state.
func (c *connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove router addr first so traffic stops before tearing down the VNI.
	if c.overlayAddr != nil && c.router != nil {
		if err := c.router.DelAddr(*c.overlayAddr); err != nil {
			return fmt.Errorf("failed to remove router addr %q: %w", c.overlayAddr.String(), err)
		}
		if err := c.router.DelRoute(*c.overlayAddr); err != nil {
			return fmt.Errorf("failed to remove router route %q: %w", c.overlayAddr.String(), err)
		}
	}

	if c.vni != nil {
		if err := c.handler.RemoveVirtualNetwork(*c.vni); err != nil {
			return err
		}
		c.vni = nil
		c.overlayAddr = nil
	}

	return nil
}

func (c *connection) ID() string {
	return c.id
}

func (c *connection) VNI() *uint {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.vni
}

// Set the VNI assigned to this connection.
func (c *connection) SetVNI(vni uint) error {
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
func (c *connection) OverlayAddress() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.overlayAddr != nil {
		return c.overlayAddr.String()
	}
	return ""
}

// SetOverlayAddress sets the overlay address/cidr and updates router + VNI.
func (c *connection) SetOverlayAddress(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	p, err := netip.ParsePrefix(addr)
	if err != nil {
		return fmt.Errorf("failed to parse overlay address %q: %w", addr, err)
	}

	// No change
	if c.overlayAddr != nil && c.overlayAddr.String() == p.String() {
		return nil
	}

	// Keep the old value for router rollback if needed.
	var old *netip.Prefix
	if c.overlayAddr != nil {
		tmp := *c.overlayAddr
		old = &tmp
	}

	// Program router: add new, then delete old (to avoid a gap).
	if c.router != nil {
		if err := c.router.AddAddr(p, nil); err != nil {
			return fmt.Errorf("router.AddAddr(%s) failed: %w", p.String(), err)
		}
		if err := c.router.AddRoute(p); err != nil {
			// Try to roll back: remove the new addr to avoid duplicates.
			_ = c.router.DelAddr(p)
			_ = c.router.DelRoute(p)
			return fmt.Errorf("router.AddRoute(%s) failed: %w", p.String(), err)
		}
		if old != nil {
			if err := c.router.DelAddr(*old); err != nil {
				// Try to roll back: remove the new addr to avoid duplicates.
				_ = c.router.DelAddr(p)
				return fmt.Errorf("router.DelAddr(%s) failed: %w", old.String(), err)
			}
			if err := c.router.DelRoute(*old); err != nil {
				return fmt.Errorf("router.DelRoute(%s) failed: %w", old.String(), err)
			}
		}
	}

	// Update in-memory state.
	c.overlayAddr = &p

	// 2) If a VNI is active, update its allowed prefixes in-place.
	if c.vni != nil {
		if err := c.handler.UpdateVirtualNetworkAddrs(*c.vni, []netip.Prefix{p}); err != nil {
			// Attempt to roll back router state to old addr on failure.
			if c.router != nil {
				_ = c.router.DelAddr(p)
				_ = c.router.DelRoute(p)
				if old != nil {
					_ = c.router.AddAddr(*old, nil)
					_ = c.router.AddRoute(*old)
				}
			}
			// Restore in-memory value.
			c.overlayAddr = old
			if old == nil {
				// If there was no old addr, also clear it.
				c.overlayAddr = nil
			}
			return fmt.Errorf("failed to update virtual network %d with address %q: %w", *c.vni, addr, err)
		}
	}

	return nil
}

// IncrementKeyEpoch increments and returns the current key epoch for this connection.
func (c *connection) IncrementKeyEpoch() uint32 {
	return c.keyEpoch.Add(1)
}
