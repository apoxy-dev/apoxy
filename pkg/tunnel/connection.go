package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/controllers"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/icx"
)

var _ controllers.Connection = (*connection)(nil)

// connection is a connection like abstraction over an icx virtual network.
// TODO (dpeckett): nuke this at some point and merge the logic into the router.
type connection struct {
	mu sync.Mutex
	id string
	// instance is the relay-local number of this connection. The id is derived
	// from the 4-tuple, so a reconnect from the same address reuses the id of
	// the connection it replaced; the instance is different for each of them
	// and is what tells the two apart. Immutable after construction.
	instance   uint64
	handler    *icx.Handler
	router     router.Router
	localAddr  netip.AddrPort
	remoteAddr netip.AddrPort
	vni        *uint
	// overlayAddr is the primary (IPv6) overlay prefix; extraAddrs are the
	// non-primary programmed prefixes (e.g. the IPv4 /32). Together they are
	// the single source of truth for what the datapath accepts: the VNI's
	// allowed routes and the reported address set (Addresses) are both derived
	// from them, so programmed and reported state cannot diverge.
	overlayAddr *netip.Prefix
	extraAddrs  []netip.Prefix
	keyEpoch    atomic.Uint32
	// master is the connection's PSP master secret, minted once when the
	// connection is constructed and never mutated afterward; every epoch's
	// per-direction data keys derive from it (icx handler-side). It is set before
	// the connection is published to the relay's map, so no reader can observe a
	// zero master.
	master api.MasterSecret
	// network is the VPCNetwork name the credential authorized this connection
	// for (from AuthzResult.Network). Immutable after construction. The relay
	// resolves it to a NetworkID to pick the leased block to allocate from.
	network string
	// scope is the opaque tenant scope the credential resolved to (from
	// AuthzResult.Scope); empty on single-tenant relays. Immutable after
	// construction.
	scope string
	// labels, advertisedRoutes, and agentInstance are the agent-declared
	// connect-request fields, already validated against the credential's
	// bounds. Immutable after construction, like master.
	labels           map[string]string
	advertisedRoutes []netip.Prefix
	agentInstance    string
	// advRoutesProgrammed records whether the advertised routes have been
	// installed on the router, so a VNI change doesn't double-program the
	// kernel routes and Close knows to remove them.
	advRoutesProgrammed bool
	// finalReported becomes true when the last counters of this connection
	// have gone to the final hook. Teardown and the shutdown flush both must
	// win the compare-and-swap before they report, so the hook gets each
	// connection exactly once even when the two paths run at the same time.
	// The registry check alone cannot promise that: both paths can read the
	// registry before either one removes the connection from it.
	finalReported atomic.Bool
}

// programLocked installs p on the router (address + route), rolling the
// address back if the route fails. Callers must hold c.mu.
func (c *connection) programLocked(p netip.Prefix) error {
	if c.router == nil {
		return nil
	}
	if err := c.router.AddAddr(p, nil); err != nil {
		return fmt.Errorf("router.AddAddr(%s) failed: %w", p.String(), err)
	}
	if err := c.router.AddRoute(p); err != nil {
		_ = c.router.DelAddr(p)
		return fmt.Errorf("router.AddRoute(%s) failed: %w", p.String(), err)
	}
	return nil
}

// unprogramLocked removes p from the router, attempting both the address and
// the route even if one fails. Callers must hold c.mu.
func (c *connection) unprogramLocked(p netip.Prefix) error {
	if c.router == nil {
		return nil
	}
	var errs []error
	if err := c.router.DelAddr(p); err != nil {
		errs = append(errs, fmt.Errorf("router.DelAddr(%s) failed: %w", p.String(), err))
	}
	if err := c.router.DelRoute(p); err != nil {
		errs = append(errs, fmt.Errorf("router.DelRoute(%s) failed: %w", p.String(), err))
	}
	return errors.Join(errs...)
}

// Close tears down the VNI and removes any router state. Teardown is
// best-effort: every address and the VNI are attempted even when an earlier
// removal fails and the errors are joined, so a single router hiccup can't
// leak the VNI or the remaining prefixes.
func (c *connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error

	// Remove router addrs first so traffic stops before tearing down the VNI.
	if c.overlayAddr != nil {
		errs = append(errs, c.unprogramLocked(*c.overlayAddr))
	}
	for _, a := range c.extraAddrs {
		errs = append(errs, c.unprogramLocked(a))
	}
	c.overlayAddr = nil
	c.extraAddrs = nil

	errs = append(errs, c.unprogramAdvertisedRoutesLocked())

	if c.vni != nil {
		if err := c.handler.RemoveVirtualNetwork(*c.vni); err != nil {
			errs = append(errs, err)
		}
		c.vni = nil
	}

	return errors.Join(errs...)
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
func (c *connection) SetVNI(ctx context.Context, vni uint) error {
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

	allowedRoutes := c.allowedRoutesLocked()

	fa := netstack.ToFullAddress(c.remoteAddr)

	// If using the netlink router, we need to resolve the MAC address of the peer.
	rtr, ok := c.router.(*router.ICXNetlinkRouter)
	if ok {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		var err error
		fa.LinkAddr, err = rtr.ResolveMAC(ctx, c.remoteAddr)
		if err != nil {
			return fmt.Errorf("failed to resolve peer MAC address: %w", err)
		}
	}

	if err := c.handler.AddVirtualNetwork(vni, fa, allowedRoutes); err != nil {
		return fmt.Errorf("failed to add virtual network %d: %w", vni, err)
	}
	c.vni = &vni

	if c.overlayAddr != nil {
		// Reprogram the primary so a VNI change can't leave stale router state.
		_ = c.unprogramLocked(*c.overlayAddr)
		if err := c.programLocked(*c.overlayAddr); err != nil {
			return err
		}
	}

	// Kernel routes for the advertised CIDRs are VNI-agnostic, so they are
	// installed once and survive a VNI change (the trie entries above were
	// rebuilt with the new VNI already).
	if err := c.programAdvertisedRoutesLocked(); err != nil {
		return err
	}

	return nil
}

// allowedRoutesForDst returns the icx route permitting traffic to dst from any
// source. Relays shouldn't have conflicting destinations, so a wildcard src
// (0.0.0.0/0 or ::/0, matching dst's address family) is safe.
func allowedRoutesForDst(dst netip.Prefix) []icx.Route {
	src := netip.MustParsePrefix("::/0")
	if dst.Addr().Is4() {
		src = netip.MustParsePrefix("0.0.0.0/0")
	}
	return []icx.Route{{Src: src, Dst: dst}}
}

// allowedRoutesLocked builds the VNI's allowed routes from every overlay
// prefix programmed on this connection — the primary (IPv6) address plus any
// extras (the IPv4 /32) — and from the agent's advertised routes (the CIDRs
// reachable behind it). The icx RX check validates the inner source against
// route Dst prefixes per address family, so both families must be present for
// dual-stack traffic to pass, and traffic returning FROM an advertised CIDR
// needs its prefix as a Dst too. The same Dst set feeds the handler's global
// route trie, which is what re-encapsulates transit traffic for those CIDRs
// toward this connection's VNI. Callers must hold c.mu.
func (c *connection) allowedRoutesLocked() []icx.Route {
	var routes []icx.Route
	if c.overlayAddr != nil {
		routes = append(routes, allowedRoutesForDst(*c.overlayAddr)...)
	}
	for _, a := range c.extraAddrs {
		routes = append(routes, allowedRoutesForDst(a)...)
	}
	for _, rt := range c.advertisedRoutes {
		routes = append(routes, allowedRoutesForDst(rt)...)
	}
	return routes
}

// programAdvertisedRoutesLocked installs the advertised CIDRs as router routes
// (kernel routes on the netlink router) so decapped transit traffic for them
// is routed back into the datapath and re-encapsulated toward this VNI. They
// are routes only, never addresses: the relay does not own these prefixes, so
// there is nothing to AddAddr (which would also enroll them in service DNAT).
// Idempotent via the advRoutesProgrammed guard; on failure every route
// installed so far is rolled back. Callers must hold c.mu.
func (c *connection) programAdvertisedRoutesLocked() error {
	if c.advRoutesProgrammed || c.router == nil || len(c.advertisedRoutes) == 0 {
		return nil
	}
	for i, rt := range c.advertisedRoutes {
		if err := c.router.AddRoute(rt); err != nil {
			for _, done := range c.advertisedRoutes[:i] {
				_ = c.router.DelRoute(done)
			}
			return fmt.Errorf("router.AddRoute(%s) failed: %w", rt.String(), err)
		}
	}
	c.advRoutesProgrammed = true
	return nil
}

// unprogramAdvertisedRoutesLocked removes the advertised routes from the
// router, attempting every route even when one fails. Callers must hold c.mu.
func (c *connection) unprogramAdvertisedRoutesLocked() error {
	if !c.advRoutesProgrammed || c.router == nil {
		return nil
	}
	var errs []error
	for _, rt := range c.advertisedRoutes {
		if err := c.router.DelRoute(rt); err != nil {
			errs = append(errs, fmt.Errorf("router.DelRoute(%s) failed: %w", rt.String(), err))
		}
	}
	c.advRoutesProgrammed = false
	return errors.Join(errs...)
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

// SetOverlayAddress sets the primary overlay prefix, programs it on the
// router, and refreshes the VNI's allowed routes. A prefix that was already
// programmed as a non-primary address is promoted in place rather than
// programmed twice, so callers may invoke SetAddresses and SetOverlayAddress
// in either order.
func (c *connection) SetOverlayAddress(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	p, err := netip.ParsePrefix(addr)
	if err != nil {
		return fmt.Errorf("failed to parse overlay address %q: %w", addr, err)
	}

	// No change
	if c.overlayAddr != nil && *c.overlayAddr == p {
		return nil
	}

	old := c.overlayAddr

	// Promote an already-programmed extra instead of double-programming it.
	promoted := false
	if i := slices.Index(c.extraAddrs, p); i >= 0 {
		c.extraAddrs = slices.Delete(c.extraAddrs, i, i+1)
		promoted = true
	} else if err := c.programLocked(p); err != nil {
		return err
	}

	c.overlayAddr = &p

	// If a VNI is active, update its allowed routes in-place.
	if c.vni != nil {
		if err := c.handler.UpdateVirtualNetworkRoutes(*c.vni, c.allowedRoutesLocked()); err != nil {
			// Roll back to the previous state.
			if promoted {
				c.extraAddrs = append(c.extraAddrs, p)
			} else {
				_ = c.unprogramLocked(p)
			}
			c.overlayAddr = old
			return fmt.Errorf("failed to update virtual network %d with address %q: %w", *c.vni, addr, err)
		}
	}

	// Remove the old primary last so there is no gap. On failure the new
	// primary stays live; the leaked old prefix is reported to the caller.
	if old != nil {
		if err := c.unprogramLocked(*old); err != nil {
			return err
		}
	}

	return nil
}

// IncrementKeyEpoch increments and returns the current key epoch for this connection.
func (c *connection) IncrementKeyEpoch() uint32 {
	return c.keyEpoch.Add(1)
}

// Master returns the connection's PSP master secret. It is immutable after
// construction, so no lock is needed.
func (c *connection) Master() api.MasterSecret {
	return c.master
}

// Network returns the VPCNetwork name this connection is bound to. Immutable
// after construction.
func (c *connection) Network() string {
	return c.network
}

// Scope returns the opaque tenant scope the connection's credential resolved
// to (empty on single-tenant relays). Immutable after construction.
func (c *connection) Scope() string {
	return c.scope
}

// Labels returns the agent-declared labels for this connection. Immutable
// after construction.
func (c *connection) Labels() map[string]string {
	return c.labels
}

// AdvertisedRoutes returns the agent-declared routes for this connection,
// already validated against the credential's bounds. Immutable after
// construction.
func (c *connection) AdvertisedRoutes() []netip.Prefix {
	return c.advertisedRoutes
}

// AgentInstance returns the agent's per-process instance UUID, if declared.
// Immutable after construction.
func (c *connection) AgentInstance() string {
	return c.agentInstance
}

// SetAddresses reconciles the connection's programmed overlay address set
// against addrs: prefixes beyond the primary (e.g. the IPv4 /32) are
// programmed onto the router and into the VNI's allowed routes, and prefixes
// that fell out of the set are unprogrammed. Without the extras' allowed
// routes the icx RX check drops every packet in that address family as an
// invalid inner source.
func (c *connection) SetAddresses(addrs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Parse everything up front so a bad input mutates nothing.
	desired := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("failed to parse overlay address %q: %w", a, err)
		}
		if c.overlayAddr == nil || *c.overlayAddr != p {
			desired = append(desired, p)
		}
	}

	var errs []error

	// Unprogram extras that fell out of the set; a prefix whose removal fails
	// stays tracked so Close retries it.
	kept := c.extraAddrs[:0]
	for _, p := range c.extraAddrs {
		if slices.Contains(desired, p) {
			kept = append(kept, p)
			continue
		}
		if err := c.unprogramLocked(p); err != nil {
			errs = append(errs, err)
			kept = append(kept, p)
		}
	}
	c.extraAddrs = kept

	// Program the new ones.
	for _, p := range desired {
		if slices.Contains(c.extraAddrs, p) {
			continue
		}
		if err := c.programLocked(p); err != nil {
			errs = append(errs, err)
			continue
		}
		c.extraAddrs = append(c.extraAddrs, p)
	}

	// If a VNI is active, refresh its allowed routes to match.
	if c.vni != nil {
		if err := c.handler.UpdateVirtualNetworkRoutes(*c.vni, c.allowedRoutesLocked()); err != nil {
			errs = append(errs, fmt.Errorf("failed to update virtual network %d routes: %w", *c.vni, err))
		}
	}

	return errors.Join(errs...)
}

// Addresses returns the programmed overlay address set (primary first), or
// nil if nothing is programmed. It is derived from programmed state, so the
// reported set can never diverge from what the datapath accepts.
func (c *connection) Addresses() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []string
	if c.overlayAddr != nil {
		out = append(out, c.overlayAddr.String())
	}
	for _, a := range c.extraAddrs {
		out = append(out, a.String())
	}
	return out
}

// Stats returns a snapshot built from the currently configured VNI (if any).
func (c *connection) Stats() (controllers.ConnectionStats, bool) {
	c.mu.Lock()

	if c.vni == nil || c.handler == nil {
		c.mu.Unlock()
		return controllers.ConnectionStats{}, false
	}
	c.mu.Unlock()

	vnet, ok := c.handler.GetVirtualNetwork(*c.vni)
	if !ok || vnet == nil {
		return controllers.ConnectionStats{}, false
	}

	var lastRx time.Time
	nano := vnet.Stats.LastRXUnixNano.Load()
	if nano > 0 {
		lastRx = time.Unix(0, nano)
	}

	return controllers.ConnectionStats{
		RXBytes: int64(vnet.Stats.RXBytes.Load()),
		TXBytes: int64(vnet.Stats.TXBytes.Load()),
		LastRX:  lastRx,
	}, true
}

// datapathStats returns the connection's identity together with the packet,
// byte, drop, and keep-alive counters of its virtual network. It reports false
// when the connection has no virtual network yet, or the handler no longer
// holds it, because then there is nothing to count.
func (c *connection) datapathStats() (ConnStats, bool) {
	c.mu.Lock()
	vni := c.vni
	handler := c.handler
	c.mu.Unlock()

	if vni == nil || handler == nil {
		return ConnStats{}, false
	}

	vnet, ok := handler.GetVirtualNetwork(*vni)
	if !ok || vnet == nil {
		return ConnStats{}, false
	}

	// Identity fields are immutable after construction, so they need no lock.
	return ConnStats{
		ID:            c.id,
		Instance:      c.instance,
		Network:       c.network,
		ProjectID:     c.scope,
		AgentInstance: c.agentInstance,
		RXBytes:       vnet.Stats.RXBytes.Load(),
		TXBytes:       vnet.Stats.TXBytes.Load(),
		RXPackets:     vnet.Stats.RXPackets.Load(),
		TXPackets:     vnet.Stats.TXPackets.Load(),
		RXDrops:       rxDrops(&vnet.Stats),
		TXDrops:       txDrops(&vnet.Stats),
		RXKeepAlives:  vnet.Stats.RXKeepAlives.Load(),
		TXKeepAlives:  vnet.Stats.TXKeepAlives.Load(),
	}, true
}

// rxDrops folds every receive-side drop reason into one count: a packet the
// datapath refused is a drop whether it failed the key check, the replay
// check, decryption, the rate limit, or the address checks. Each counter is
// read once, so the total is a snapshot of counters that move on their own.
func rxDrops(s *icx.Statistics) uint64 {
	return s.RXDropsNoKey.Load() +
		s.RXDropsExpiredKey.Load() +
		s.RXDropsSPIMismatch.Load() +
		s.RXDropsBadPeer.Load() +
		s.RXDecryptErrors.Load() +
		s.RXReplayDrops.Load() +
		s.RXRateLimitDrops.Load() +
		s.RXInvalidSrc.Load() +
		s.RXInvalidDst.Load()
}

// txDrops folds every transmit-side drop and error into one count: a frame the
// datapath could not send is lost whether the key had expired, the remote
// endpoint was unknown, or the write itself failed.
func txDrops(s *icx.Statistics) uint64 {
	return s.TXDropsExpiredKey.Load() +
		s.TXDropsNoRemote.Load() +
		s.TXErrors.Load()
}
