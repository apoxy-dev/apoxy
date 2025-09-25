package router

import (
	"context"
	"io"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

type TunnelRouteState int

const (
	TunnelRouteStateActive TunnelRouteState = iota
	TunnelRouteStateDraining
)

type TunnelRoute struct {
	Dst   netip.Prefix
	TunID string
	State TunnelRouteState
}

// Router is an interface for managing tunnel routing.
type Router interface {
	io.Closer

	// Start initializes the router and starts forwarding traffic.
	// It's a blocking call that should be run in a separate goroutine.
	Start(ctx context.Context) error

	// AddAddr adds a tun with an associated address to the router.
	AddAddr(addr netip.Prefix, tun connection.Connection) error

	// DelAddr removes a tun by its addr from the router.
	DelAddr(addr netip.Prefix) error

	// AddRoute adds a dst prefix to be routed through the given tunnel connection.
	// If multiple tunnels are provided, the router will distribute traffic across them
	// uniformly.
	AddRoute(dst netip.Prefix) error

	// Del removes a routing associations for a given destination prefix and Connection name.
	// New matching flows will stop being routed through the tunnel immediately while
	// existing flows may continue to use the tunnel for some draining period before
	// getting re-routed via a different tunnel or dropped (if no tunnel is available for
	// the given dst).
	DelRoute(dst netip.Prefix) error
}
