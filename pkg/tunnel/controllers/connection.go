package controllers

import (
	"context"
	"io"
	"net/netip"
	"time"
)

// ConnectionStats is a lightweight snapshot of connection counters.
type ConnectionStats struct {
	// RXBytes is the total number of bytes received on this connection.
	RXBytes int64
	// TXBytes is the total number of bytes transmitted on this connection.
	TXBytes int64
	// LastRX is the last time a packet was received on this connection.
	// The zero value indicates that no packets have been received.
	LastRX time.Time
}

// Connection is a simple abstraction representing a connection from a TunnelAgent to a Relay.
type Connection interface {
	io.Closer
	// ID is the unique identifier of the connection.
	ID() string
	// Set the overlay address/prefix assigned to this connection.
	SetOverlayAddress(addr string) error
	// Set the VNI assigned to this connection.
	SetVNI(ctx context.Context, vni uint) error
	// Stats returns a snapshot of connection statistics.
	Stats() (ConnectionStats, bool)
	// Network is the name of the VPCNetwork this connection is bound to (the
	// credential-authorized network, resolved by the relay at connect).
	Network() string
	// Scope is the opaque tenant scope the connection's credential resolved to
	// (AuthzResult.Scope); empty on single-tenant relays. Multi-tenant relay
	// operators use it to route per-connection callbacks to the right tenant.
	Scope() string
	// Labels are the agent-declared labels, already validated against the
	// credential's bounds. VPCService selectors match on these.
	Labels() map[string]string
	// AdvertisedRoutes are the agent-declared prefixes reachable behind this
	// connection, already validated against the credential's bounds.
	AdvertisedRoutes() []netip.Prefix
	// AgentInstance is the agent process's stable instance UUID, if declared.
	AgentInstance() string
	// SetAddresses reconciles the connection's programmed overlay address set
	// (an IPv6 /96 plus a best-effort IPv4 /32) against addrs: non-primary
	// prefixes are programmed onto the router and into the VNI's allowed
	// routes, and prefixes that fell out of the set are unprogrammed
	// (SetOverlayAddress covers the primary IPv6 address).
	SetAddresses(addrs []string) error
	// Addresses returns the programmed dual-stack overlay address set (primary
	// first), or nil if nothing is programmed. It is the set surfaced in the
	// connect response and the Tunnel object.
	Addresses() []string
}
