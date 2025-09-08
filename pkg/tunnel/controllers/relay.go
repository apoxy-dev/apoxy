package controllers

import (
	"context"
	"net/netip"
)

// Relay is a simple abstraction representing a relay server that TunnelAgents connect to.
type Relay interface {
	// Name is the name of the relay.
	Name() string
	// Address is the underlay address of the relay.
	Address() netip.AddrPort
	// SetCredentials sets the authentication token used by agents to authenticate with the relay.
	SetCredentials(tunnelName, token string)
	// SetOnConnect sets a callback that is invoked when a new connection is established to the relay.
	SetOnConnect(onConnect func(ctx context.Context, agentName string, conn Connection) error)
	// SetOnDisconnect sets a callback that is invoked when a connection is closed.
	SetOnDisconnect(onDisconnect func(ctx context.Context, agentName, id string) error)
}
