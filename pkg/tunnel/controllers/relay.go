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
	// RemoveCredentials revokes a tunnel's authentication token so new connects to it fail closed.
	RemoveCredentials(tunnelName string)
	// SetEgressGateway enables or disables internet egress for the tunnel agents.
	SetEgressGateway(enabled bool)
	// SetOnConnect sets a callback that is invoked when a new connection is established to the relay.
	SetOnConnect(onConnect func(ctx context.Context, tunnelName, agentName string, conn Connection) error)
	// SetOnDisconnect sets a callback that is invoked when a connection is closed.
	SetOnDisconnect(onDisconnect func(ctx context.Context, agentName, id string) error)
	// DisconnectConnection closes one live connection and runs its cleanup.
	DisconnectConnection(id string)
	// SetOnShutdown sets a callback that is invoked when the relay is shutting down.
	SetOnShutdown(onShutdown func(ctx context.Context))
}
