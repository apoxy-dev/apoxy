package controllers

import "net/netip"

// Relay is a simple abstraction representing a relay server that TunnelAgents connect to.
type Relay interface {
	// Name is the name of the relay.
	Name() string
	// Address is the address of the relay.
	Address() netip.AddrPort
	// SetCredentials sets the authentication token used by agents to authenticate with the relay.
	SetCredentials(tunnelName, token string)
}
