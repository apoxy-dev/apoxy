package controllers

import (
	"io"
	"net/netip"
)

// Connection is a simple abstraction representing a connection from a TunnelAgent to a Relay.
type Connection interface {
	io.Closer
	// ID is the unique identifier of the connection.
	ID() string
	// Address is the address of the agent assigned to this connection.
	Address() netip.Prefix
	// VNI is the virtual network identifier assigned to this connection.
	VNI() uint32
}
