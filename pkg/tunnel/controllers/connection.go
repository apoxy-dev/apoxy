package controllers

import "io"

// Connection is a simple abstraction representing a connection from a TunnelAgent to a Relay.
type Connection interface {
	io.Closer
	// ID is the unique identifier of the connection.
	ID() string
	// Set the overlay address/cidr assigned to this connection.
	SetAddress(addr string)
	// Set the VNI assigned to this connection.
	SetVNI(vni uint32)
}
