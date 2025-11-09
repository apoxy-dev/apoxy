package controllers

import (
	"context"
	"io"
	"time"
)

// ConnectionStats is a lightweight snapshot of connection counters.
type ConnectionStats struct {
	// RXBytes is the total number of bytes received on this connection.
	RXBytes uint64
	// TXBytes is the total number of bytes transmitted on this connection.
	TXBytes uint64
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
}
