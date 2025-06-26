package connection

import (
	"io"
	"net/netip"
)

// Connection is a simple interface implemented by connect-ip-go and custom
// connection types.
type Connection interface {
	io.Closer

	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
}

// LocalAddressProvider is an optional interface that connections can implement
// to provide their local addresses for use as gateways in default routes.
type LocalAddressProvider interface {
	LocalAddresses() ([]netip.Prefix, error)
}
