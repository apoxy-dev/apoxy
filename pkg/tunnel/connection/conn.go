package connection

import (
	"io"
)

// Connection is a simple interface implemented by connect-ip-go and custom
// connection types.
type Connection interface {
	io.Closer

	String() string

	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
}
