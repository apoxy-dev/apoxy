// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/quic-go/quic-go"
)

// DatagramConn is the part of a QUIC connection of A that FRAME in and FRAME out use. Its
// TrySendDatagram is the frame writer of the port: SetFrameWriter(port, c.TrySendDatagram).
type DatagramConn interface {
	// ReceiveDatagram returns the next datagram. It fails when the connection ends.
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	// TrySendDatagram sends a datagram and never waits. An error means that the datagram was
	// not queued, and the pipeline drops the frame (datagram_full).
	TrySendDatagram(b []byte) error
}

// ReadFrames is the frame reader of a QUIC connection of A: it gives each datagram of c to t as
// FRAME in of port and session. It returns when c ends or ctx is done.
func ReadFrames(ctx context.Context, t Target, c DatagramConn, port, session uint64) error {
	po := &p4.PacketOut{Metadata: PacketOutMeta{Kind: KindFrame, Port: port, Session: session}.Metadata()}
	for {
		b, err := c.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}
		po.Payload = b
		err = t.PacketOut(po)
		quic.ReleaseDatagram(b)
		if err != nil {
			return err
		}
	}
}

var _ DatagramConn = (*quic.Conn)(nil)
