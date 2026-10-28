// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"context"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/quic-go/quic-go"
)

// datagramBatch is the most datagrams in one read of a connection of A: the size of one quicTurn.
const datagramBatch = 64

// DatagramConn is the part of a QUIC connection of A that DATAGRAM in and DATAGRAM out use. Its
// TrySendDatagram is the datagram writer of the port: SetDatagramWriter(port, c.TrySendDatagram).
type DatagramConn interface {
	// ReceiveDatagrams puts up to len(bufs) datagrams in bufs and returns their number. It
	// fails when the connection ends, and then returns no datagram.
	ReceiveDatagrams(ctx context.Context, bufs [][]byte) (int, error)
	// TrySendDatagram sends a datagram and never waits. An error means that the datagram was
	// not queued, and the pipeline drops the datagram (datagram_full).
	TrySendDatagram(b []byte) error
}

// ReadDatagrams gives each datagram of c to t as DATAGRAM in of port and session, and releases it.
// It returns when c ends, ctx is done, or PacketOut fails.
func ReadDatagrams(ctx context.Context, t Target, c DatagramConn, port, session uint64) error {
	po := &p4.PacketOut{Metadata: PacketOutMeta{Kind: KindDatagram, Port: port, Session: session}.Metadata()}
	var bufs [datagramBatch][]byte
	for {
		n, err := c.ReceiveDatagrams(ctx, bufs[:])
		if err != nil {
			return err
		}
		for i, b := range bufs[:n] {
			if err == nil {
				po.Payload = b
				err = t.PacketOut(po)
			}
			quic.ReleaseDatagram(b)
			bufs[i] = nil
		}
		if err != nil {
			return err
		}
	}
}

var _ DatagramConn = (*quic.Conn)(nil)
