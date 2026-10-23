// SPDX-License-Identifier: AGPL-3.0-only

// Package peerconn has the frames of the QUIC datagrams on agent sessions. Conn carries the
// data frames on the session connection of a relay session.
package peerconn

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// recvBatch is the most datagrams in one read of the session connection. A read fills one set
// of the receive pipe at most.
const recvBatch = 64

// QUICConn is the part of a QUIC connection that Conn uses.
type QUICConn interface {
	SendDatagram([]byte) error
	ReceiveDatagrams(ctx context.Context, bufs [][]byte) (int, error)
}

var _ QUICConn = (*quic.Conn)(nil)

// DataHandler takes the data frames of the relay session. It runs on the reader of the session
// connection, so one goroutine calls it.
type DataHandler interface {
	// HandleData takes one data frame. The frame is valid only until it returns. It can wait
	// for the receive pipe or the read batch, as a read loop of a socket does.
	HandleData(frame []byte)
	// BatchEnd runs after the last frame of one read.
	BatchEnd()
}

// Conn sends data frames on the session connection of a relay session, and
// gives the received data frames to its handler.
type Conn struct {
	qc     QUICConn
	stop   context.CancelFunc // Stops the reader of the session connection.
	closed atomic.Bool

	data atomic.Pointer[DataHandler]

	otherDrops atomic.Uint64
}

// Stats counts dropped frames.
type Stats struct {
	// OtherDrops are frames that are not data frames, or that no handler took.
	OtherDrops uint64
}

// New returns a Conn on the relay session qc, and starts the reader of qc.
// qc must have datagrams on.
func New(qc QUICConn) *Conn {
	ctx, stop := context.WithCancel(context.Background())
	c := &Conn{qc: qc, stop: stop}
	go c.receive(ctx)
	return c
}

// SendData sends a data frame on the session connection. SendDatagram copies
// the frame.
func (c *Conn) SendData(frame []byte) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.qc.SendDatagram(frame)
}

// HandleData gives the data frames of the relay session to h, and nil stops it.
func (c *Conn) HandleData(h DataHandler) {
	if h == nil {
		c.data.Store(nil)
		return
	}
	c.data.Store(&h)
}

// receive gives the data frames of each read to the data handler, then calls BatchEnd, until ctx
// ends or the connection closes. It drops and counts the other frames.
func (c *Conn) receive(ctx context.Context) {
	var bufs [recvBatch][]byte
	for {
		n, err := c.qc.ReceiveDatagrams(ctx, bufs[:])
		if err != nil {
			return
		}
		h := c.data.Load()
		for _, b := range bufs[:n] {
			if h != nil && len(b) > 0 && b[0] == TypeData {
				(*h).HandleData(b)
			} else {
				c.otherDrops.Add(1)
			}
			quic.ReleaseDatagram(b)
		}
		if h != nil {
			(*h).BatchEnd()
		}
	}
}

// Close stops the reader of the session connection and the sends. It does
// not close the relay session, and it does not wait for a reader.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	c.stop()
	return nil
}

// Stats returns the drop counters.
func (c *Conn) Stats() Stats {
	return Stats{OtherDrops: c.otherDrops.Load()}
}
