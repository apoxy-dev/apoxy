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

// Conn sends data frames on the session connection of a relay session, and
// gives the received data frames to its handler.
type Conn struct {
	qc     quic.Connection
	stop   context.CancelFunc // Stops the reader of the session connection.
	closed atomic.Bool

	data atomic.Pointer[func([]byte)]

	otherDrops atomic.Uint64
}

// Stats counts dropped frames.
type Stats struct {
	// OtherDrops are frames that are not data frames, or that no handler took.
	OtherDrops uint64
}

// New returns a Conn on the relay session qc, and starts the reader of qc.
// qc must have datagrams on.
func New(qc quic.Connection) *Conn {
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

// HandleData gives the data frames of the relay session to h, and nil stops it. h runs on the reader
// of the session connection and must not block. The frame is valid only until h returns.
func (c *Conn) HandleData(h func(frame []byte)) {
	if h == nil {
		c.data.Store(nil)
		return
	}
	c.data.Store(&h)
}

// receive reads the frames of the session connection until ctx ends or the
// connection closes. Data frames go to the data handler. It drops and counts
// the other frames.
func (c *Conn) receive(ctx context.Context) {
	for {
		b, err := c.qc.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if h := c.data.Load(); h != nil && len(b) > 0 && b[0] == TypeData {
			(*h)(b)
		} else {
			c.otherDrops.Add(1)
		}
		quic.ReleaseDatagram(b)
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
