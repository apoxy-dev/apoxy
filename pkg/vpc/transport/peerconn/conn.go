// SPDX-License-Identifier: AGPL-3.0-only

// Package peerconn has the frames of the QUIC datagrams on agent sessions. Conn carries the
// data frames on the connections of a relay session: the session and its extra connections.
package peerconn

import (
	"context"
	"errors"
	"hash/maphash"
	"net"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/flow"
)

// MaxConns is the most QUIC connections that carry the data of one relay
// session. Connection 0 is the session connection; the others are extra.
const MaxConns = 4

// ErrExtraIndex is the error for an extra connection index that is not from 1
// to MaxConns-1.
var ErrExtraIndex = errors.New("peerconn: extra connection index is not from 1 to MaxConns-1")

// Conn sends data frames on the connections of a relay session, one
// connection for each flow, and gives the received data frames to its handler.
type Conn struct {
	qc   quic.Connection
	stop context.CancelFunc // Stops the reader of the session connection.

	mu     sync.Mutex // Guards closed and the connection changes.
	closed bool

	seed  maphash.Seed
	table atomic.Pointer[connTable]
	data  atomic.Pointer[func([]byte)]

	otherDrops atomic.Uint64
}

// connTable is the connections of a session. It does not change after Conn
// publishes it.
type connTable struct {
	conns [MaxConns]quic.Connection // Nil for a connection that is down.
	n     int                       // 1 + the highest connection set since New.
	live  []quic.Connection
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
	c := &Conn{qc: qc, stop: stop, seed: maphash.MakeSeed()}
	c.publish(connTable{conns: [MaxConns]quic.Connection{qc}, n: 1})
	go c.Receive(ctx, qc)
	return c
}

// SetExtra makes qc extra connection i of the relay session, or removes it if
// qc is nil. The caller reads the frames of qc with Receive. When a connection
// is down, the flows on it move to the other connections.
func (c *Conn) SetExtra(i int, qc quic.Connection) error {
	if i < 1 || i >= MaxConns {
		return ErrExtraIndex
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	t := *c.table.Load()
	t.conns[i] = qc
	if qc != nil {
		t.n = max(t.n, i+1)
	}
	c.publish(t)
	return nil
}

// publish makes t the connection table.
func (c *Conn) publish(t connTable) {
	t.live = nil
	for _, qc := range t.conns[:t.n] {
		if qc != nil {
			t.live = append(t.live, qc)
		}
	}
	c.table.Store(&t)
}

// SendData sends a data frame on the connection of its flow. A flow whose
// connection is down goes to another one. SendDatagram copies the frame.
func (c *Conn) SendData(frame []byte) error {
	t := c.table.Load()
	if t.live == nil {
		return net.ErrClosed
	}
	var h uint64
	if len(frame) > DataLen {
		h = flow.Hash(c.seed, frame[DataLen:])
	}
	n := uint64(t.n)
	qc := t.conns[h%n]
	if qc == nil {
		qc = t.live[(h/n)%uint64(len(t.live))]
	}
	return qc.SendDatagram(frame)
}

// Conns returns the number of live connections, with the session.
func (c *Conn) Conns() int { return len(c.table.Load().live) }

// HandleData gives the data frames of the relay session to h, and nil stops it. h runs on the reader
// of each connection and must not block. The frame is valid only until h returns.
func (c *Conn) HandleData(h func(frame []byte)) {
	if h == nil {
		c.data.Store(nil)
		return
	}
	c.data.Store(&h)
}

// Receive reads the frames of qc, the session connection or an extra one,
// until ctx ends or qc closes. Data frames go to the data handler. It drops
// and counts the other frames.
func (c *Conn) Receive(ctx context.Context, qc quic.Connection) {
	for {
		b, err := qc.ReceiveDatagram(ctx)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	c.stop()
	c.publish(connTable{n: 1})
	return nil
}

// Stats returns the drop counters.
func (c *Conn) Stats() Stats {
	return Stats{OtherDrops: c.otherDrops.Load()}
}
