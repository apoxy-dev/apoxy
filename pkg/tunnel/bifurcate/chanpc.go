package bifurcate

import (
	"net"
	"time"
)

type chanPacketConn struct {
	pc     net.PacketConn // underlying connection
	ch     chan *packet   // incoming packets
	closed chan struct{}
}

func newChanPacketConn(pc net.PacketConn) *chanPacketConn {
	return &chanPacketConn{
		ch:     make(chan *packet, 1024),
		pc:     pc,
		closed: make(chan struct{}),
	}
}

func (c *chanPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.ch:
		defer packetPool.Put(pkt) // return packet to pool
		n = copy(p, pkt.buf)
		return n, pkt.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *chanPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.pc.WriteTo(p, addr)
}

func (c *chanPacketConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
		return nil
	}
}

func (c *chanPacketConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}

func (c *chanPacketConn) SetDeadline(t time.Time) error {
	return c.pc.SetDeadline(t)
}

func (c *chanPacketConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *chanPacketConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}
