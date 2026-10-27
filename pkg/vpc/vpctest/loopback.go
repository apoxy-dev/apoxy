// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"errors"
	"net"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp/aead"
)

// Sockets is a relay data plane on two UDP sockets, in place of the dedicated interface of a
// relay: Data carries the PSP packets and the path probes, and QUIC carries the agent connections.
type Sockets struct {
	Target *SocketTarget
	Data   *net.UDPConn
	QUIC   *net.UDPConn
}

// NewLoopback opens the two sockets on free ports of 127.0.0.1.
func NewLoopback() (*Sockets, error) {
	data, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	qc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = data.Close()
		return nil, err
	}
	return &Sockets{Target: NewSocketTarget(data), Data: data, QUIC: qc}, nil
}

// DataPort returns the port of Data.
func (s *Sockets) DataPort() uint16 { return s.Target.DataPort() }

// SocketTarget is a pipeline that sends from the UDP socket sock. It is a relay.PortTarget.
type SocketTarget struct {
	*dp.Pipeline
	port uint16
}

// NewSocketTarget returns a pipeline that sends its packets from sock.
func NewSocketTarget(sock net.PacketConn) *SocketTarget {
	return &SocketTarget{
		Pipeline: dp.New(socketSender{sock}, aead.GCM{}),
		port:     sock.LocalAddr().(*net.UDPAddr).AddrPort().Port(),
	}
}

// socketSender sends each packet of a batch with one WriteTo.
type socketSender struct{ sock net.PacketConn }

func (s socketSender) Send(b *dp.TxBatch) {
	for i := range b.Len() {
		to, p := b.Packet(i)
		_, _ = s.sock.WriteTo(p, net.UDPAddrFromAddrPort(to))
	}
}

// DataPort returns the port of the socket.
func (t *SocketTarget) DataPort() uint16 { return t.port }

// Run gives each packet of Data to the pipeline, in a batch of one, until Data closes.
func (s *Sockets) Run() error {
	buf := make([]byte, 65535)
	rx := make([]dp.RxPacket, 1)
	var tx dp.TxBatch
	for {
		n, from, err := s.Data.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		rx[0] = dp.RxPacket{From: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), Payload: buf[:n]}
		s.Target.Receive(rx, &tx)
	}
}

// Close closes the two sockets.
func (s *Sockets) Close() error {
	return errors.Join(s.Data.Close(), s.QUIC.Close())
}
