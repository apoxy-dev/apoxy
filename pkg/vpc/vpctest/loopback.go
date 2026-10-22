// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"errors"
	"net"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
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
	return NewSockets(data, qc), nil
}

// NewSockets returns the data plane on data and quic. Run gives the packets of data to the
// pipeline.
func NewSockets(data, quic *net.UDPConn) *Sockets {
	return &Sockets{Target: NewSocketTarget(data), Data: data, QUIC: quic}
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
		Pipeline: dp.New(func(to netip.AddrPort, b []byte) { _, _ = sock.WriteTo(b, net.UDPAddrFromAddrPort(to)) }),
		port:     sock.LocalAddr().(*net.UDPAddr).AddrPort().Port(),
	}
}

// DataPort returns the port of the socket.
func (t *SocketTarget) DataPort() uint16 { return t.port }

// Run gives each packet of Data to the pipeline until Data closes.
func (s *Sockets) Run() error {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.Data.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		s.Target.Receive(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), buf[:n])
	}
}

// Close closes the two sockets.
func (s *Sockets) Close() error {
	return errors.Join(s.Data.Close(), s.QUIC.Close())
}
