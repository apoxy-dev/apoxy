//go:build linux

package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/udp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	_ Connection = (*ICXConn)(nil)
)

var ErrInvalidFrame = errors.New("invalid frame")

type ICXConn struct {
	pc        net.PacketConn
	handler   *icx.Handler
	localAddr *tcpip.FullAddress
	pktPool   sync.Pool
}

// NewICXConn creates a new ICXConn instance from a PacketConn and an ICX handler.
// The ICX handler should be configured in layer 3 mode.
func NewICXConn(pc net.PacketConn, handler *icx.Handler) (*ICXConn, error) {
	localAddr := pc.LocalAddr().(*net.UDPAddr)
	if localAddr == nil {
		return nil, fmt.Errorf("failed to get local address from PacketConn")
	}

	return &ICXConn{
		pc:        pc,
		handler:   handler,
		localAddr: toFullAddress(localAddr),
		pktPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 65535)
				return &b
			},
		},
	}, nil
}

func (c *ICXConn) Close() error {
	return c.pc.Close()
}

func (c *ICXConn) ReadPacket(pkt []byte) (int, error) {
	phyFrame := c.pktPool.Get().(*[]byte)
	defer c.pktPool.Put(phyFrame)
	*phyFrame = (*phyFrame)[:cap(*phyFrame)]

	// Temporarily read into the start of the buffer
	n, raddr, err := c.pc.ReadFrom((*phyFrame)[:])
	if err != nil {
		return 0, err
	}
	remoteAddr := raddr.(*net.UDPAddr)

	// Determine payload offset based on remoteAddr family
	payloadOffset := udp.PayloadOffsetIPv4
	if remoteAddr.IP.To4() == nil {
		payloadOffset = udp.PayloadOffsetIPv6
	}

	// Ensure there's enough space for move
	if payloadOffset+n > cap(*phyFrame) {
		return 0, errors.New("packet too large to fit in buffer with offset")
	}

	// Shift the received data to payloadOffset
	copy((*phyFrame)[payloadOffset:], (*phyFrame)[:n])

	// Encode the UDP frame in-place starting from offset
	phyFrameLen, err := udp.Encode(*phyFrame, toFullAddress(remoteAddr), c.localAddr, n, true)
	if err != nil {
		return 0, err
	}

	pktLen := c.handler.PhyToVirt((*phyFrame)[:phyFrameLen], pkt)
	if pktLen <= 0 {
		slog.Warn("Invalid frame received", slog.String("remote", remoteAddr.String()), slog.Int("len", n))
		return 0, nil
	}

	return pktLen, nil
}

func (c *ICXConn) WritePacket(pkt []byte) ([]byte, error) {
	phyFrame := c.pktPool.Get().(*[]byte)
	defer c.pktPool.Put(phyFrame)
	*phyFrame = (*phyFrame)[:cap(*phyFrame)]

	phyFrameLen, loopback := c.handler.VirtToPhy(pkt, *phyFrame)
	if phyFrameLen <= 0 {
		return nil, ErrInvalidFrame
	}
	*phyFrame = (*phyFrame)[:phyFrameLen]

	if loopback {
		// If the frame is a loopback, we don't send it out.
		// TODO: we should be clear if this is L2 or L3 loopback.
		// Either way for now there will be no loopbacks expected in L3 mode.
		loopbackPacket := make([]byte, phyFrameLen)
		copy(loopbackPacket, *phyFrame)
		return loopbackPacket, nil
	}

	eth := header.Ethernet((*phyFrame)[:header.EthernetMinimumSize])
	ethType := eth.Type()

	// Extract the destination address and payload offset from the frame
	var payloadOffset int
	var raddr *net.UDPAddr
	if ethType == header.IPv6ProtocolNumber {
		payloadOffset = udp.PayloadOffsetIPv6

		ip := header.IPv6((*phyFrame)[header.EthernetMinimumSize:])
		udp := header.UDP(ip.Payload())

		raddr = &net.UDPAddr{
			IP:   net.IP(ip.DestinationAddressSlice()),
			Port: int(udp.DestinationPort()),
		}
	} else if ethType == header.IPv4ProtocolNumber {
		payloadOffset = udp.PayloadOffsetIPv4

		ip := header.IPv4((*phyFrame)[header.EthernetMinimumSize:])
		udp := header.UDP(ip.Payload())

		raddr = &net.UDPAddr{
			IP:   net.IP(ip.DestinationAddressSlice()),
			Port: int(udp.DestinationPort()),
		}
	} else {
		return nil, fmt.Errorf("unsupported ethertype: %d", ethType)
	}

	// Send the packet out
	_, err := c.pc.WriteTo((*phyFrame)[payloadOffset:], raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to write packet: %w", err)
	}

	return nil, nil
}

func toFullAddress(addr *net.UDPAddr) *tcpip.FullAddress {
	if addr.IP.To4() != nil {
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addr.IP.To4()[:]),
			Port: uint16(addr.Port),
		}
	} else {
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addr.IP.To16()[:]),
			Port: uint16(addr.Port),
		}
	}
}
