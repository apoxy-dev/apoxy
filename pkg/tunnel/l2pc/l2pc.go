package l2pc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/icx/addrselect"
	"github.com/apoxy-dev/icx/udp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

var ErrInvalidFrame = errors.New("invalid frame")

// L2PacketConn adapts a net.PacketConn (UDP) to read/write L2 Ethernet frames.
type L2PacketConn struct {
	pc           batchpc.BatchPacketConn // now the batched PacketConn (still implements net.PacketConn)
	localAddrs   addrselect.List
	localMAC     tcpip.LinkAddress
	peerMACCache sync.Map
	pktPool      sync.Pool
}

// NewL2PacketConn creates a new L2PacketConn.
func NewL2PacketConn(pc batchpc.BatchPacketConn) (*L2PacketConn, error) {
	ua, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || ua == nil {
		return nil, fmt.Errorf("PacketConn must be UDP")
	}

	localAddrPort := netip.AddrPortFrom(netip.MustParseAddr(ua.IP.String()),
		uint16(ua.Port))

	localAddrPorts := []netip.AddrPort{localAddrPort}
	if localAddrPort.Addr().IsUnspecified() {
		localAddrs, err := tunnet.GetAllGlobalUnicastAddresses(true)
		if err != nil {
			return nil, fmt.Errorf("failed to get local addresses: %w", err)
		}

		for _, addr := range localAddrs {
			localAddrPorts = append(localAddrPorts, netip.AddrPortFrom(addr.Addr(), localAddrPort.Port()))
		}
	}

	// Random locally-administered unicast MAC for "our" link address.
	localMAC := tcpip.GetRandMacAddr()

	var localAddrs addrselect.List
	for _, ap := range localAddrPorts {
		la := &tcpip.FullAddress{
			Addr: func() tcpip.Address {
				if ap.Addr().Is4() {
					return tcpip.AddrFrom4Slice(ap.Addr().AsSlice())
				}
				return tcpip.AddrFrom16Slice(ap.Addr().AsSlice())
			}(),
			Port:     uint16(ua.Port),
			LinkAddr: localMAC,
		}
		localAddrs = append(localAddrs, la)
	}

	// Ensure we have at least one address.
	if len(localAddrs) == 0 {
		return nil, fmt.Errorf("no valid local addresses found")
	}

	c := &L2PacketConn{
		pc:         pc,
		localAddrs: localAddrs,
		localMAC:   localMAC,
		pktPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 65535)
				return &b
			},
		},
	}
	return c, nil
}

func (c *L2PacketConn) Close() error {
	return c.pc.Close()
}

// WriteFrame consumes an Ethernet frame (IPv4/IPv6 + UDP) and writes the payload
// to the underlying PacketConn based on the frame’s dst IP:port.
func (c *L2PacketConn) WriteFrame(frame []byte) error {
	payload, dst, err := extractUDPPayloadAndDst(frame)
	if err != nil {
		return err
	}
	_, err = c.pc.WriteTo(payload, dst)
	return err
}

// ReadFrame reads from PacketConn and emits a full Ethernet frame into dst.
// The Ethernet dst MAC is our random local MAC; the src MAC is a stable random,
// locally-administered unicast MAC based on the remote IP.
func (c *L2PacketConn) ReadFrame(dst []byte) (int, error) {
	phy := c.pktPool.Get().(*[]byte)
	defer c.pktPool.Put(phy)
	*phy = (*phy)[:cap(*phy)]

	// Read UDP payload.
	n, raddr, err := c.pc.ReadFrom((*phy)[:])
	if err != nil {
		return 0, err
	}
	remote, ok := raddr.(*net.UDPAddr)
	if !ok || remote == nil {
		return 0, fmt.Errorf("unexpected remote addr type %T", raddr)
	}

	// Encode the full Ethernet+IP+UDP frame in-place.
	frameLen, err := c.encodeInboundFrame((*phy)[:], n, remote)
	if err != nil {
		return 0, err
	}

	// Finally, copy out to dst.
	if len(dst) < frameLen {
		return 0, errors.New("destination buffer too small")
	}
	copy(dst[:frameLen], (*phy)[:frameLen])
	return frameLen, nil
}

// WriteBatchFrames consumes a batch of Ethernet frames (IPv4/IPv6 + UDP)
// and writes their UDP payloads to destinations extracted from each frame.
// On return, n is the number of frames successfully queued/written.
func (c *L2PacketConn) WriteBatchFrames(msgs []batchpc.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	// Prepare the underlying UDP messages (payload + addr).
	umsgs := make([]batchpc.Message, len(msgs))
	for i := range msgs {
		payload, dst, err := extractUDPPayloadAndDst(msgs[i].Buf)
		if err != nil {
			return i, err
		}
		umsgs[i].Buf = payload
		umsgs[i].Addr = dst
	}

	// Send in one batch.
	return c.pc.WriteBatch(umsgs, flags)
}

// ReadBatchFrames reads a batch of UDP payloads and emits fully-formed
// Ethernet frames into msgs[i].Buf (resizing the slice length to the frame size).
// msgs[i].Addr will be set to the remote *net.UDPAddr for convenience.
func (c *L2PacketConn) ReadBatchFrames(msgs []batchpc.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	// Prepare underlying UDP read buffers sourced from our pool.
	umsgs := make([]batchpc.Message, len(msgs))
	phys := make([]*[]byte, len(msgs)) // to Put() back after use

	for i := range msgs {
		phy := c.pktPool.Get().(*[]byte)
		*phy = (*phy)[:cap(*phy)]
		phys[i] = phy
		umsgs[i].Buf = (*phy)[:]
	}

	n, err := c.pc.ReadBatch(umsgs, flags)

	// Return pooled buffers we didn't fill.
	for i := n; i < len(phys); i++ {
		if phys[i] != nil {
			c.pktPool.Put(phys[i])
			phys[i] = nil
		}
	}
	if err != nil && n == 0 {
		// If nothing was read, return early with the error.
		for i := 0; i < len(phys); i++ {
			if phys[i] != nil {
				c.pktPool.Put(phys[i])
			}
		}
		return 0, err
	}

	// Translate each UDP payload into a full Ethernet frame and copy to caller buffers.
	for i := 0; i < n; i++ {
		raddr, ok := umsgs[i].Addr.(*net.UDPAddr)
		if !ok || raddr == nil {
			// Clean up and return partial progress + error.
			for j := i; j < n; j++ {
				if phys[j] != nil {
					c.pktPool.Put(phys[j])
				}
			}
			return i, fmt.Errorf("unexpected remote addr type %T", umsgs[i].Addr)
		}

		// Encode headers into our scratch buffer.
		frameLen, encErr := c.encodeInboundFrame((*phys[i])[:], len(umsgs[i].Buf), raddr)
		if encErr != nil {
			for j := i; j < n; j++ {
				if phys[j] != nil {
					c.pktPool.Put(phys[j])
				}
			}
			return i, encErr
		}

		// Copy to caller buffer and set slice length.
		if len(msgs[i].Buf) < frameLen {
			for j := i; j < n; j++ {
				if phys[j] != nil {
					c.pktPool.Put(phys[j])
				}
			}
			return i, errors.New("destination buffer too small")
		}
		copy(msgs[i].Buf[:frameLen], (*phys[i])[:frameLen])
		msgs[i].Buf = msgs[i].Buf[:frameLen]
		msgs[i].Addr = raddr // surface the remote UDP address for diagnostics/metrics
	}

	// Return pooled buffers for the successfully processed packets.
	for i := 0; i < n; i++ {
		if phys[i] != nil {
			c.pktPool.Put(phys[i])
		}
	}

	return n, err
}

// LocalMAC returns the locally-administered unicast MAC address used by this connection.
func (c *L2PacketConn) LocalMAC() tcpip.LinkAddress {
	return c.localMAC
}

// peerMACForIP returns a cached random, locally-administered unicast MAC
// for the given remote IP, creating it on first use.
func (c *L2PacketConn) peerMACForIP(ip net.IP) tcpip.LinkAddress {
	key := ip.String()
	if v, ok := c.peerMACCache.Load(key); ok {
		return v.(tcpip.LinkAddress)
	}
	// Create and publish a new random MAC.
	newMAC := tcpip.GetRandMacAddr()
	// Use LoadOrStore to avoid races/duplication.
	if v, loaded := c.peerMACCache.LoadOrStore(key, newMAC); loaded {
		return v.(tcpip.LinkAddress)
	}
	return newMAC
}

// encodeInboundFrame takes an inbound UDP payload (already read from the socket)
// plus its remote addr, and encodes a full Ethernet+IP+UDP frame into buf in place.
// It returns the frame length. buf must be a scratch buffer with capacity >= headers+payload.
func (c *L2PacketConn) encodeInboundFrame(buf []byte, payloadLen int, raddr *net.UDPAddr) (int, error) {
	// Decide header room by family and move payload to make space.
	payloadOff := udp.PayloadOffsetIPv4
	if raddr.IP.To4() == nil {
		payloadOff = udp.PayloadOffsetIPv6
	}
	if payloadOff+payloadLen > cap(buf) {
		return 0, errors.New("packet too large")
	}
	// The input layout is [payload ...]; shift it up in-place.
	copy(buf[payloadOff:], buf[:payloadLen])

	// Build addresses for udp.Encode (inbound: src = remote, dst = local).
	srcFA := toFullAddr(raddr)
	dstFA := c.localAddrs.Select(srcFA)
	srcFA.LinkAddr = c.peerMACForIP(raddr.IP) // stable random per peer

	return udp.Encode(buf[:], srcFA, dstFA, payloadLen, false)
}

// extractUDPPayloadAndDst validates an Ethernet frame (IPv4/IPv6+UDP)
// and returns the UDP payload and destination socket address.
func extractUDPPayloadAndDst(frame []byte) (payload []byte, dst *net.UDPAddr, err error) {
	if len(frame) < header.EthernetMinimumSize {
		return nil, nil, ErrInvalidFrame
	}
	eth := header.Ethernet(frame)
	switch eth.Type() {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.Protocol() != uint8(header.UDPProtocolNumber) {
			return nil, nil, ErrInvalidFrame
		}
		udpHdr := header.UDP(ip.Payload())
		if len(udpHdr) < header.UDPMinimumSize {
			return nil, nil, ErrInvalidFrame
		}
		return udpHdr.Payload(), &net.UDPAddr{
			IP:   net.IP(ip.DestinationAddressSlice()),
			Port: int(udpHdr.DestinationPort()),
		}, nil

	case header.IPv6ProtocolNumber:
		ip6 := header.IPv6(frame[header.EthernetMinimumSize:])
		if !ip6.IsValid(len(ip6)) || ip6.TransportProtocol() != header.UDPProtocolNumber {
			return nil, nil, ErrInvalidFrame
		}
		udpHdr := header.UDP(ip6.Payload())
		if len(udpHdr) < header.UDPMinimumSize {
			return nil, nil, ErrInvalidFrame
		}
		return udpHdr.Payload(), &net.UDPAddr{
			IP:   net.IP(ip6.DestinationAddressSlice()),
			Port: int(udpHdr.DestinationPort()),
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported ethertype: %d", eth.Type())
	}
}

func toFullAddr(ua *net.UDPAddr) *tcpip.FullAddress {
	if ua.IP.To4() != nil {
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(ua.IP.To4()),
			Port: uint16(ua.Port),
		}
	}
	return &tcpip.FullAddress{
		Addr: tcpip.AddrFrom16Slice(ua.IP.To16()),
		Port: uint16(ua.Port),
	}
}
