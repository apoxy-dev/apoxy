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

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

var ErrInvalidFrame = errors.New("invalid frame")

// L2PacketConn adapts a net.PacketConn (UDP) to read/write L2 Ethernet frames.
type L2PacketConn struct {
	pc           net.PacketConn
	localAddrs   addrselect.List
	localMAC     tcpip.LinkAddress
	peerMACCache sync.Map
	pktPool      sync.Pool
}

// NewL2PacketConn creates a new L2PacketConn.
func NewL2PacketConn(pc net.PacketConn) (*L2PacketConn, error) {
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

func (c *L2PacketConn) Close() error { return c.pc.Close() }

// WriteFrame consumes an Ethernet frame (IPv4/IPv6 + UDP) and writes the payload
// to the underlying PacketConn based on the frame’s dst IP:port.
func (c *L2PacketConn) WriteFrame(frame []byte) error {
	if len(frame) < header.EthernetMinimumSize {
		return ErrInvalidFrame
	}

	eth := header.Ethernet(frame)
	switch eth.Type() {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.Protocol() != uint8(header.UDPProtocolNumber) {
			return ErrInvalidFrame
		}
		udpHdr := header.UDP(ip.Payload())
		if len(udpHdr) < header.UDPMinimumSize {
			return ErrInvalidFrame
		}
		dst := &net.UDPAddr{
			IP:   net.IP(ip.DestinationAddressSlice()),
			Port: int(udpHdr.DestinationPort()),
		}
		payload := udpHdr.Payload()
		_, err := c.pc.WriteTo(payload, dst)
		return err

	case header.IPv6ProtocolNumber:
		ip6 := header.IPv6(frame[header.EthernetMinimumSize:])
		if !ip6.IsValid(len(ip6)) || ip6.TransportProtocol() != header.UDPProtocolNumber {
			return ErrInvalidFrame
		}
		udpHdr := header.UDP(ip6.Payload())
		if len(udpHdr) < header.UDPMinimumSize {
			return ErrInvalidFrame
		}
		dst := &net.UDPAddr{
			IP:   net.IP(ip6.DestinationAddressSlice()),
			Port: int(udpHdr.DestinationPort()),
		}
		payload := udpHdr.Payload()
		_, err := c.pc.WriteTo(payload, dst)
		return err

	default:
		return fmt.Errorf("unsupported ethertype: %d", eth.Type())
	}
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
	remote := raddr.(*net.UDPAddr)

	// Decide offset by family; then shift payload to that offset.
	payloadOffset := udp.PayloadOffsetIPv4
	isIPv6 := remote.IP.To4() == nil
	if isIPv6 {
		payloadOffset = udp.PayloadOffsetIPv6
	}

	if payloadOffset+n > cap(*phy) {
		return 0, errors.New("packet too large")
	}
	copy((*phy)[payloadOffset:], (*phy)[:n])

	// Build addresses for udp.Encode (note: for an inbound frame,
	// src = remote, dst = local).
	srcFA := toFullAddr(remote)
	dstFA := c.localAddrs.Select(srcFA)

	// Random-but-stable (per remote IP) src MAC.
	srcFA.LinkAddr = c.peerMACForIP(remote.IP)

	// Encode the full Ethernet+IP+UDP frame in-place.
	frameLen, err := udp.Encode((*phy)[:], srcFA, dstFA, n, false)
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
