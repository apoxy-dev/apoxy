package connection_test

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

func TestICXConn(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Create two local packet connections
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc1, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)

	fa1 := mustNewFullAddress(pc1.LocalAddr().String())

	laddr, err = net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc2, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)

	fa2 := mustNewFullAddress(pc2.LocalAddr().String())

	vni := uint(0x12345)

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	// Setup ICX handlers
	handler1, err := icx.NewHandler(icx.WithLocalAddr(fa1),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()), icx.WithLayer3VirtFrames())
	require.NoError(t, err)

	err = handler1.AddVirtualNetwork(
		vni,
		fa2,
		[]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	)
	require.NoError(t, err)

	err = handler1.UpdateVirtualNetworkKeys(
		vni,
		1, key, key,
		time.Now().Add(10*time.Minute),
	)
	require.NoError(t, err)

	handler2, err := icx.NewHandler(icx.WithLocalAddr(fa2),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()), icx.WithLayer3VirtFrames())
	require.NoError(t, err)

	err = handler2.AddVirtualNetwork(
		vni,
		fa1,
		[]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	)
	require.NoError(t, err)

	err = handler2.UpdateVirtualNetworkKeys(
		vni,
		1, key, key,
		time.Now().Add(10*time.Minute),
	)
	require.NoError(t, err)

	// Build ICX connections
	conn1, err := connection.NewICXConn(pc1, handler1)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn1.Close())
	})

	conn2, err := connection.NewICXConn(pc2, handler2)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn2.Close())
	})

	// Send a packet from conn1 to conn2
	ipPacket := makeIPv4UDPPacket()
	_, err = conn1.WritePacket(ipPacket)
	require.NoError(t, err)

	// Read the packet on conn2
	buf := make([]byte, 1500)
	n, err := conn2.ReadPacket(buf)
	require.NoError(t, err)
	require.Greater(t, n, 0)
	require.Equal(t, ipPacket, buf[:n])
}

func makeIPv4UDPPacket() []byte {
	ipPacket := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)

	ip := header.IPv4(ipPacket)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipPacket)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udp := header.UDP(ipPacket[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 1234,
		DstPort: 5678,
		Length:  header.UDPMinimumSize,
	})

	return ipPacket
}

func mustNewFullAddress(addrPortStr string) *tcpip.FullAddress {
	addrPort := netip.MustParseAddrPort(addrPortStr)

	switch addrPort.Addr().BitLen() {
	case 32:
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addrPort.Addr().AsSlice()),
			Port: addrPort.Port(),
		}
	case 128:
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addrPort.Addr().AsSlice()),
			Port: addrPort.Port(),
		}
	default:
		panic("Unsupported IP address length")
	}
}
