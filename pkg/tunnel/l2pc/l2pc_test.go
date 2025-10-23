package l2pc_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
	"github.com/apoxy-dev/icx/udp"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestNewL2PacketConn_UDPOnly(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NotEmpty(t, c.LocalMAC())
}

type notUDPConn struct{ batchpc.BatchPacketConn }

func (n notUDPConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }

func TestNewL2PacketConn_RejectsNonUDP(t *testing.T) {
	_, err := l2pc.NewL2PacketConn(notUDPConn{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "PacketConn must be UDP")
}

func TestWriteFrame_IPv4_UsesPayloadAndDst(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	dst := peer.LocalAddr().(*net.UDPAddr)

	payload := []byte("hi-v4")
	frame := makeIPv4Frame(
		tcpip.GetRandMacAddr(),
		tcpip.GetRandMacAddr(),
		net.IPv4(127, 0, 0, 1),
		12345,
		dst.IP,
		uint16(dst.Port),
		payload,
	)

	err = c.WriteFrame(frame)
	require.NoError(t, err)

	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, from, err := peer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
	require.Equal(t, pc.LocalAddr().(*net.UDPAddr).Port, from.(*net.UDPAddr).Port)
}

func TestWriteFrame_IPv6_UsesPayloadAndDst(t *testing.T) {
	peer, err := net.ListenPacket("udp", "[::1]:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	conn, err := net.ListenPacket("udp", "[::1]:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp6", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	dst := peer.LocalAddr().(*net.UDPAddr)
	payload := []byte("hi-v6")

	frame := makeIPv6Frame(
		tcpip.GetRandMacAddr(),
		tcpip.GetRandMacAddr(),
		net.ParseIP("::1"),
		2222,
		dst.IP,
		uint16(dst.Port),
		payload,
	)

	err = c.WriteFrame(frame)
	require.NoError(t, err)

	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, from, err := peer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
	require.Equal(t, pc.LocalAddr().(*net.UDPAddr).Port, from.(*net.UDPAddr).Port)
}

func TestWriteFrame_InvalidFrames(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	// Too short
	err = c.WriteFrame([]byte{0x00})
	require.Error(t, err)
	require.True(t, errors.Is(err, l2pc.ErrInvalidFrame))

	// Unsupported ethertype
	b := make([]byte, header.EthernetMinimumSize+20)
	eth := header.Ethernet(b[:header.EthernetMinimumSize])
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type: func() tcpip.NetworkProtocolNumber {
			return tcpip.NetworkProtocolNumber(0x1234) // Invalid ethertype
		}(),
	})

	err = c.WriteFrame(b)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported ethertype")

	// IPv4 but non-UDP protocol (valid IPv4 header)
	b = make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize)
	eth = header.Ethernet(b[:header.EthernetMinimumSize])
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type: func() tcpip.NetworkProtocolNumber {
			return header.IPv4ProtocolNumber
		}(),
	})

	ip := header.IPv4(b[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(1, 1, 1, 1).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(1, 1, 1, 2).To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	err = c.WriteFrame(b)
	require.Error(t, err)
	require.True(t, errors.Is(err, l2pc.ErrInvalidFrame))

	// IPv6 but non-UDP next header
	b = make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize)
	eth = header.Ethernet(b[:header.EthernetMinimumSize])
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type: func() tcpip.NetworkProtocolNumber {
			return header.IPv6ProtocolNumber
		}(),
	})

	ip6 := header.IPv6(b[header.EthernetMinimumSize:])
	ip6.Encode(&header.IPv6Fields{
		PayloadLength:     0,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16Slice(net.ParseIP("::1").To16()),
		DstAddr:           tcpip.AddrFrom16Slice(net.ParseIP("::1").To16()),
	})
	err = c.WriteFrame(b)
	require.Error(t, err)
	require.True(t, errors.Is(err, l2pc.ErrInvalidFrame))
}

func TestReadFrame_IPv4_EncodesWithUDPEncodeAndStablePeerMAC(t *testing.T) {
	// Adapter under test
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	// Send to adapter
	_, err = peer.WriteTo([]byte("v4-one"), pc.LocalAddr())
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	frame := make([]byte, 4096)
	n, err := c.ReadFrame(frame)
	require.NoError(t, err)
	frame = frame[:n]

	// Validate the produced frame using udp.Decode (checksum + fields)
	var src tcpip.FullAddress
	pl, err := udp.Decode(frame, &src, false /* validate checksum */)
	require.NoError(t, err)
	require.Equal(t, []byte("v4-one"), pl)

	// Ethernet dst MAC must be our localMAC; src MAC is cached per IP. Decode
	// already filled src.LinkAddr from Ethernet.
	require.Equal(t, c.LocalMAC(), header.Ethernet(frame).DestinationAddress())
	srcMAC1 := src.LinkAddr

	// Second message from same IP → same cached src MAC
	_, err = peer.WriteTo([]byte("v4-two"), pc.LocalAddr())
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	n, err = c.ReadFrame(frame[:cap(frame)])
	require.NoError(t, err)
	frame = frame[:n]

	pl, err = udp.Decode(frame, &src, false)
	require.NoError(t, err)
	require.Equal(t, []byte("v4-two"), pl)
	require.Equal(t, srcMAC1, src.LinkAddr, "peer MAC should be stable for the same IP")
}

func TestReadFrame_IPv6_EncodesWithUDPEncodeAndStablePeerMAC(t *testing.T) {
	conn, err := net.ListenPacket("udp", "[::1]:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp6", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "[::1]:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	_, err = peer.WriteTo([]byte("v6-one"), pc.LocalAddr())
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	frame := make([]byte, 4096)
	n, err := c.ReadFrame(frame)
	require.NoError(t, err)
	frame = frame[:n]

	var src tcpip.FullAddress
	pl, err := udp.Decode(frame, &src, false /* checksum */)
	require.NoError(t, err)
	require.Equal(t, []byte("v6-one"), pl)
	require.Equal(t, c.LocalMAC(), header.Ethernet(frame).DestinationAddress())
	srcMAC1 := src.LinkAddr

	_, err = peer.WriteTo([]byte("v6-two"), pc.LocalAddr())
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	n, err = c.ReadFrame(frame[:cap(frame)])
	require.NoError(t, err)

	pl, err = udp.Decode(frame[:n], &src, false)
	require.NoError(t, err)
	require.Equal(t, []byte("v6-two"), pl)
	require.Equal(t, srcMAC1, src.LinkAddr)
}

func TestReadFrame_BufferTooSmall(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	_, err = peer.WriteTo([]byte("tiny"), pc.LocalAddr())
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	// Just smaller than minimum Ethernet+IPv4+UDP envelope.
	dst := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize+header.UDPMinimumSize-1)
	_, err = c.ReadFrame(dst)
	require.Error(t, err)
	require.Contains(t, err.Error(), "destination buffer too small")
}

func TestWriteBatchFrames_IPv4_SendsAll(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	dst := peer.LocalAddr().(*net.UDPAddr)

	// Build three frames to the same peer.
	payloads := [][]byte{[]byte("b1"), []byte("b2"), []byte("b3")}
	msgs := make([]batchpc.Message, len(payloads))
	for i := range payloads {
		frame := makeIPv4Frame(
			tcpip.GetRandMacAddr(),
			tcpip.GetRandMacAddr(),
			net.IPv4(127, 0, 0, 1),
			12340+uint16(i),
			dst.IP,
			uint16(dst.Port),
			payloads[i],
		)
		msgs[i].Buf = frame
	}

	n, err := c.WriteBatchFrames(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, len(msgs), n)

	// Receive all three payloads (order is not important).
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := map[string]int{}
	for i := 0; i < len(payloads); i++ {
		buf := make([]byte, 64)
		ni, _, rerr := peer.ReadFrom(buf)
		require.NoError(t, rerr)
		got[string(buf[:ni])]++
	}
	require.Equal(t, 1, got["b1"])
	require.Equal(t, 1, got["b2"])
	require.Equal(t, 1, got["b3"])
}

func TestWriteBatchFrames_Empty_NoOp(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })

	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	n, err := c.WriteBatchFrames(nil, 0)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func TestWriteBatchFrames_InvalidFrameStopsAtIndex(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })
	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	dst := peer.LocalAddr().(*net.UDPAddr)

	// Good, Bad, Good — should fail at index 1 with partial count 1.
	good1 := makeIPv4Frame(tcpip.GetRandMacAddr(), tcpip.GetRandMacAddr(),
		net.IPv4(127, 0, 0, 1), 1111, dst.IP, uint16(dst.Port), []byte("ok1"))
	bad := []byte{0x01, 0x02} // too short → ErrInvalidFrame
	good2 := makeIPv4Frame(tcpip.GetRandMacAddr(), tcpip.GetRandMacAddr(),
		net.IPv4(127, 0, 0, 1), 2222, dst.IP, uint16(dst.Port), []byte("ok2"))

	msgs := []batchpc.Message{
		{Buf: good1},
		{Buf: bad},
		{Buf: good2},
	}

	n, err := c.WriteBatchFrames(msgs, 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, l2pc.ErrInvalidFrame))
	require.Equal(t, 1, n, "should report count up to first bad frame")
}

func TestReadBatchFrames_IPv4_EncodesFramesAndSetsAddr(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })
	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	// Send three datagrams to the adapter.
	want := [][]byte{[]byte("r1"), []byte("r2"), []byte("r3")}
	for _, w := range want {
		_, err := peer.WriteTo(w, pc.LocalAddr())
		require.NoError(t, err)
	}

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Prepare batch buffers.
	msgs := make([]batchpc.Message, len(want))
	for i := range msgs {
		msgs[i].Buf = make([]byte, 4096)
	}

	n, err := c.ReadBatchFrames(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, len(want), n)

	// Validate each produced Ethernet+IP+UDP frame and that Addr is set.
	got := map[string]int{}
	for i := 0; i < n; i++ {
		var src tcpip.FullAddress
		pl, derr := udp.Decode(msgs[i].Buf, &src, false /* checksum */)
		require.NoError(t, derr)
		got[string(pl)]++
		require.NotNil(t, msgs[i].Addr)
		// Ethernet dst must be local MAC; src MAC should be stable per IP (not strictly checked here).
		require.Equal(t, c.LocalMAC(), header.Ethernet(msgs[i].Buf).DestinationAddress())
	}
	require.Equal(t, 1, got["r1"])
	require.Equal(t, 1, got["r2"])
	require.Equal(t, 1, got["r3"])
}

func TestReadBatchFrames_Empty_NoOp(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })
	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	n, err := c.ReadBatchFrames(nil, 0)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func TestReadBatchFrames_BufferTooSmallAtIndex(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pc, err := batchpc.New("udp4", conn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pc.Close()) })
	c, err := l2pc.NewL2PacketConn(pc)
	require.NoError(t, err)

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })

	// Send two datagrams.
	_, err = peer.WriteTo([]byte("x1"), pc.LocalAddr())
	require.NoError(t, err)
	_, err = peer.WriteTo([]byte("x2"), pc.LocalAddr())
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))

	// msgs[0] big enough, msgs[1] deliberately too small (< Ethernet+IPv4+UDP).
	msgs := []batchpc.Message{
		{Buf: make([]byte, 4096)},
		{Buf: make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize+header.UDPMinimumSize-1)},
	}

	n, err := c.ReadBatchFrames(msgs, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "destination buffer too small")
	require.Equal(t, 1, n, "should process exactly the first frame before failing on index 1")
}

func makeIPv4Frame(srcMAC, dstMAC tcpip.LinkAddress, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) []byte {
	buf := make([]byte, udp.PayloadOffsetIPv4+len(payload))
	copy(buf[udp.PayloadOffsetIPv4:], payload)

	src := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(srcIP.To4()),
		Port:     srcPort,
		LinkAddr: srcMAC,
	}
	dst := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(dstIP.To4()),
		Port:     dstPort,
		LinkAddr: dstMAC,
	}
	n, err := udp.Encode(buf, src, dst, len(payload), false /* calc checksum */)
	if err != nil {
		panic(err)
	}
	return buf[:n]
}

func makeIPv6Frame(srcMAC, dstMAC tcpip.LinkAddress, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) []byte {
	buf := make([]byte, udp.PayloadOffsetIPv6+len(payload))
	copy(buf[udp.PayloadOffsetIPv6:], payload)

	src := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom16Slice(dstTo16(srcIP)),
		Port:     srcPort,
		LinkAddr: srcMAC,
	}
	dst := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom16Slice(dstTo16(dstIP)),
		Port:     dstPort,
		LinkAddr: dstMAC,
	}
	n, err := udp.Encode(buf, src, dst, len(payload), false /* calc checksum */)
	if err != nil {
		panic(err)
	}
	return buf[:n]
}

func dstTo16(ip net.IP) []byte {
	if ip == nil {
		return nil
	}
	return ip.To16()
}
