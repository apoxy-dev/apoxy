package main

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

const (
	vni = 0x1000
	// sockBuf is the UDP socket buffer size that quic-go asks for.
	sockBuf = 7 << 20
)

var (
	agentInner = netip.MustParseAddr("10.0.0.1")
	relayInner = netip.MustParseAddr("10.0.0.2")
)

// newEngine returns an ICX engine in layer 3 mode with one virtual network to peer.
// Both sides use a fixed master secret.
func newEngine(local, peer netip.AddrPort, role psp.Role) (*icx.Handler, error) {
	h, err := icx.NewHandler(icx.WithLocalAddr(netstack.ToFullAddress(local)), icx.WithLayer3VirtFrames())
	if err != nil {
		return nil, err
	}
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if err := h.AddVirtualNetwork(vni, netstack.ToFullAddress(peer), []icx.Route{{Src: prefix, Dst: prefix}}); err != nil {
		return nil, err
	}
	rxSPI, txSPI, err := psp.EpochSPIs(role, 1)
	if err != nil {
		return nil, err
	}
	var master [32]byte
	copy(master[:], "tcpbench-fixed-master-secret-000")
	if err := h.UpdateVirtualNetworkSecret(vni, master, rxSPI, txSPI, time.Now().Add(24*time.Hour)); err != nil {
		return nil, err
	}
	return h, nil
}

// listenPhy opens the tunnel UDP socket at local, with the I/O wrappers of the tunnel.
func listenPhy(local netip.AddrPort) (*l2pc.L2PacketConn, error) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, err
	}
	if err := errors.Join(conn.SetReadBuffer(sockBuf), conn.SetWriteBuffer(sockBuf)); err != nil {
		conn.Close()
		return nil, err
	}
	bpc, err := batchpc.New("udp4", conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	phy, err := l2pc.NewL2PacketConn(bpc)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return phy, nil
}
