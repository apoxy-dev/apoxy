package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"
	"github.com/apoxy-dev/icx/udp"
	"golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	softpspVNI = 0x1000
	// encapRoom is more than the outer Ethernet, IPv4, UDP and Geneve headers
	// and the AES-GCM tag that the engine adds.
	encapRoom = 128
)

var (
	innerSrc = [4]byte{10, 0, 0, 1}
	innerDst = [4]byte{10, 0, 0, 2}
)

// newEngine returns an ICX engine in layer 3 mode, as the tunnel runs it, with
// one virtual network to peer. Both sides use a fixed master secret.
func newEngine(local, peer *net.UDPAddr, role psp.Role) (*icx.Handler, error) {
	h, err := icx.NewHandler(icx.WithLocalAddr(fullAddr(local)), icx.WithLayer3VirtFrames())
	if err != nil {
		return nil, err
	}
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if err := h.AddVirtualNetwork(softpspVNI, fullAddr(peer), []icx.Route{{Src: prefix, Dst: prefix}}); err != nil {
		return nil, err
	}
	rxSPI, txSPI, err := psp.EpochSPIs(role, 1)
	if err != nil {
		return nil, err
	}
	var master [32]byte
	copy(master[:], "tunbench-fixed-master-secret-000")
	if err := h.UpdateVirtualNetworkSecret(softpspVNI, master, rxSPI, txSPI, time.Now().Add(24*time.Hour)); err != nil {
		return nil, err
	}
	return h, nil
}

func fullAddr(a *net.UDPAddr) *tcpip.FullAddress {
	return &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(a.IP.To4()), Port: uint16(a.Port)}
}

// innerPacket returns an IPv4 UDP packet of size bytes from innerSrc to innerDst.
func innerPacket(size int) []byte {
	b := make([]byte, size)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(innerSrc),
		DstAddr:     tcpip.AddrFrom4(innerDst),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	header.UDP(b[header.IPv4MinimumSize:]).Encode(&header.UDPFields{
		SrcPort: 5000,
		DstPort: 5001,
		Length:  uint16(size - header.IPv4MinimumSize),
	})
	return b
}

// softpspSender encrypts a batch of packets with the ICX engine and sends
// them with one sendmmsg call.
type softpspSender struct {
	engine *icx.Handler
	pc     *ipv4.PacketConn
	pkt    []byte
	bufs   [][]byte
	msgs   []ipv4.Message
}

func newSoftPSPSender(conn *net.UDPConn, relay *net.UDPAddr, pkt []byte, batch int) (*softpspSender, error) {
	engine, err := newEngine(conn.LocalAddr().(*net.UDPAddr), relay, psp.Initiator)
	if err != nil {
		return nil, err
	}
	s := &softpspSender{
		engine: engine,
		pc:     ipv4.NewPacketConn(conn),
		pkt:    pkt,
		bufs:   make([][]byte, batch),
		msgs:   make([]ipv4.Message, batch),
	}
	for i := range s.msgs {
		s.bufs[i] = make([]byte, len(pkt)+encapRoom)
		s.msgs[i] = ipv4.Message{Buffers: [][]byte{nil}, Addr: relay}
	}
	return s, nil
}

func (s *softpspSender) send() (int, error) {
	for i := range s.msgs {
		payload, err := seal(s.engine, s.pkt, s.bufs[i])
		if err != nil {
			return 0, err
		}
		s.msgs[i].Buffers[0] = payload
	}
	sent := 0
	for sent < len(s.msgs) {
		n, err := s.pc.WriteBatch(s.msgs[sent:], 0)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

func (s *softpspSender) Close() error { return nil }

// receiveSoftPSP reads batches with recvmmsg and decrypts each packet.
func receiveSoftPSP(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, o options, c *counter) error {
	engine, err := newEngine(conn.LocalAddr().(*net.UDPAddr), peer, psp.Responder)
	if err != nil {
		return err
	}
	pc := ipv4.NewPacketConn(conn)
	bufs := make([][]byte, o.Batch)
	msgs := make([]ipv4.Message, o.Batch)
	for i := range msgs {
		bufs[i] = make([]byte, o.Size+encapRoom+512)
		msgs[i].Buffers = [][]byte{bufs[i][udp.PayloadOffsetIPv4:]}
	}
	virt := make([]byte, len(bufs[0]))
	for {
		n, err := pc.ReadBatch(msgs, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read UDP batch: %w", err)
		}
		var packets, bytes uint64
		for i := range n {
			src, ok := msgs[i].Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			if k := open(engine, bufs[i], msgs[i].N, src, virt); k > 0 {
				packets++
				bytes += uint64(k)
			}
		}
		c.add(packets, bytes)
	}
}

// seal encrypts pkt into buf and returns the UDP payload. The engine writes a
// full Ethernet+IPv4+UDP frame, and the socket sends only its payload.
func seal(engine *icx.Handler, pkt, buf []byte) ([]byte, error) {
	n, _ := engine.VirtToPhy(pkt, buf)
	if n == 0 {
		return nil, errors.New("the icx engine dropped the packet")
	}
	return buf[udp.PayloadOffsetIPv4:n], nil
}

// open decrypts the UDP payload of n bytes at buf[udp.PayloadOffsetIPv4:] into
// virt and returns the inner packet length, or 0 for a drop. It first writes
// the outer frame that the engine expects in front of the payload.
func open(engine *icx.Handler, buf []byte, n int, src *net.UDPAddr, virt []byte) int {
	fa := fullAddr(src)
	frame, err := udp.Encode(buf, fa, fa, n, true)
	if err != nil {
		return 0
	}
	return engine.PhyToVirt(buf[:frame], virt)
}
