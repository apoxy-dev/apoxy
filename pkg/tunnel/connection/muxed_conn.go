package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dpeckett/triemap"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// muxedConn multiplexes multiple connection.Conn objects.
type muxedConn struct {
	// Maps tunnel destination address to CONNECT-IP connection.
	conns            *triemap.TrieMap[Connection]
	incomingPackets  chan *[]byte
	packetBufferPool sync.Pool

	closeOnce sync.Once
	closed    atomic.Bool
}

// newMuxedConn creates a new *muxedConn.
func newMuxedConn() *muxedConn {
	return &muxedConn{
		conns:           triemap.New[Connection](),
		incomingPackets: make(chan *[]byte, 100),
		packetBufferPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, netstack.IPv6MinMTU)
				return &b
			},
		},
	}
}

func (m *muxedConn) readPackets(src netip.Prefix, conn Connection) {
	for {
		pkt := m.packetBufferPool.Get().(*[]byte)

		n, err := conn.ReadPacket(*pkt)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("Failed to read from connection", slog.Any("error", err))
			}
			slog.Info("Connection closed", slog.Any("src", src))
			return
		}

		slog.Debug("Read packet from connection", slog.Int("bytes", n))

		*pkt = (*pkt)[:n]
		select {
		case m.incomingPackets <- pkt:
		default:
			// Channel is closed or full, return the buffer to the pool
			m.packetBufferPool.Put(pkt)
			return
		}

		metrics.TunnelPacketsReceived.Inc()
		metrics.TunnelBytesReceived.Add(float64(n))
	}
}

// Add adds a new connection to the multiplexer.
func (m *muxedConn) Add(addr netip.Prefix, conn Connection) error {
	if !addr.IsValid() {
		return fmt.Errorf("invalid prefix for connection: %v", addr)
	}
	m.conns.Insert(addr, conn)
	go m.readPackets(addr, conn)
	return nil
}

// List lists all connections in the multiplexer.
func (m *muxedConn) List() ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	m.conns.ForEach(func(prefix netip.Prefix, value Connection) bool {
		prefixes = append(prefixes, prefix)
		return true
	})
	return prefixes, nil
}

// Del removes a connection from the multiplexer.
func (m *muxedConn) Del(addr netip.Prefix) error {
	// Has the connection already been closed?
	if m.closed.Load() {
		// Then this becomes a no-op.
		return nil
	}

	if !addr.IsValid() {
		return fmt.Errorf("invalid prefix for connection: %v", addr)
	}

	// Remove the connection from the map. Connection closing is handled by
	// the layer above.
	if ok := m.conns.Remove(addr); !ok {
		return fmt.Errorf("connection not found: %v", addr)
	}

	return nil
}

func (m *muxedConn) Prefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	m.conns.ForEach(func(prefix netip.Prefix, value Connection) bool {
		prefixes = append(prefixes, prefix)
		return true
	})
	return prefixes
}

func (m *muxedConn) Close() error {
	var firstErr error
	m.closeOnce.Do(func() {
		// Close all connections in the map.
		m.conns.ForEach(func(prefix netip.Prefix, conn Connection) bool {
			if err := conn.Close(); err != nil {
				slog.Warn("Failed to close connection",
					slog.String("prefix", prefix.String()), slog.Any("error", err))
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to close connection: %w", err)
				}
			}
			return true
		})

		// Clear the map.
		m.conns.Clear()

		// Close the incoming packets channel.
		close(m.incomingPackets)

		// Mark the connection as closed.
		m.closed.Store(true)
	})

	return firstErr
}

// ReadPacket reads a packet from multiple underlying Connection pipes.
func (m *muxedConn) ReadPacket(pkt []byte) (int, error) {
	if m.closed.Load() {
		return 0, net.ErrClosed
	}

	p, ok := <-m.incomingPackets
	if !ok {
		return 0, net.ErrClosed
	}

	n := copy(pkt, *p)

	// Slice len must be reset to capacity or else next time it's used,
	// it may be too short.
	*p = (*p)[:cap(*p)]
	m.packetBufferPool.Put(p)

	return n, nil
}

func (m *muxedConn) writePacket(addr netip.Addr, pkt []byte) ([]byte, error) {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		slog.Warn("Invalid IP", slog.String("ip", addr.String()))
		return nil, nil
	}

	conn, ok := m.conns.Get(addr)
	if !ok {
		return nil, fmt.Errorf("no matching tunnel found for IP: %s", addr.String())
	}

	metrics.TunnelPacketsSent.Inc()
	metrics.TunnelBytesSent.Add(float64(len(pkt)))

	icmp, err := conn.WritePacket(pkt)
	if err != nil && strings.Contains(err.Error(), "closed") { // Don't propagate close of underlying connection.
		return icmp, err
	}

	return icmp, nil
}

// SrcMuxedConn implements Connection that multiplexes multiple Connections based
// on the source IP of the IPv4/v6 packet.
type SrcMuxedConn struct {
	muxedConn
}

// NewSrcMuxedConn creates a new SrcMuxedConn instance.
func NewSrcMuxedConn() *SrcMuxedConn {
	return &SrcMuxedConn{
		muxedConn: *newMuxedConn(),
	}
}

// WritePacket writes a pkt to one of the underlying Connection objects
// based on the source IP of the pkt.
func (m *SrcMuxedConn) WritePacket(pkt []byte) ([]byte, error) {
	if m.closed.Load() {
		return nil, net.ErrClosed
	}

	slog.Debug("Write packet to connection", slog.Int("bytes", len(pkt)))

	var srcAddr netip.Addr
	switch pkt[0] >> 4 {
	case 6:
		// IPv6 packet (RFC 8200).
		if len(pkt) >= 40 {
			var addr [16]byte
			copy(addr[:], pkt[8:24])
			srcAddr = netip.AddrFrom16(addr)
		} else {
			return nil, fmt.Errorf("IPv6 packet too short: %d", len(pkt))
		}
	case 4:
		// IPv4 packet (RFC 791).
		if len(pkt) >= 20 {
			var addr [4]byte
			copy(addr[:], pkt[12:16])
			srcAddr = netip.AddrFrom4(addr)
		} else {
			return nil, fmt.Errorf("IPv4 packet too short: %d", len(pkt))
		}
	default:
		return nil, fmt.Errorf("unknown packet type: %d", pkt[0]>>4)
	}

	slog.Debug("Packet source", slog.String("ip", srcAddr.String()))

	return m.writePacket(srcAddr, pkt)
}

// SrcMuxedConn implements Connection that multiplexes multiple Connections based
// on the destination IP of the IPv4/v6 packet.
type DstMuxedConn struct {
	muxedConn
}

// NewDstMuxedConn creates a new DstMuxedConn instance.
func NewDstMuxedConn() *DstMuxedConn {
	return &DstMuxedConn{
		muxedConn: *newMuxedConn(),
	}
}

// WritePacket writes a pkt to one of the underlying Connection objects
// based on the destination IP of the pkt.
func (m *DstMuxedConn) WritePacket(pkt []byte) ([]byte, error) {
	if m.closed.Load() {
		return nil, net.ErrClosed
	}

	slog.Debug("Write packet to connection", slog.Int("bytes", len(pkt)))

	var dstAddr netip.Addr
	switch pkt[0] >> 4 {
	case 6:
		// IPv6 packet (RFC 8200).
		if len(pkt) >= 40 {
			var addr [16]byte
			copy(addr[:], pkt[24:40])
			dstAddr = netip.AddrFrom16(addr)
		} else {
			return nil, fmt.Errorf("IPv6 packet too short: %d", len(pkt))
		}
	case 4:
		// IPv4 packet (RFC 791).
		if len(pkt) >= 20 {
			var addr [4]byte
			copy(addr[:], pkt[16:20])
			dstAddr = netip.AddrFrom4(addr)
		} else {
			return nil, fmt.Errorf("IPv4 packet too short: %d", len(pkt))
		}
	default:
		return nil, fmt.Errorf("unknown packet type: %d", pkt[0]>>4)
	}

	slog.Debug("Packet destination", slog.String("ip", dstAddr.String()))

	return m.writePacket(dstAddr, pkt)
}
