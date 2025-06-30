package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/dpeckett/triemap"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// MuxedConn multiplexes multiple connection.Conn objects.
type MuxedConn struct {
	// Maps tunnel destination address to CONNECT-IP connection.
	conns            *triemap.TrieMap[Connection]
	incomingPackets  chan *[]byte
	packetBufferPool sync.Pool

	closeOnce sync.Once
	closed    atomic.Bool
}

// NewMuxedConn creates a new muxedConn.
func NewMuxedConn() *MuxedConn {
	return &MuxedConn{
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

func (m *MuxedConn) AddConnection(prefix netip.Prefix, conn Connection) {
	if prefix.IsValid() {
		m.conns.Insert(prefix, conn)
		go m.readPackets(conn)
	} else {
		slog.Warn("Invalid prefix for connection", slog.String("prefix", prefix.String()))
	}
}

func (m *MuxedConn) RemoveConnection(prefix netip.Prefix) error {
	// Has the connection already been closed?
	if m.closed.Load() {
		// Then this becomes a no-op.
		return nil
	}

	if prefix.IsValid() {
		conn, ok := m.conns.Get(prefix.Addr())
		if !ok {
			return fmt.Errorf("no connection found for prefix: %s", prefix.String())
		}

		// Close the connection and remove it from the map.
		if err := conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}

		// Remove the connection from the map.
		m.conns.Remove(prefix)
	} else {
		return fmt.Errorf("invalid prefix for connection: %s", prefix.String())
	}
	return nil
}

func (m *MuxedConn) Prefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	m.conns.ForEach(func(prefix netip.Prefix, value Connection) bool {
		prefixes = append(prefixes, prefix)
		return true
	})
	return prefixes
}

func (m *MuxedConn) Close() error {
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

func (m *MuxedConn) ReadPacket(pkt []byte) (int, error) {
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

func (m *MuxedConn) WritePacket(pkt []byte) ([]byte, error) {
	slog.Debug("Write packet to connection", slog.Int("bytes", len(pkt)))

	var dstIP netip.Addr
	switch pkt[0] >> 4 {
	case 6:
		// IPv6 packet (RFC 8200)
		if len(pkt) >= 40 {
			var addr [16]byte
			copy(addr[:], pkt[24:40])
			dstIP = netip.AddrFrom16(addr)
		} else {
			return nil, fmt.Errorf("IPv6 packet too short: %d", len(pkt))
		}
	case 4:
		// IPv4 packet (RFC 791)
		if len(pkt) >= 20 {
			var addr [4]byte
			copy(addr[:], pkt[16:20])
			dstIP = netip.AddrFrom4(addr)
		} else {
			return nil, fmt.Errorf("IPv4 packet too short: %d", len(pkt))
		}
	default:
		return nil, fmt.Errorf("unknown packet type: %d", pkt[0]>>4)
	}

	if !dstIP.IsValid() || !dstIP.IsGlobalUnicast() {
		slog.Debug("Invalid destination IP", slog.String("ip", dstIP.String()))
		return nil, nil
	}

	slog.Debug("Packet destination", slog.String("ip", dstIP.String()))

	conn, ok := m.conns.Get(dstIP)
	if !ok {
		return nil, fmt.Errorf("no matching tunnel found for destination IP: %s", dstIP.String())
	}

	metrics.TunnelPacketsSent.Inc()
	metrics.TunnelBytesSent.Add(float64(len(pkt)))

	return conn.WritePacket(pkt)

}

func (m *MuxedConn) readPackets(conn Connection) {
	for {
		pkt := m.packetBufferPool.Get().(*[]byte)

		n, err := conn.ReadPacket(*pkt)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("Failed to read from connection", slog.Any("error", err))
			}

			break
		}

		slog.Debug("Read packet from connection", slog.Int("bytes", n))

		*pkt = (*pkt)[:n]
		m.incomingPackets <- pkt

		metrics.TunnelPacketsReceived.Inc()
		metrics.TunnelBytesReceived.Add(float64(n))
	}
}
