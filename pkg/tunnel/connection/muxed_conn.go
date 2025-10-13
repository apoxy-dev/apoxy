package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/phemmer/go-iptrie"
	connectip "github.com/quic-go/connect-ip-go"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// muxedConn multiplexes multiple connection.Conn objects.
type muxedConn struct {
	mu sync.RWMutex
	// Maps tunnel destination address to CONNECT-IP connection using iptrie.
	conns *iptrie.Trie
	// Local tracking of prefixes since go-iptrie doesn't provide enumeration
	prefixes         map[netip.Prefix]Connection
	incomingPackets  chan *[]byte
	packetBufferPool sync.Pool

	closeOnce sync.Once
	closed    atomic.Bool
}

// newMuxedConn creates a new *muxedConn.
func newMuxedConn() *muxedConn {
	return &muxedConn{
		conns:           iptrie.NewTrie(),
		prefixes:        make(map[netip.Prefix]Connection),
		incomingPackets: make(chan *[]byte, 10000),
		packetBufferPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, 1500)
				return &b
			},
		},
	}
}

func (m *muxedConn) readFromConn(src netip.Prefix, conn Connection) {
	for {
		pkt := m.packetBufferPool.Get().(*[]byte)
		// Reset the buffer to its original size.
		*pkt = (*pkt)[:cap(*pkt)]

		n, err := conn.ReadPacket(*pkt)
		if err != nil {
			// If the connection is closed, remove it from the multiplexer and quit
			// the read loop. Otherwise, treat it as transient error and just log it.
			var closedErr *connectip.CloseError
			if errors.As(err, &closedErr) {
				slog.Info("Connection closed", slog.Any("src", src), slog.Bool("remoteClosed", closedErr.Remote))
				metrics.TunnelPacketsReceivedErrors.WithLabelValues("read_closed").Inc()

				m.Remove(src)
				m.packetBufferPool.Put(pkt)

				return
			}

			slog.Error("Failed to read from connection", slog.Any("error", err))
			metrics.TunnelPacketsReceivedErrors.WithLabelValues("read_error").Inc()

			m.packetBufferPool.Put(pkt)
			continue
		}

		slog.Debug("Read packet from connection", slog.Int("bytes", n))

		*pkt = (*pkt)[:n]
		select {
		case m.incomingPackets <- pkt:
		default: // Channel is closed or full, return the buffer to the pool
			if m.closed.Load() {
				slog.Warn("Muxed connection closed", slog.Any("src", src))

				m.packetBufferPool.Put(pkt)
				return
			}
			slog.Warn("Packet queue full", slog.Int("bytes", n))
			metrics.TunnelPacketsDropped.WithLabelValues("queue_full").Inc()

			m.packetBufferPool.Put(pkt)
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

	slog.Info("Adding connection", slog.String("prefix", addr.String()))

	m.mu.Lock()
	m.conns.Insert(addr, conn)
	m.prefixes[addr] = conn
	m.mu.Unlock()

	go m.readFromConn(addr, conn)

	return nil
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

	slog.Info("Removing connection", slog.String("addr", addr.String()))

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove the connection from both the trie and our local tracking
	if _, exists := m.prefixes[addr]; !exists {
		return fmt.Errorf("connection not found: %v", addr)
	}

	m.conns.Remove(addr)
	delete(m.prefixes, addr)

	return nil
}

// Remove is an internal helper that removes a connection without external validation
func (m *muxedConn) Remove(addr netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.conns.Remove(addr)
	delete(m.prefixes, addr)
}

func (m *muxedConn) Prefixes() []netip.Prefix {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]netip.Prefix, 0, len(m.prefixes))
	for prefix := range m.prefixes {
		result = append(result, prefix)
	}
	return result
}

func (m *muxedConn) Close() error {
	slog.Info("Closing muxed connection")
	var firstErr error
	m.closeOnce.Do(func() {
		m.mu.Lock()
		// Close all connections in the map.
		for prefix, conn := range m.prefixes {
			slog.Info("Closing underlying connection", slog.String("prefix", prefix.String()))
			if err := conn.Close(); err != nil {
				slog.Warn("Failed to close connection",
					slog.String("prefix", prefix.String()), slog.Any("error", err))
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to close connection: %w", err)
				}
			}
		}

		// Clear the maps.
		m.conns = iptrie.NewTrie()
		m.prefixes = make(map[netip.Prefix]Connection)
		m.mu.Unlock()

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

	m.packetBufferPool.Put(p)

	return n, nil
}

func (m *muxedConn) writeToConn(addr netip.Addr, pkt []byte) []byte {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		slog.Warn("Invalid IP", slog.String("ip", addr.String()))
		metrics.TunnelPacketsSentErrors.WithLabelValues("invalid_ip").Inc()
		return nil
	}

	m.mu.RLock()
	connInterface := m.conns.Find(addr)
	m.mu.RUnlock()

	if connInterface == nil {
		slog.Warn("No matching tunnel found for IP", slog.String("ip", addr.String()))
		metrics.TunnelPacketsSentErrors.WithLabelValues("no_tunnel").Inc()
		return nil
	}

	conn, ok := connInterface.(Connection)
	if !ok {
		slog.Error("Invalid connection type in trie", slog.String("ip", addr.String()))
		metrics.TunnelPacketsSentErrors.WithLabelValues("internal").Inc()
		return nil
	}

	slog.Debug("Writing packet to connection", slog.String("ip", addr.String()), slog.String("conn", conn.String()))

	metrics.TunnelPacketsSent.Inc()
	metrics.TunnelBytesSent.Add(float64(len(pkt)))

	icmp, err := conn.WritePacket(pkt)
	if err != nil {
		// Log the error but don't remove the connection here to avoid issues
		// Let the read loop handle connection removal when it detects closure
		slog.Error("Failed to write to connection",
			slog.String("ip", addr.String()),
			slog.Any("error", err))
		metrics.TunnelPacketsSentErrors.WithLabelValues("write_error").Inc()
	}

	return icmp
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

func (m *SrcMuxedConn) String() string {
	return fmt.Sprintf("[src mux]: %v", m.muxedConn.Prefixes())
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

	return m.writeToConn(srcAddr, pkt), nil
}

// DstMuxedConn implements Connection that multiplexes multiple Connections based
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

func (m *DstMuxedConn) String() string {
	return fmt.Sprintf("[dst mux]: %v", m.muxedConn.Prefixes())
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

	return m.writeToConn(dstAddr, pkt), nil
}
