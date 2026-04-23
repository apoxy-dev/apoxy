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

	// headroom is the number of bytes reserved before packet data in pooled
	// buffers. This allows callers using readPacketDirect to receive buffers
	// with pre-allocated headroom (e.g. for TUN transport headers), avoiding
	// an extra copy.
	headroom int

	closeOnce sync.Once
	closed    atomic.Bool
}

const defaultMTU = 1500

// newMuxedConn creates a new *muxedConn.
func newMuxedConn() *muxedConn {
	headroom := tunOffset
	bufSize := headroom + defaultMTU
	return &muxedConn{
		conns:           iptrie.NewTrie(),
		prefixes:        make(map[netip.Prefix]Connection),
		incomingPackets: make(chan *[]byte, 10000),
		headroom:        headroom,
		packetBufferPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, bufSize)
				return &b
			},
		},
	}
}

func (m *muxedConn) readFromConn(src netip.Prefix, conn Connection) {
	for {
		pkt := m.packetBufferPool.Get().(*[]byte)
		// Reset the buffer to its full capacity.
		*pkt = (*pkt)[:cap(*pkt)]

		n, err := conn.ReadPacket((*pkt)[m.headroom:])
		if err != nil {
			// If the connection is closed, remove it from the multiplexer and quit
			// the read loop. Otherwise, treat it as transient error and just log it.
			var closedErr *connectip.CloseError
			isClosedErr := errors.As(err, &closedErr) ||
				errors.Is(err, net.ErrClosed) ||
				strings.Contains(err.Error(), "use of closed network connection")

			if isClosedErr {
				slog.Info("Connection closed, removing from mux",
					slog.Any("src", src),
					slog.Any("error", err))
				metrics.TunnelPacketsReceivedErrors.WithLabelValues("read_closed").Inc()

				m.Remove(src)
				m.packetBufferPool.Put(pkt)

				// Reclaim the async sender goroutine. The underlying is
				// already closed (that's what ReadPacket just told us), so
				// only the sender needs to stop — we must not double-close.
				if w, ok := conn.(*asyncSendConn); ok {
					w.shutdownSender()
				}

				return
			}

			slog.Error("Failed to read from connection", slog.Any("error", err))
			metrics.TunnelPacketsReceivedErrors.WithLabelValues("read_error").Inc()

			m.packetBufferPool.Put(pkt)
			continue
		}

		*pkt = (*pkt)[:n+m.headroom]
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

		if c := metrics.GetProtocolCounters(protocolFromPacket((*pkt)[m.headroom:m.headroom+n]), "rx"); c != nil {
			c.Packets.Inc()
			c.Bytes.Add(float64(n))
		}
	}
}

// Add adds a new connection to the multiplexer.
//
// The connection is wrapped in an asyncSendConn so that a slow or
// backpressured underlying connection cannot stall writes destined for its
// siblings via the shared splice goroutine (see async_send.go). Reads flow
// through the embedded Connection unchanged.
func (m *muxedConn) Add(addr netip.Prefix, conn Connection) error {
	if !addr.IsValid() {
		return fmt.Errorf("invalid prefix for connection: %v", addr)
	}

	slog.Info("Adding connection", slog.String("prefix", addr.String()))

	wrapped := newAsyncSendConn(conn, addr.String(), func(icmp []byte) {
		// ICMP reply (e.g. DatagramTooLarge → "packet too big") from the
		// underlying WritePacket must be delivered back up to the TUN.
		// Reuse the inbound path: push into incomingPackets with the same
		// headroom layout readFromConn produces. Drop on overflow.
		metrics.TunnelConnectIPICMPReturned.Inc()
		buf := m.packetBufferPool.Get().(*[]byte)
		*buf = (*buf)[:cap(*buf)]
		if m.headroom+len(icmp) > cap(*buf) {
			m.packetBufferPool.Put(buf)
			return
		}
		copy((*buf)[m.headroom:], icmp)
		*buf = (*buf)[:m.headroom+len(icmp)]
		select {
		case m.incomingPackets <- buf:
		default:
			m.packetBufferPool.Put(buf)
			metrics.TunnelPacketsDropped.WithLabelValues("icmp_queue_full").Inc()
		}
	})

	m.mu.Lock()
	m.conns.Insert(addr, wrapped)
	m.prefixes[addr] = wrapped
	m.mu.Unlock()

	go m.readFromConn(addr, wrapped)

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

	n := copy(pkt, (*p)[m.headroom:])

	m.packetBufferPool.Put(p)

	return n, nil
}

// readPacketDirect returns the next packet's pooled buffer directly, avoiding
// a copy. Packet data starts at buf[m.headroom:]. The caller must call
// putPacketBuffer when done with the buffer.
func (m *muxedConn) readPacketDirect() (*[]byte, error) {
	if m.closed.Load() {
		return nil, net.ErrClosed
	}

	p, ok := <-m.incomingPackets
	if !ok {
		return nil, net.ErrClosed
	}

	return p, nil
}

// tryReadPacketDirect attempts a non-blocking read from the incoming packet
// channel. Returns (nil, false) if no packet is immediately available.
func (m *muxedConn) tryReadPacketDirect() (*[]byte, bool) {
	if m.closed.Load() {
		return nil, false
	}

	select {
	case p, ok := <-m.incomingPackets:
		if !ok {
			return nil, false
		}
		return p, true
	default:
		return nil, false
	}
}

// putPacketBuffer returns a buffer obtained from readPacketDirect to the pool.
func (m *muxedConn) putPacketBuffer(p *[]byte) {
	*p = (*p)[:cap(*p)]
	m.packetBufferPool.Put(p)
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

	metrics.TunnelPacketsSent.Inc()
	metrics.TunnelBytesSent.Add(float64(len(pkt)))

	if c := metrics.GetProtocolCounters(protocolFromPacket(pkt), "tx"); c != nil {
		c.Packets.Inc()
		c.Bytes.Add(float64(len(pkt)))
	}

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

// protocolFromPacket extracts the IP protocol number from an IPv4/IPv6 packet
// and returns a label string ("tcp", "udp", "icmp", "other"). Returns "" if
// the packet is too short to determine the protocol.
func protocolFromPacket(pkt []byte) string {
	if len(pkt) == 0 {
		return ""
	}
	var proto byte
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return ""
		}
		proto = pkt[9] // IPv4 protocol field.
	case 6:
		if len(pkt) < 40 {
			return ""
		}
		proto = pkt[6] // IPv6 next header field.
	default:
		return ""
	}
	return metrics.ProtocolFromIPHeader(proto)
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

	return m.writeToConn(dstAddr, pkt), nil
}
