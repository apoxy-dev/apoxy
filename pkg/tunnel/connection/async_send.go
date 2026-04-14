package connection

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// asyncSendQueueSize is the per-connection send-queue depth. 256 packets at
// 1500 bytes each ≈ 384KB per connection — enough to absorb short QUIC
// flow-control stalls without unbounded memory growth.
const asyncSendQueueSize = 256

// asyncSendConn wraps a Connection with a bounded send queue drained by a
// dedicated writer goroutine. WritePacket enqueues a copy and returns
// immediately; a stalled or backpressured underlying connection cannot block
// the caller. This eliminates head-of-line blocking in the splice path, where
// the single TUN→muxer goroutine previously serialized WritePacket across
// every connection.
//
// ReadPacket and the io.Closer are inherited from the embedded Connection
// without interception.
type asyncSendConn struct {
	Connection

	sendQ   chan []byte
	onICMP  func([]byte)
	addr    string // for logs/metrics
	closed  atomic.Bool
	done    chan struct{}
	closeMu sync.Mutex
}

// newAsyncSendConn wraps c with a bounded send queue. onICMP, if non-nil, is
// invoked synchronously from the sender goroutine with any ICMP reply that
// the underlying WritePacket returns (e.g. DatagramTooLarge); callers can use
// it to forward the reply back up the stack.
func newAsyncSendConn(c Connection, addr string, onICMP func([]byte)) *asyncSendConn {
	a := &asyncSendConn{
		Connection: c,
		sendQ:      make(chan []byte, asyncSendQueueSize),
		onICMP:     onICMP,
		addr:       addr,
		done:       make(chan struct{}),
	}
	go a.run()
	return a
}

func (a *asyncSendConn) run() {
	defer close(a.done)
	for pkt := range a.sendQ {
		icmp, err := a.Connection.WritePacket(pkt)
		if err != nil {
			slog.Debug("async send: WritePacket failed",
				slog.String("addr", a.addr), slog.Any("error", err))
			metrics.TunnelPacketsSentErrors.WithLabelValues("async_write").Inc()
		}
		if len(icmp) > 0 && a.onICMP != nil {
			a.onICMP(icmp)
		}
	}
}

// WritePacket enqueues pkt for asynchronous delivery. The caller retains
// ownership of pkt and is free to mutate/recycle it once WritePacket returns,
// so we copy into a freshly-allocated slice. On queue overflow the packet is
// dropped rather than blocking — a slow underlying connection must not stall
// the splice goroutine that also serves sibling connections.
func (a *asyncSendConn) WritePacket(pkt []byte) ([]byte, error) {
	if a.closed.Load() {
		return nil, nil
	}
	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	select {
	case a.sendQ <- buf:
		return nil, nil
	default:
		metrics.TunnelPacketsDropped.WithLabelValues("async_send_queue_full").Inc()
		return nil, nil
	}
}

// Close stops the sender goroutine (draining any queued packets) and then
// closes the underlying connection. Safe to call multiple times.
func (a *asyncSendConn) Close() error {
	a.closeMu.Lock()
	if !a.closed.Swap(true) {
		close(a.sendQ)
	}
	a.closeMu.Unlock()
	<-a.done
	return a.Connection.Close()
}

// shutdownSender stops the sender goroutine without closing the underlying
// connection. Used when the underlying is being closed out-of-band (e.g. by
// readFromConn detecting QUIC closure) — we still need to reclaim the
// goroutine but must not double-close the underlying.
func (a *asyncSendConn) shutdownSender() {
	a.closeMu.Lock()
	if !a.closed.Swap(true) {
		close(a.sendQ)
	}
	a.closeMu.Unlock()
	<-a.done
}
