package bifurcate

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

var messagePool = sync.Pool{
	New: func() any {
		return &batchpc.Message{Buf: make([]byte, batchpc.MaxDatagramSize)}
	},
}

// Bifurcate splits the packets of pc into a Geneve side and a side for all other
// packets. A read deadline applies to one side. pc closes when both sides close.
func Bifurcate(pc batchpc.BatchPacketConn) (batchpc.BatchPacketConn, batchpc.BatchPacketConn) {
	open := new(atomic.Int32)
	open.Store(2)
	geneveConn := newChanPacketConn(pc, open)
	otherConn := newChanPacketConn(pc, open)

	// Local copies that become nil when a side closes.
	geneveCh := geneveConn.ch
	otherCh := otherConn.ch
	var geneveClosed <-chan struct{} = geneveConn.closed
	var otherClosed <-chan struct{} = otherConn.closed

	go func() {
		// The read batch for the kernel. It is used again for each read.
		msgs := make([]batchpc.Message, batchpc.MaxBatchSize)
		// The pooled messages that this goroutine owns.
		pm := make([]*batchpc.Message, batchpc.MaxBatchSize)

		for {
			// Stop when both sides are closed.
			if geneveCh == nil && otherCh == nil {
				return
			}

			// Prepare buffers for a full batch read.
			for i := range msgs {
				if pm[i] == nil {
					pm[i] = messagePool.Get().(*batchpc.Message)
				}
				// Give the full buffer to the kernel.
				pm[i].Buf = pm[i].Buf[:cap(pm[i].Buf)]
				pm[i].Addr = nil

				msgs[i].Buf = pm[i].Buf
				msgs[i].Addr = nil
			}

			n, err := pc.ReadBatch(msgs, 0)
			if err != nil {
				// Put back the pooled messages that no receiver has.
				for i := 0; i < len(pm); i++ {
					if pm[i] != nil {
						messagePool.Put(pm[i])
						pm[i] = nil
					}
				}

				// Send the error to each side.
				geneveConn.setErr(err)
				otherConn.setErr(err)

				// Stop only when pc is closed.
				if errors.Is(err, net.ErrClosed) {
					_ = geneveConn.Close()
					_ = otherConn.Close()
					return
				}

				slog.Warn("Error reading batch from underlying connection", slog.Any("error", err))

				// Continue after a temporary error.
				continue
			}

			if n == 0 {
				continue
			}

			// A receiver can still read the last batch, so each batch gets new slices.
			gBatch := make([]*batchpc.Message, 0, batchpc.MaxBatchSize)
			oBatch := make([]*batchpc.Message, 0, batchpc.MaxBatchSize)

			for i := 0; i < n; i++ {
				m := pm[i]
				// ReadBatch can change the length of msgs[i].Buf.
				m.Buf = msgs[i].Buf
				m.Addr = msgs[i].Addr

				if isGeneve(m.Buf) {
					gBatch = append(gBatch, m)
				} else {
					oBatch = append(oBatch, m)
				}

				// The batch owns m now, so an error does not put it back two times.
				pm[i] = nil
			}

			// sendBatch sends a batch, or puts its messages back when the side is closed.
			sendBatch := func(ch chan []*batchpc.Message, closed <-chan struct{}, batch []*batchpc.Message) (chan []*batchpc.Message, <-chan struct{}) {
				if ch == nil || len(batch) == 0 {
					return ch, closed
				}
				select {
				case ch <- batch:
					// The receiver owns the messages now.
				case <-closed:
					for _, m := range batch {
						messagePool.Put(m)
					}
					close(ch)
					ch = nil
					closed = nil
				}
				return ch, closed
			}

			geneveCh, geneveClosed = sendBatch(geneveCh, geneveClosed, gBatch)
			otherCh, otherClosed = sendBatch(otherCh, otherClosed, oBatch)
		}
	}()

	return geneveConn, otherConn
}

// isGeneve checks the fixed 8-byte Geneve header: version 0 and a protocol type
// of IPv4, IPv6 or 0.
func isGeneve(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	if b[0]>>6 != 0 {
		return false
	}
	proto := uint16(b[2])<<8 | uint16(b[3])
	return proto == uint16(header.IPv4ProtocolNumber) ||
		proto == uint16(header.IPv6ProtocolNumber) ||
		proto == 0
}
