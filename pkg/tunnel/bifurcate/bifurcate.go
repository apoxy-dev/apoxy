package bifurcate

import (
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/apoxy-dev/icx/geneve"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

var messagePool = sync.Pool{
	New: func() any {
		return &batchpc.Message{Buf: make([]byte, 65535)}
	},
}

// Bifurcate splits incoming packets from `pc` into geneve and other channels.
func Bifurcate(pc batchpc.BatchPacketConn) (batchpc.BatchPacketConn, batchpc.BatchPacketConn) {
	var closeConnOnce sync.Once
	geneveConn := newChanPacketConn(pc, &closeConnOnce)
	otherConn := newChanPacketConn(pc, &closeConnOnce)

	// Local copies we can nil out when a side is closed.
	geneveCh := geneveConn.ch
	otherCh := otherConn.ch
	var geneveClosed <-chan struct{} = geneveConn.closed
	var otherClosed <-chan struct{} = otherConn.closed

	go func() {
		// Reusable read batch (values) for kernel I/O.
		msgs := make([]batchpc.Message, batchpc.MaxBatchSize)
		// Shadow array of pooled message pointers we own & recycle.
		pm := make([]*batchpc.Message, batchpc.MaxBatchSize)

		for {
			// If both sides are gone, stop.
			if geneveCh == nil && otherCh == nil {
				return
			}

			// Prepare buffers for a full batch read.
			for i := range msgs {
				if pm[i] == nil {
					pm[i] = messagePool.Get().(*batchpc.Message)
				}
				// Reset/expand the buffer we hand to the kernel.
				pm[i].Buf = pm[i].Buf[:cap(pm[i].Buf)]
				pm[i].Addr = nil

				msgs[i].Buf = pm[i].Buf
				msgs[i].Addr = nil
			}

			n, err := pc.ReadBatch(msgs, 0)
			if err != nil {
				// Recycle any pooled messages we haven't handed off.
				for i := 0; i < len(pm); i++ {
					if pm[i] != nil {
						messagePool.Put(pm[i])
						pm[i] = nil
					}
				}

				// Bubble the error up to each chanPacketConn.
				geneveConn.setErr(err)
				otherConn.setErr(err)

				// Only close+exit if this is a permanent close.
				if errors.Is(err, net.ErrClosed) {
					_ = geneveConn.Close()
					_ = otherConn.Close()
					return
				}

				slog.Warn("Error reading batch from underlying connection", slog.Any("error", err))

				// Transient error: keep the bifurcator alive.
				continue
			}

			if n == 0 {
				continue
			}

			// Classify into destination batches (slices referencing pooled messages).
			gBatch := make([]*batchpc.Message, 0, n)
			oBatch := make([]*batchpc.Message, 0, n)

			for i := 0; i < n; i++ {
				m := pm[i]
				// msgs[i].Buf may have been resized by underlying BatchPacketConn ReadBatch.
				m.Buf = msgs[i].Buf
				m.Addr = msgs[i].Addr

				if isGeneve(m.Buf) {
					gBatch = append(gBatch, m)
				} else {
					oBatch = append(oBatch, m)
				}

				// Detach so we don't double-put on error paths.
				pm[i] = nil
			}

			// Helper to send a batch or recycle if receiver closed.
			sendBatch := func(ch chan []*batchpc.Message, closed <-chan struct{}, batch []*batchpc.Message) (chan []*batchpc.Message, <-chan struct{}) {
				if ch == nil || len(batch) == 0 {
					return ch, closed
				}
				select {
				case ch <- batch:
					// Delivered; ownership of messages transfers to receiver.
				case <-closed:
					// Receiver closed: recycle messages.
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

func isGeneve(b []byte) bool {
	var hdr geneve.Header
	_, err := hdr.UnmarshalBinary(b)
	if err != nil {
		return false
	}

	// Only Geneve version 0 is defined.
	if hdr.Version != 0 {
		return false
	}

	// Check for valid protocol types (IPv4 or IPv6) or EtherType 0 (mgmt / oob).
	if hdr.ProtocolType != uint16(header.IPv4ProtocolNumber) &&
		hdr.ProtocolType != uint16(header.IPv6ProtocolNumber) &&
		hdr.ProtocolType != 0 {
		return false
	}

	return true
}
