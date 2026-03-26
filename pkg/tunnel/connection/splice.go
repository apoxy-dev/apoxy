package connection

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

const (
	tunOffset = device.MessageTransportHeaderSize
)

// observePacket handles packet observation, skipping ExtractPacketInfo when suspended.
func observePacket(obs PacketObserver, packet []byte, dir Direction) {
	if s, ok := obs.(SuspendableObserver); ok && s.IsSuspended() {
		s.CountPacket()
		return
	}
	obs.OnPacket(ExtractPacketInfo(packet, dir))
}

// SpliceConfig holds configuration options for splice operations.
type SpliceConfig struct {
	recalculateChecksum bool
	verifyChecksum      bool
	logChecksumErrors   bool
	observer            PacketObserver
}

// SpliceOption is a function that configures splice behavior.
type SpliceOption func(*SpliceConfig)

// WithChecksumRecalculation enables TCP checksum recalculation.
func WithChecksumRecalculation() SpliceOption {
	return func(c *SpliceConfig) {
		c.recalculateChecksum = true
	}
}

// WithChecksumVerification enables TCP checksum verification (for debugging).
func WithChecksumVerification() SpliceOption {
	return func(c *SpliceConfig) {
		c.verifyChecksum = true
	}
}

// WithChecksumErrorLogging enables detailed logging of checksum errors.
func WithChecksumErrorLogging() SpliceOption {
	return func(c *SpliceConfig) {
		c.logChecksumErrors = true
	}
}

// WithPacketObserver sets a packet observer for traffic monitoring.
func WithPacketObserver(obs PacketObserver) SpliceOption {
	return func(c *SpliceConfig) {
		c.observer = obs
	}
}

func defaultSpliceConfig() *SpliceConfig {
	return &SpliceConfig{
		recalculateChecksum: false,
		verifyChecksum:      false,
		logChecksumErrors:   false,
	}
}

// Splice starts the TUN <-> Connection splice operation.
func Splice(tunDev tun.Device, conn Connection, opts ...SpliceOption) error {
	config := defaultSpliceConfig()
	for _, opt := range opts {
		opt(config)
	}

	var g errgroup.Group
	batchSize := tunDev.BatchSize()

	// TUN -> Connection path
	g.Go(func() error {
		defer func() {
			slog.Debug("Stopped reading from TUN")
		}()

		defer conn.Close()

		sizes := make([]int, batchSize)
		pkts := make([][]byte, batchSize)
		for i := range pkts {
			pkts[i] = make([]byte, netstack.IPv6MinMTU)
		}

		for {
			n, err := tunDev.Read(pkts, sizes, 0)
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					slog.Error("TUN device closed", slog.Any("error", err))
					return net.ErrClosed
				}

				if errors.Is(err, tun.ErrTooManySegments) {
					slog.Warn("Dropped packets from multi-segment TUN read", slog.Any("error", err))
					continue
				}

				slog.Error("Unexpected error reading from TUN", slog.Any("error", err))
			}

			for i := 0; i < n; i++ {
				packetData := pkts[i][:sizes[i]]

				if config.observer != nil {
					observePacket(config.observer, packetData, DirectionOutbound)
				}

				if config.recalculateChecksum {
					if err := recalculateChecksumIfNeeded(packetData, config); err != nil {
						slog.Debug("Failed to recalculate checksum", slog.Any("error", err))
						// Continue processing - not all packets are TCP
					}
				}

				icmp, err := conn.WritePacket(packetData)
				if err != nil {
					slog.Error("Failed to write to connection", slog.Any("error", err))

					if len(icmp) > 0 {
						slog.Debug("Sending ICMP packet")
						if _, err := tunDev.Write([][]byte{icmp}, 0); err != nil {
							slog.Error("Failed to write ICMP packet", slog.Any("error", err))
						}
					}

					return fmt.Errorf("failed to write to connection: %w", err)
				}
			}
		}
	})

	// Connection -> TUN path
	//
	// When the connection is a muxedConn with matching headroom, we use
	// readPacketDirect to receive pooled buffers without an extra copy, and
	// tryReadPacketDirect for non-blocking batch accumulation — eliminating
	// the intermediate channel and goroutine.
	// Otherwise we fall back to the standard ReadPacket-into-local-pool path.
	type directReader interface {
		readPacketDirect() (*[]byte, error)
		tryReadPacketDirect() (*[]byte, bool)
		putPacketBuffer(*[]byte)
	}
	dr, zeroCopy := conn.(directReader)

	g.Go(func() error {
		defer func() {
			slog.Debug("Stopped reading from connection")
		}()

		pkts := make([][]byte, batchSize)

		if zeroCopy {
			// Zero-copy path: read directly from the muxedConn's internal
			// packet channel without an intermediate goroutine or channel.
			// This reduces per-packet overhead (no channel hop, no extra
			// goroutine switch) and improves batching by draining all
			// available packets from the 10k-deep internal queue.
			for {
				// Block for the first packet.
				pkt, err := dr.readPacketDirect()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return nil
					}
					slog.Error("Failed to read from connection", slog.Any("error", err))
					return fmt.Errorf("failed to read from connection: %w", err)
				}

				if config.observer != nil && len(*pkt) > tunOffset {
					observePacket(config.observer, (*pkt)[tunOffset:], DirectionInbound)
				}
				if config.recalculateChecksum {
					if err := recalculateChecksumIfNeeded((*pkt)[tunOffset:], config); err != nil {
						slog.Debug("Failed to recalculate checksum on incoming packet", slog.Any("error", err))
					}
				}

				pkts[0] = *pkt
				batchCount := 1

				// Drain available packets non-blockingly to maximize batch size.
				for batchCount < batchSize {
					pkt, ok := dr.tryReadPacketDirect()
					if !ok {
						break
					}
					if config.observer != nil && len(*pkt) > tunOffset {
						observePacket(config.observer, (*pkt)[tunOffset:], DirectionInbound)
					}
					if config.recalculateChecksum {
						if err := recalculateChecksumIfNeeded((*pkt)[tunOffset:], config); err != nil {
							slog.Debug("Failed to recalculate checksum on incoming packet", slog.Any("error", err))
						}
					}
					pkts[batchCount] = *pkt
					batchCount++
				}

				if _, err := tunDev.Write(pkts[:batchCount], tunOffset); err != nil {
					if strings.Contains(err.Error(), "closed") {
						slog.Debug("TUN device closed")
						return net.ErrClosed
					}
					slog.Error("Failed to write to TUN", slog.Any("error", err))
					return fmt.Errorf("failed to write to TUN: %w", err)
				}

				for i := 0; i < batchCount; i++ {
					p := pkts[i][:cap(pkts[i])]
					dr.putPacketBuffer(&p)
				}
			}
		}

		// Non-zero-copy fallback: use intermediate channel for batching.
		pktPool := &sync.Pool{
			New: func() any {
				return ptr.To(make([]byte, netstack.IPv6MinMTU+tunOffset))
			},
		}

		pktCh := make(chan *[]byte, batchSize)

		g.Go(func() error {
			defer close(pktCh)

			for {
				pkt := pktPool.Get().(*[]byte)
				*pkt = (*pkt)[:cap(*pkt)]
				n, err := conn.ReadPacket((*pkt)[tunOffset:])
				if err != nil {
					slog.Error("Failed to read from connection", slog.Any("error", err))
					return fmt.Errorf("failed to read from connection: %w", err)
				}
				*pkt = (*pkt)[:n+tunOffset]

				if config.observer != nil && n > 0 {
					observePacket(config.observer, (*pkt)[tunOffset:], DirectionInbound)
				}
				if config.recalculateChecksum {
					if err := recalculateChecksumIfNeeded((*pkt)[tunOffset:], config); err != nil {
						slog.Debug("Failed to recalculate checksum on incoming packet", slog.Any("error", err))
					}
				}

				pktCh <- pkt
			}
		})

		for {
			select {
			case pkt, ok := <-pktCh:
				if !ok {
					return nil
				}

				pkts[0] = *pkt
				batchCount := 1

			gatherBatch:
				for batchCount < batchSize {
					select {
					case pkt, ok := <-pktCh:
						if !ok {
							break gatherBatch
						}
						pkts[batchCount] = *pkt
						batchCount++
					default:
						break gatherBatch
					}
				}

				if _, err := tunDev.Write(pkts[:batchCount], tunOffset); err != nil {
					if strings.Contains(err.Error(), "closed") {
						slog.Debug("TUN device closed")
						return net.ErrClosed
					}
					slog.Error("Failed to write to TUN", slog.Any("error", err))
					return fmt.Errorf("failed to write to TUN: %w", err)
				}

				for i := 0; i < batchCount; i++ {
					p := pkts[i][:cap(pkts[i])]
					pktPool.Put(&p)
				}
			}
		}
	})

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to splice: %w", err)
	}

	name, _ := tunDev.Name()

	slog.Debug("Splice completed",
		slog.String("name", name),
		slog.Int("batch_size", batchSize),
		slog.Bool("checksum_recalc_enabled", config.recalculateChecksum),
	)

	return nil
}

// recalculateChecksumIfNeeded recalculates TCP checksum if the packet is TCP.
func recalculateChecksumIfNeeded(packetData []byte, config *SpliceConfig) error {
	if len(packetData) < 20 {
		return nil // Packet too short to be an IP packet.
	}

	isTCP := false
	switch packetData[0] >> 4 {
	case 4:
		if len(packetData) >= 20 {
			ihl := int(packetData[0]&0x0F) * 4
			if len(packetData) > ihl && packetData[9] == 6 {
				isTCP = true
			}
		}
	case 6:
		if len(packetData) >= 40 && packetData[6] == 6 {
			isTCP = true
		}
	default:
		return nil // Unknown IP version.
	}
	if !isTCP {
		return nil // Not a TCP packet.
	}

	if config.verifyChecksum {
		valid, err := tunnet.VerifyTCPChecksum(packetData)
		if err != nil {
			if config.logChecksumErrors {
				slog.Debug("Failed to verify TCP checksum", slog.Any("error", err))
			}
		} else if !valid {
			if config.logChecksumErrors {
				slog.Debug("Invalid TCP checksum detected before recalculation")
			}
		}
	}

	if err := tunnet.RecalculateTCPChecksum(packetData); err != nil {
		if config.logChecksumErrors {
			slog.Error("Failed to recalculate TCP checksum", slog.Any("error", err))
		}
		return err
	}

	return nil
}
