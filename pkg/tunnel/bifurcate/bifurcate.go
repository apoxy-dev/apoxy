package bifurcate

import (
	"net"
	"sync"

	"github.com/apoxy-dev/icx/geneve"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type packet struct {
	buf  []byte
	addr net.Addr
}

var packetPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 65535)
		return &packet{
			buf:  buf,
			addr: nil,
		}
	},
}

// Bifurcate splits incoming packets from `pc` into geneve and other channels.
func Bifurcate(pc net.PacketConn) (net.PacketConn, net.PacketConn) {
	geneveConn := newChanPacketConn(pc)
	otherConn := newChanPacketConn(pc)

	// Local copies we can nil out when a side is closed.
	geneveCh := geneveConn.ch
	otherCh := otherConn.ch
	geneveClosed := geneveConn.closed
	otherClosed := otherConn.closed

	go func() {
		for {
			// If both sides are gone, stop.
			if geneveCh == nil && otherCh == nil {
				return
			}

			// Reuse packet buffer
			p := packetPool.Get().(*packet)
			p.buf = p.buf[:cap(p.buf)]

			n, addr, err := pc.ReadFrom(p.buf)
			if err != nil {
				packetPool.Put(p)
				// Propagate underlying error/closure to both children.
				_ = geneveConn.Close()
				_ = otherConn.Close()
				return
			}

			p.addr = addr
			p.buf = p.buf[:n]

			if isGeneve(p.buf) {
				for {
					// If that side is closed, drop the packet.
					if geneveCh == nil {
						packetPool.Put(p)
						break
					}
					select {
					case geneveCh <- p:
						// delivered
						break
					case <-geneveClosed:
						// Stop sending to this side going forward.
						geneveCh = nil
						geneveClosed = nil
						// try loop again, which will drop since geneveCh==nil
						continue
					}
					break
				}
			} else {
				for {
					if otherCh == nil {
						packetPool.Put(p)
						break
					}
					select {
					case otherCh <- p:
						break
					case <-otherClosed:
						otherCh = nil
						otherClosed = nil
						continue
					}
					break
				}
			}
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

	// Only Geneve version 0 is defined
	if hdr.Version != 0 {
		return false
	}

	// Check for valid protocol types (IPv4 or IPv6)
	if hdr.ProtocolType != uint16(header.IPv4ProtocolNumber) && hdr.ProtocolType != uint16(header.IPv6ProtocolNumber) {
		return false
	}

	return true
}
