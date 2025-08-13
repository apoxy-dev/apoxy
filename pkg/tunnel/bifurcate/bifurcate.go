package bifurcate

import (
	"net"
	"sync"

	"github.com/apoxy-dev/icx/geneve"
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

	go func() {
		for {
			// Get a reusable packet from the pool
			p := packetPool.Get().(*packet)
			p.buf = p.buf[:cap(p.buf)] // reset buffer to full capacity

			n, addr, err := pc.ReadFrom(p.buf)
			if err != nil {
				packetPool.Put(p)
				_ = geneveConn.Close()
				_ = otherConn.Close()
				return
			}

			p.addr = addr
			p.buf = p.buf[:n] // trim to actual size

			var targetChan chan *packet
			if isGeneve(p.buf) {
				targetChan = geneveConn.ch
			} else {
				targetChan = otherConn.ch
			}

			select {
			case targetChan <- p:
			case <-geneveConn.closed:
				packetPool.Put(p)
				return
			case <-otherConn.closed:
				packetPool.Put(p)
				return
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

	// TODO: validate Geneve header fields if necessary

	return true
}
