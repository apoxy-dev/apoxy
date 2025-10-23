package batchpc

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// MaxBatchSize is the maximum number of packets that can be read/written in a single batch.
const MaxBatchSize = 64

// Message represents a single packet for batched I/O.
type Message struct {
	Buf  []byte
	Addr net.Addr
}

// BatchPacketConn is a PacketConn with batched I/O using Messages.
type BatchPacketConn interface {
	net.PacketConn
	ReadBatch(msgs []Message, flags int) (int, error)
	WriteBatch(msgs []Message, flags int) (int, error)
}

// New creates a pooled BatchPacketConn wrapping a UDP PacketConn.
// network must be one of: "udp", "udp4", "udp6" (empty treated as "udp").
// If network == "udp", we infer from LocalAddr(); if ambiguous we prefer IPv6.
// Only *net.UDPConn is supported.
func New(network string, pc net.PacketConn) (BatchPacketConn, error) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("batchudp: only *net.UDPConn is supported")
	}
	return newFromUDPConn(network, uc)
}

func resolveNetwork(network string, pc net.PacketConn) (string, error) {
	switch network {
	case "", "udp":
		// Infer from LocalAddr if possible; prefer IPv6 when ambiguous.
		if ua, _ := pc.LocalAddr().(*net.UDPAddr); ua != nil && ua.IP != nil {
			if ua.IP.To4() != nil {
				return "udp4", nil
			}
			return "udp6", nil
		}
		return "udp6", nil
	case "udp4":
		return "udp4", nil
	case "udp6":
		return "udp6", nil
	default:
		return "", fmt.Errorf("batchudp: unsupported network %q (want udp, udp4, udp6)", network)
	}
}

func newFromUDPConn(network string, pc *net.UDPConn) (BatchPacketConn, error) {
	nw, err := resolveNetwork(network, pc)
	if err != nil {
		return nil, err
	}
	switch nw {
	case "udp4":
		return newBatch4(pc), nil
	case "udp6":
		return newBatch6(pc), nil
	default:
		// unreachable due to resolveNetwork
		return nil, fmt.Errorf("batchudp: unknown network %q", nw)
	}
}

// IPv4 implementation.
type batch4 struct {
	net.PacketConn                  // for net.PacketConn interface
	ipv4pc         *ipv4.PacketConn // for batch I/O
	msgPool        sync.Pool
}

func newBatch4(pc net.PacketConn) *batch4 {
	return &batch4{
		PacketConn: pc,
		ipv4pc:     ipv4.NewPacketConn(pc),
		msgPool: sync.Pool{
			New: func() any {
				s := make([]ipv4.Message, MaxBatchSize)
				return &s
			},
		},
	}
}

func (b *batch4) getTmp(n int) *[]ipv4.Message {
	ps := b.msgPool.Get().(*[]ipv4.Message)
	if cap(*ps) < n {
		// grow once; keep for reuse (amortized)
		ns := make([]ipv4.Message, n)
		*ps = ns
	}
	*ps = (*ps)[:n]
	// zero out fields we set (only Buffers/Addr/N are touched by kernel)
	for i := range *ps {
		(*ps)[i].Buffers = (*ps)[i].Buffers[:0]
		(*ps)[i].Addr = nil
		(*ps)[i].N = 0
	}
	return ps
}

func (b *batch4) putTmp(ps *[]ipv4.Message) { b.msgPool.Put(ps) }

func (b *batch4) ReadBatch(msgs []Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	tmp := b.getTmp(len(msgs))
	for i := range msgs {
		(*tmp)[i].Buffers = [][]byte{msgs[i].Buf}
	}
	n, err := b.ipv4pc.ReadBatch(*tmp, flags)
	if n > 0 {
		for i := 0; i < n; i++ {
			if len((*tmp)[i].Buffers) > 0 {
				msgs[i].Buf = (*tmp)[i].Buffers[0][:(*tmp)[i].N]
			} else {
				msgs[i].Buf = msgs[i].Buf[:0]
			}
			msgs[i].Addr = (*tmp)[i].Addr
		}
	}
	b.putTmp(tmp)
	return n, err
}

func (b *batch4) WriteBatch(msgs []Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	tmp := b.getTmp(len(msgs))
	for i := range msgs {
		(*tmp)[i].Buffers = [][]byte{msgs[i].Buf}
		(*tmp)[i].Addr = msgs[i].Addr
	}
	n, err := b.ipv4pc.WriteBatch(*tmp, flags)
	b.putTmp(tmp)
	return n, err
}

// IPv6 implementation.
type batch6 struct {
	net.PacketConn
	ipv6pc  *ipv6.PacketConn
	msgPool sync.Pool
}

func newBatch6(pc net.PacketConn) *batch6 {
	return &batch6{
		PacketConn: pc,
		ipv6pc:     ipv6.NewPacketConn(pc),
		msgPool: sync.Pool{
			New: func() any {
				s := make([]ipv6.Message, MaxBatchSize)
				return &s
			},
		},
	}
}

func (b *batch6) getTmp(n int) *[]ipv6.Message {
	ps := b.msgPool.Get().(*[]ipv6.Message)
	if cap(*ps) < n {
		ns := make([]ipv6.Message, n)
		*ps = ns
	}
	*ps = (*ps)[:n]
	for i := range *ps {
		(*ps)[i].Buffers = (*ps)[i].Buffers[:0]
		(*ps)[i].Addr = nil
		(*ps)[i].N = 0
	}
	return ps
}

func (b *batch6) putTmp(ps *[]ipv6.Message) { b.msgPool.Put(ps) }

func (b *batch6) ReadBatch(msgs []Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	tmp := b.getTmp(len(msgs))
	for i := range msgs {
		(*tmp)[i].Buffers = [][]byte{msgs[i].Buf}
	}
	n, err := b.ipv6pc.ReadBatch(*tmp, flags)
	if n > 0 {
		for i := 0; i < n; i++ {
			if len((*tmp)[i].Buffers) > 0 {
				msgs[i].Buf = (*tmp)[i].Buffers[0][:(*tmp)[i].N]
			} else {
				msgs[i].Buf = msgs[i].Buf[:0]
			}
			msgs[i].Addr = (*tmp)[i].Addr
		}
	}
	b.putTmp(tmp)
	return n, err
}

func (b *batch6) WriteBatch(msgs []Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	tmp := b.getTmp(len(msgs))
	for i := range msgs {
		(*tmp)[i].Buffers = [][]byte{msgs[i].Buf}
		(*tmp)[i].Addr = msgs[i].Addr
	}
	n, err := b.ipv6pc.WriteBatch(*tmp, flags)
	b.putTmp(tmp)
	return n, err
}
