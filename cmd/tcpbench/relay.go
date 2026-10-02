package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/icx/psp"
	"github.com/apoxy-dev/icx/vtep"
	icxns "github.com/apoxy-dev/icx/vtep/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

// relayOptions configure the relay side.
type relayOptions struct {
	Local, Peer netip.AddrPort
	MTU         int
}

// mark is a snapshot of the relay counters and CPU time.
type mark struct {
	Bytes    uint64  `json:"bytes"`
	Segments uint64  `json:"segments"`
	Retrans  uint64  `json:"retrans"`
	Nanos    int64   `json:"nanos"`
	CPU      float64 `json:"cpu_s"`
}

// segCounter counts the inner TCP data segments that the relay decrypts.
// A segment that ends at or below the highest end sequence of its flow counts as a retransmission.
// A reordered segment also counts.
type segCounter struct {
	vtep.EngineXfrm
	segments, retrans atomic.Uint64
	// high is the highest end sequence by source port. Only the inbound pump uses it.
	high map[uint16]uint32
}

func newSegCounter(e vtep.EngineXfrm) *segCounter {
	return &segCounter{EngineXfrm: e, high: make(map[uint16]uint32)}
}

func (c *segCounter) PhyToVirt(phy, virt []byte) int {
	n := c.EngineXfrm.PhyToVirt(phy, virt)
	if n > 0 {
		c.count(virt[:n])
	}
	return n
}

func (c *segCounter) count(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != header.IPv4Version {
		return
	}
	ip := header.IPv4(pkt)
	hl, tl := int(ip.HeaderLength()), int(ip.TotalLength())
	if ip.TransportProtocol() != header.TCPProtocolNumber || tl > len(pkt) || tl < hl+header.TCPMinimumSize {
		return
	}
	seg := header.TCP(pkt[hl:tl])
	payload := tl - hl - int(seg.DataOffset())
	if payload <= 0 {
		return
	}
	c.segments.Add(1)
	end := seg.SequenceNumber() + uint32(payload)
	if high, ok := c.high[seg.SourcePort()]; ok && int32(end-high) <= 0 {
		c.retrans.Add(1)
		return
	}
	c.high[seg.SourcePort()] = end
}

// relay is the receiver side: a gVisor stack behind the netstack datapath, a TCP
// sink and a UDP echo.
type relay struct {
	stack *stack.Stack
	seg   *segCounter
	bytes atomic.Uint64
	start time.Time
}

func (r *relay) mark() mark {
	return mark{
		Bytes:    r.bytes.Load(),
		Segments: r.seg.segments.Load(),
		Retrans:  r.seg.retrans.Load(),
		Nanos:    time.Since(r.start).Nanoseconds(),
		CPU:      bench.CPUSeconds(),
	}
}

// runRelay serves one agent on the control listener ln until the agent closes the control connection.
// It answers marks only after the datapath runs.
func runRelay(ctx context.Context, o relayOptions, ln net.Listener) (mark, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Close the control socket when ctx ends, to stop Accept.
	defer context.AfterFunc(ctx, func() { ln.Close() })()

	phy, err := listenPhy(o.Local)
	if err != nil {
		return mark{}, err
	}
	defer phy.Close()
	engine, err := newEngine(o.Local, o.Peer, psp.Responder)
	if err != nil {
		return mark{}, err
	}
	r := &relay{seg: newSegCounter(engine), start: time.Now()}
	ep, err := r.newStack(o.MTU)
	if err != nil {
		return mark{}, err
	}
	defer r.stack.Destroy()
	dp, err := icxns.New(icxns.Config{Engine: r.seg, Endpoint: ep, Underlay: &underlay{phy: phy}})
	if err != nil {
		return mark{}, err
	}
	go func() {
		if err := dp.Run(ctx); err != nil {
			slog.Error("Relay datapath stopped", "error", err)
		}
	}()
	if err := r.serve(ctx); err != nil {
		return mark{}, err
	}

	slog.Info("Relay listening", "ctl", ln.Addr(), "tunnel", o.Local)
	ctl, err := ln.Accept()
	if err != nil {
		return mark{}, fmt.Errorf("accept control connection: %w", err)
	}
	defer ctl.Close()
	err = serveMarks(ctl, r)
	return r.mark(), err
}

// newStack creates the receiver stack with large receive buffers, so that the receiver does not limit the sender.
func (r *relay) newStack(mtu int) (*channel.Endpoint, error) {
	r.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	sack := tcpip.TCPSACKEnabled(true)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	opts := []tcpip.SettableTransportProtocolOption{
		&sack,
		&moderate,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 64 << 10, Default: 2 << 20, Max: 64 << 20},
	}
	for _, opt := range opts {
		if err := r.stack.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return nil, fmt.Errorf("set %T: %v", opt, err)
		}
	}
	ep := channel.New(4096, uint32(mtu), "")
	if err := r.stack.CreateNIC(1, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}
	addr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(relayInner.As4()).WithPrefix(),
	}
	if err := r.stack.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address: %v", err)
	}
	r.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return ep, nil
}

// serve starts the TCP sink and the UDP echo on the inner address.
func (r *relay) serve(ctx context.Context) error {
	addr := tcpip.AddrFrom4(relayInner.As4())
	ln, err := gonet.ListenTCP(r.stack, tcpip.FullAddress{NIC: 1, Addr: addr, Port: sinkPort}, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	echo, err := gonet.DialUDP(r.stack, &tcpip.FullAddress{NIC: 1, Addr: addr, Port: echoPort}, nil, ipv4.ProtocolNumber)
	if err != nil {
		ln.Close()
		return err
	}
	context.AfterFunc(ctx, func() {
		ln.Close()
		echo.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.sink(c)
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], from)
		}
	}()
	return nil
}

// sink reads and counts the data of one flow.
func (r *relay) sink(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 256<<10)
	for {
		n, err := c.Read(buf)
		r.bytes.Add(uint64(n))
		if err != nil {
			return
		}
	}
}

// serveMarks answers each "mark" line of the agent with the relay counters.
func serveMarks(ctl net.Conn, r *relay) error {
	sc := bufio.NewScanner(ctl)
	enc := json.NewEncoder(ctl)
	for sc.Scan() {
		if sc.Text() != "mark" {
			return fmt.Errorf("unknown control message %q", sc.Text())
		}
		if err := enc.Encode(r.mark()); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// underlay adapts *l2pc.L2PacketConn to the datapath underlay, as pkg/netstack does.
type underlay struct {
	phy  *l2pc.L2PacketConn
	msgs []batchpc.Message
}

func (u *underlay) ReadFrame(buf []byte) (int, error) { return u.phy.ReadFrame(buf) }

func (u *underlay) WriteFrames(frames [][]byte) (int, error) {
	if cap(u.msgs) < len(frames) {
		u.msgs = make([]batchpc.Message, len(frames))
	}
	msgs := u.msgs[:len(frames)]
	for i, f := range frames {
		msgs[i] = batchpc.Message{Buf: f}
	}
	return u.phy.WriteBatchFrames(msgs, 0)
}
