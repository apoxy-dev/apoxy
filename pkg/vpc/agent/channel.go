// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

const (
	// pairRx is the most channel packets that wait for the QUIC transport of a pair.
	pairRx = 256
	// maxInitials is the most Initials of no known flow that wait for the root.
	maxInitials = 64
	// maxList is the most prefixes in a list.
	maxList = 16
	// udpHdr is the size of a UDP header.
	udpHdr = 8
)

// flow is the two ends of a channel: the base address of an own session and the base address of a
// session of the peer.
type flow struct{ own, peer netip.Addr }

// flowRef is the part of a pair that the take-out handler uses.
type flowRef struct {
	rx   *proc.Mailbox // The channel packets for the QUIC transport of the pair.
	open atomic.Bool   // Set at openOK. Then an Initial on the flow drops.
	used atomic.Int64  // Unix time in nanoseconds of the last channel packet.
	// disc gets the inner probes of the flow: the PSP tests. It is set while discovery runs.
	disc atomic.Pointer[discovery]
}

// chanNet is how a pair sends its packets and finds its probe size: the binding of the agent.
type chanNet interface {
	Send(pkts [][]byte) (int, error)
	SendVia(p *psp.Peer, pkt []byte, to netip.AddrPort) error
	mtuSource
}

// chanPkt is the UDP payload of a channel packet and the way that it came.
type chanPkt struct {
	data []byte
	src  psp.Source
}

// initialMsg is a QUIC Initial of no known flow, for the root.
type initialMsg struct {
	flow flow
	pkt  chanPkt
}

// ownSet is the own addresses that the take-out handler uses.
type ownSet struct {
	list []netip.Prefix // The own list.
	all  []netip.Prefix // The prefixes of each own attachment.
	vpc  netip.Prefix   // The VPC network.
}

// chanTable is the state of the take-out handler. The root stores each new value; the handler
// reads them with no lock.
type chanTable struct {
	on       bool // Config.DirectPaths.
	flows    atomic.Pointer[map[flow]*flowRef]
	own      atomic.Pointer[ownSet]
	initials *proc.Mailbox // To the root.
}

func newChanTable(on bool) *chanTable {
	t := &chanTable{on: on, initials: proc.NewMailbox(maxInitials)}
	t.flows.Store(&map[flow]*flowRef{})
	t.own.Store(&ownSet{})
	return t
}

// take gets each channel packet to the own list from the binding. It must not block. A packet of a
// known flow goes to its pair; a QUIC Initial of no known flow that came from a relay goes to the
// root. Each other packet drops.
func (t *chanTable) take(pkt []byte, src psp.Source) {
	if len(pkt) < header.IPv6MinimumSize+udpHdr || header.IPv6(pkt).NextHeader() != uint8(header.UDPProtocolNumber) {
		return
	}
	from, to := netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
	u := header.UDP(pkt[header.IPv6MinimumSize:])
	n := int(u.Length())
	if u.SourcePort() != psp.ChannelPort || n < udpHdr || n > len(u) {
		return
	}
	data := u[udpHdr:n]
	f := flow{own: to, peer: from}
	relayed := src.Link != nil || (src.Peer != nil && !src.Peer.Direct())
	if len(data) > 0 && data[0] == p2p.TypeProbe {
		// An inner probe is a PSP test, which comes only through a direct peer.
		if ref := (*t.flows.Load())[f]; ref != nil && !relayed && src.Peer != nil {
			if d := ref.disc.Load(); d != nil {
				d.takeInner(data, src.Peer, src.Addr)
			}
		}
		return
	}
	initial := isInitial(data)
	if ref := (*t.flows.Load())[f]; ref != nil {
		if initial && (!relayed || ref.open.Load()) {
			return
		}
		ref.used.Store(time.Now().UnixNano())
		ref.rx.Send(chanPkt{data: slices.Clone(data), src: src})
		return
	}
	own := t.own.Load()
	if !t.on || !initial || !relayed || !own.vpc.Contains(from) || inPrefixes(own.all, from) || !inPrefixes(own.list, to) {
		return
	}
	t.initials.Send(initialMsg{flow: f, pkt: chanPkt{data: slices.Clone(data), src: src}})
}

// isInitial reports whether b is a QUIC version 1 Initial packet.
func isInitial(b []byte) bool {
	return len(b) >= 5 && b[0]&0x80 != 0 && b[0]&0x30 == 0 && binary.BigEndian.Uint32(b[1:5]) == 1
}

// inPrefixes reports whether a prefix of ps holds a.
func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(a) })
}

// parseList parses a list of a peer: at most maxList IPv6 /96 prefixes, one for each session.
func parseList(ss []string) ([]netip.Prefix, error) {
	if len(ss) > maxList {
		return nil, fmt.Errorf("list has %d prefixes, more than %d", len(ss), maxList)
	}
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 96 {
			return nil, fmt.Errorf("list has %q, which is not an IPv6 /96 prefix", s)
		}
		if p = p.Masked(); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// errTimeout is the error of a read after its deadline.
type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

// chanConn is the net.PacketConn of the QUIC transport of a pair. A write is an inner IPv6/UDP
// packet from port ChannelPort at the own end to the peer end; a read takes the packets that the
// take-out handler gave the flow. A write does not wait for the relay connection.
type chanConn struct {
	b             chanNet
	relay         *psp.Peer // The relay peer of the own end.
	local, remote *net.UDPAddr
	src, dst      tcpip.Address
	// routed is set at openOK: from then on a packet goes on its route, else on the relay peer.
	routed atomic.Bool
	rx     *proc.Mailbox
	q      []any // Packets that the reader took from rx and did not read yet.

	mu    sync.Mutex
	dl    time.Time     // The read deadline.
	dlSig chan struct{} // Closed at each change of dl.

	done      chan struct{}
	closeOnce sync.Once
}

func newChanConn(b chanNet, relay *psp.Peer, f flow, rx *proc.Mailbox) *chanConn {
	return &chanConn{
		b: b, relay: relay, rx: rx,
		local:  net.UDPAddrFromAddrPort(netip.AddrPortFrom(f.own, psp.ChannelPort)),
		remote: net.UDPAddrFromAddrPort(netip.AddrPortFrom(f.peer, psp.ChannelPort)),
		src:    tcpip.AddrFrom16(f.own.As16()), dst: tcpip.AddrFrom16(f.peer.As16()),
		dlSig: make(chan struct{}), done: make(chan struct{}),
	}
}

// ReadFrom gives the next channel packet. Only one goroutine reads.
func (c *chanConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if len(c.q) > 0 {
			m := c.q[0].(chanPkt)
			c.q[0] = nil
			c.q = c.q[1:]
			return copy(p, m.data), c.remote, nil
		}
		c.mu.Lock()
		dl, sig := c.dl, c.dlSig
		c.mu.Unlock()
		var expire <-chan time.Time
		var t *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, errTimeout{}
			}
			t = time.NewTimer(d)
			expire = t.C
		}
		select {
		case <-c.done:
			stopTimer(t)
			return 0, nil, net.ErrClosed
		case <-c.rx.Wake():
			c.q = c.rx.Take()
		case <-sig:
		case <-expire:
		}
		stopTimer(t)
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// WriteTo sends p to the peer end. A packet that the binding cannot send drops, as on a socket.
func (c *chanConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	pkt, err := chanPacket(c.src, c.dst, p)
	if err != nil {
		return 0, err
	}
	if c.routed.Load() {
		_, _ = c.b.Send([][]byte{pkt})
	} else {
		_ = c.b.SendVia(c.relay, pkt, netip.AddrPort{})
	}
	return len(p), nil
}

// chanPacket returns p as the UDP payload of an inner IPv6 packet from port ChannelPort at src to
// port ChannelPort at dst.
func chanPacket(src, dst tcpip.Address, p []byte) ([]byte, error) {
	n := udpHdr + len(p)
	if header.IPv6MinimumSize+n > psp.MaxMTU {
		return nil, errors.New("channel packet is too large")
	}
	pkt := make([]byte, header.IPv6MinimumSize+n)
	header.IPv6(pkt).Encode(&header.IPv6Fields{
		PayloadLength: uint16(n), TransportProtocol: header.UDPProtocolNumber, HopLimit: 64,
		SrcAddr: src, DstAddr: dst,
	})
	u := header.UDP(pkt[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: psp.ChannelPort, DstPort: psp.ChannelPort, Length: uint16(n)})
	copy(u[udpHdr:], p)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(n))
	u.SetChecksum(^u.CalculateChecksum(checksum.Checksum(p, xsum)))
	return pkt, nil
}

func (c *chanConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *chanConn) LocalAddr() net.Addr { return c.local }

func (c *chanConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *chanConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dl = t
	close(c.dlSig)
	c.dlSig = make(chan struct{})
	return nil
}

func (c *chanConn) SetWriteDeadline(time.Time) error { return nil }
