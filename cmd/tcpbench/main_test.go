package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
)

// tcpPacket returns an IPv4 TCP packet with payload bytes of data.
func tcpPacket(srcPort uint16, seq uint32, payload int) []byte {
	size := header.IPv4MinimumSize + header.TCPMinimumSize + payload
	b := make([]byte, size)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(agentInner.As4()),
		DstAddr:     tcpip.AddrFrom4(relayInner.As4()),
	})
	header.TCP(b[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    sinkPort,
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
	})
	return b
}

func TestSegCounter(t *testing.T) {
	type seg struct {
		port    uint16
		seq     uint32
		payload int
	}
	cases := []struct {
		name        string
		segs        []seg
		wantSegs    uint64
		wantRetrans uint64
	}{
		{name: "in order", segs: []seg{{1, 0, 100}, {1, 100, 100}, {1, 200, 100}}, wantSegs: 3},
		{name: "hole repaired", segs: []seg{{1, 0, 100}, {1, 200, 100}, {1, 100, 100}}, wantSegs: 3, wantRetrans: 1},
		{name: "duplicate", segs: []seg{{1, 0, 100}, {1, 0, 100}}, wantSegs: 2, wantRetrans: 1},
		{name: "pure ACK", segs: []seg{{1, 0, 100}, {1, 100, 0}}, wantSegs: 1},
		{name: "two flows", segs: []seg{{1, 500, 100}, {2, 0, 100}, {2, 100, 100}}, wantSegs: 3},
		{name: "sequence wrap", segs: []seg{{1, 0xffffff00, 0x80}, {1, 0xffffff80, 0x100}, {1, 0xffffff80, 0x80}}, wantSegs: 3, wantRetrans: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newSegCounter(nil)
			for _, s := range tc.segs {
				c.count(tcpPacket(s.port, s.seq, s.payload))
			}
			if got := c.segments.Load(); got != tc.wantSegs {
				t.Errorf("segments = %d, want %d", got, tc.wantSegs)
			}
			if got := c.retrans.Load(); got != tc.wantRetrans {
				t.Errorf("retransmits = %d, want %d", got, tc.wantRetrans)
			}
		})
	}
}

func TestSegCounterIgnoresOtherPackets(t *testing.T) {
	c := newSegCounter(nil)
	udp := tcpPacket(1, 0, 100)
	header.IPv4(udp).Encode(&header.IPv4Fields{TotalLength: uint16(len(udp)), Protocol: uint8(header.UDPProtocolNumber)})
	for _, pkt := range [][]byte{nil, {0x60}, udp, tcpPacket(1, 0, 100)[:30]} {
		c.count(pkt)
	}
	if c.segments.Load() != 0 {
		t.Fatalf("counted %d segments in packets that are not TCP data", c.segments.Load())
	}
}

// freeUDPPort returns a free local UDP port.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func TestRun(t *testing.T) {
	defer func(cc string) { netstack.TCPCongestionControl = cc }(netstack.TCPCongestionControl)
	for _, cc := range []string{"bbr", "cubic"} {
		t.Run(cc, func(t *testing.T) {
			lo := netip.MustParseAddr("127.0.0.1")
			agentAddr := netip.AddrPortFrom(lo, freeUDPPort(t))
			relayAddr := netip.AddrPortFrom(lo, freeUDPPort(t))
			mtu := icx.MTU(api.TunnelPathMTU)
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			relayDone := make(chan error, 1)
			go func() {
				_, err := runRelay(ctx, relayOptions{Local: relayAddr, Peer: agentAddr, MTU: mtu}, ln)
				relayDone <- err
			}()
			res, err := runAgent(ctx, agentOptions{
				Local: agentAddr, Peer: relayAddr, Ctl: ln.Addr().String(), CC: cc, Streams: 2, MTU: mtu,
				Idle: 200 * time.Millisecond, Omit: 300 * time.Millisecond, Duration: 700 * time.Millisecond,
				ProbeInterval: 10 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("agent: %v", err)
			}
			if err := <-relayDone; err != nil {
				t.Fatalf("relay: %v", err)
			}
			if res.CC != cc || res.BitsPerSecond <= 0 || res.PacketsPerSecond <= 0 {
				t.Fatalf("bad result: %+v", res)
			}
			if res.IdleRTT.Probes == 0 || res.IdleRTT.Lost == res.IdleRTT.Probes || res.LoadRTT.P50 <= 0 {
				t.Fatalf("no RTT probe echoes: %+v", res)
			}
			t.Logf("%s: %.2f Gbps, retrans %.2f%%, idle RTT p50 %.2f ms, load RTT p50 %.2f ms p99 %.2f ms",
				cc, res.BitsPerSecond/1e9, res.RetransPercent, res.IdleRTT.P50, res.LoadRTT.P50, res.LoadRTT.P99)
		})
	}
}

func BenchmarkSegCounter(b *testing.B) {
	c := newSegCounter(nil)
	pkt := tcpPacket(1, 0, 1380)
	seg := header.TCP(pkt[header.IPv4MinimumSize:])
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		seg.SetSequenceNumber(uint32(i) * 1380)
		c.count(pkt)
	}
}
