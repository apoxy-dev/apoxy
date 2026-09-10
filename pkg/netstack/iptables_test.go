package netstack

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func mustAddr(s string) tcpip.Address {
	return tcpip.AddrFromSlice(netip.MustParseAddr(s).AsSlice())
}

// newUDPPacket builds a UDP packet. The caller must release it.
func newUDPPacket(
	t *testing.T,
	proto tcpip.NetworkProtocolNumber,
	src, dst tcpip.Address,
) *stack.PacketBuffer {
	t.Helper()

	const payloadLen = 4
	netHdrLen := header.IPv6MinimumSize
	if proto == header.IPv4ProtocolNumber {
		netHdrLen = header.IPv4MinimumSize
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: netHdrLen + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(make([]byte, payloadLen)),
	})
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	pkt.NetworkProtocolNumber = proto

	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.Encode(&header.UDPFields{
		SrcPort: 12345,
		DstPort: 53,
		Length:  header.UDPMinimumSize + payloadLen,
	})

	switch proto {
	case header.IPv6ProtocolNumber:
		ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     header.UDPMinimumSize + payloadLen,
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           src,
			DstAddr:           dst,
		})
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + header.UDPMinimumSize + payloadLen),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     src,
			DstAddr:     dst,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	default:
		panic(fmt.Sprintf("unsupported network protocol %d", proto))
	}

	return pkt
}

func TestRandSNATTargetAddDel(t *testing.T) {
	a := mustAddr("fd00::1")
	b := mustAddr("fd00::2")
	c := mustAddr("fd00::3")

	cases := []struct {
		name string
		add  []tcpip.Address
		del  []tcpip.Address
		want []tcpip.Address
	}{
		{name: "empty by default"},
		{name: "add is idempotent", add: []tcpip.Address{a, a, b}, want: []tcpip.Address{a, b}},
		{name: "del removes only the named address", add: []tcpip.Address{a, b, c}, del: []tcpip.Address{b}, want: []tcpip.Address{a, c}},
		{name: "del of an absent address is a no-op", add: []tcpip.Address{a}, del: []tcpip.Address{b}, want: []tcpip.Address{a}},
		{name: "del of every address empties the set", add: []tcpip.Address{a, b}, del: []tcpip.Address{a, b}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := &randSNATTarget{networkProtocol: header.IPv6ProtocolNumber}
			for _, addr := range tc.add {
				target.add(addr)
			}
			for _, addr := range tc.del {
				target.del(addr)
			}
			require.ElementsMatch(t, tc.want, target.addrs)
		})
	}
}

func TestRandSNATTargetPick(t *testing.T) {
	v6 := []tcpip.Address{mustAddr("fd00::1"), mustAddr("fd00::2"), mustAddr("fd00::3")}
	v4 := []tcpip.Address{mustAddr("10.0.0.1"), mustAddr("10.0.0.2")}

	cases := []struct {
		name  string
		addrs []tcpip.Address
		src   tcpip.Address
		// wantKept means the source is returned unchanged. Otherwise the
		// pick must be a member of addrs.
		wantKept bool
		wantOK   bool
	}{
		{name: "empty set drops", src: mustAddr("fd00::9")},
		{name: "source in set is kept", addrs: v6, src: v6[1], wantKept: true, wantOK: true},
		{name: "only address in set is kept", addrs: v6[:1], src: v6[0], wantKept: true, wantOK: true},
		{name: "foreign source is rewritten", addrs: v6, src: mustAddr("fd00::9"), wantOK: true},
		{name: "unspecified source is rewritten", addrs: v6, src: tcpip.Address{}, wantOK: true},
		{name: "v4 source in set is kept", addrs: v4, src: v4[0], wantKept: true, wantOK: true},
		{name: "v4 foreign source is rewritten", addrs: v4, src: mustAddr("10.0.0.9"), wantOK: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := &randSNATTarget{addrs: tc.addrs}
			// Repeat so that a random pick cannot hide a wrong answer.
			for i := 0; i < 64; i++ {
				addr, ok := target.pick(tc.src)
				require.Equal(t, tc.wantOK, ok)
				if !ok {
					continue
				}
				if tc.wantKept {
					require.True(t, addr.Equal(tc.src), "source %s changed to %s", tc.src, addr)
				} else {
					require.True(t, slices.ContainsFunc(tc.addrs, addr.Equal), "picked %s which is not in the set", addr)
				}
			}
		})
	}
}

// TestRandSNATTargetAction covers the packet path: a bound source stays, and
// an empty set drops.
func TestRandSNATTargetAction(t *testing.T) {
	cases := []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
		addrs []tcpip.Address
		dst   tcpip.Address
	}{
		{
			name:  "ipv6",
			proto: header.IPv6ProtocolNumber,
			addrs: []tcpip.Address{mustAddr("fd00::1"), mustAddr("fd00::2")},
			dst:   mustAddr("fd00::ff"),
		},
		{
			name:  "ipv4",
			proto: header.IPv4ProtocolNumber,
			addrs: []tcpip.Address{mustAddr("10.0.0.1"), mustAddr("10.0.0.2")},
			dst:   mustAddr("10.0.0.255"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := &randSNATTarget{networkProtocol: tc.proto}
			pkt := newUDPPacket(t, tc.proto, tc.addrs[0], tc.dst)
			verdict, _ := target.Action(pkt, stack.Postrouting, nil, nil)
			require.Equal(t, stack.RuleDrop, verdict)
			pkt.DecRef()

			for _, addr := range tc.addrs {
				target.add(addr)
			}
			for _, src := range tc.addrs {
				for i := 0; i < 32; i++ {
					pkt := newUDPPacket(t, tc.proto, src, tc.dst)
					verdict, _ := target.Action(pkt, stack.Postrouting, nil, nil)
					require.Equal(t, stack.RuleAccept, verdict)
					require.True(t, pkt.Network().SourceAddress().Equal(src),
						"source changed from %s to %s", src, pkt.Network().SourceAddress())
					pkt.DecRef()
				}
			}
		})
	}
}

// TestRandSNATTargetConcurrentUpdates runs add/del against the packet path.
// It is meant to be run under -race.
func TestRandSNATTargetConcurrentUpdates(t *testing.T) {
	target := &randSNATTarget{networkProtocol: header.IPv6ProtocolNumber}
	addrs := []tcpip.Address{mustAddr("fd00::1"), mustAddr("fd00::2"), mustAddr("fd00::3")}
	target.add(addrs[0])

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, addr := range addrs[1:] {
				target.add(addr)
			}
			for _, addr := range addrs[1:] {
				target.del(addr)
			}
		}
	}()

	src, dst := mustAddr("fd00::ee"), mustAddr("fd00::ff")
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				// The verdict is not checked: gvisor SNAT drops a packet
				// without a conntrack entry.
				pkt := newUDPPacket(t, header.IPv6ProtocolNumber, src, dst)
				target.Action(pkt, stack.Postrouting, nil, nil)
				pkt.DecRef()

				// t.Errorf, not require: FailNow must not run off the test goroutine.
				addr, ok := target.pick(src)
				if !ok || !slices.ContainsFunc(addrs, addr.Equal) {
					t.Errorf("picked %s ok=%v, which was never added", addr, ok)
					return
				}
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	close(done)
	wg.Wait()
}
