package conntrack

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

var (
	clientAddr = netip.MustParseAddr("fd61:706f:7879::10")
	serverAddr = netip.MustParseAddr("fd61:706f:7879::20")
)

const (
	syn    = connection.TCPFlagSYN
	synAck = connection.TCPFlagSYN | connection.TCPFlagACK
	ack    = connection.TCPFlagACK
	finAck = connection.TCPFlagFIN | connection.TCPFlagACK
	rst    = connection.TCPFlagRST
)

// pkt builds a TCP PacketInfo from src to dst with the given flags.
func pkt(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, flags connection.TCPFlags) connection.PacketInfo {
	return connection.PacketInfo{
		Protocol: connection.ProtocolTCP,
		SrcIP:    src,
		SrcPort:  srcPort,
		DstIP:    dst,
		DstPort:  dstPort,
		TCPFlags: flags,
	}
}

// fwd is a client->server packet on the standard test flow.
func fwd(flags connection.TCPFlags) connection.PacketInfo {
	return pkt(clientAddr, 40000, serverAddr, 443, flags)
}

// rev is a server->client packet on the standard test flow.
func rev(flags connection.TCPFlags) connection.PacketInfo {
	return pkt(serverAddr, 443, clientAddr, 40000, flags)
}

func TestTracker(t *testing.T) {
	cases := []struct {
		name    string
		packets []connection.PacketInfo
		want    int
	}{
		{
			name:    "handshake counts one flow not two",
			packets: []connection.PacketInfo{fwd(syn), rev(synAck), fwd(ack)},
			want:    1,
		},
		{
			name:    "retransmitted syn does not double count",
			packets: []connection.PacketInfo{fwd(syn), fwd(syn), rev(synAck), fwd(ack)},
			want:    1,
		},
		{
			name: "full close removes flow after both fins",
			packets: []connection.PacketInfo{
				fwd(syn), rev(synAck), fwd(ack),
				fwd(finAck), rev(ack), rev(finAck), fwd(ack),
			},
			want: 0,
		},
		{
			name: "server initiated close removes flow",
			packets: []connection.PacketInfo{
				fwd(syn), rev(synAck), fwd(ack),
				rev(finAck), fwd(ack), fwd(finAck), rev(ack),
			},
			want: 0,
		},
		{
			name:    "half close keeps flow active",
			packets: []connection.PacketInfo{fwd(syn), rev(synAck), fwd(ack), fwd(finAck)},
			want:    1,
		},
		{
			name:    "forward rst removes flow",
			packets: []connection.PacketInfo{fwd(syn), rev(synAck), fwd(rst)},
			want:    0,
		},
		{
			name:    "reverse rst removes flow",
			packets: []connection.PacketInfo{fwd(syn), rev(synAck), rev(rst)},
			want:    0,
		},
		{
			name:    "rst after half close removes flow",
			packets: []connection.PacketInfo{fwd(syn), rev(synAck), fwd(finAck), rev(rst)},
			want:    0,
		},
		{
			name:    "retransmitted syn-ack after close does not resurrect flow",
			packets: []connection.PacketInfo{fwd(syn), rev(synAck), fwd(rst), rev(synAck)},
			want:    0,
		},
		{
			name: "syn on reused tuple resets stale half-close state",
			// Old connection half-closes (client FIN only), then the same
			// 4-tuple is reused by a new connection. The new connection's
			// first FIN must NOT complete the stale half-close and delete
			// the live flow.
			packets: []connection.PacketInfo{
				fwd(syn), rev(synAck), fwd(finAck),
				fwd(syn), rev(synAck), fwd(ack),
				rev(finAck),
			},
			want: 1,
		},
		{
			name: "reused tuple closes cleanly after reset",
			packets: []connection.PacketInfo{
				fwd(syn), rev(synAck), fwd(finAck),
				fwd(syn), rev(synAck), fwd(ack),
				rev(finAck), fwd(finAck),
			},
			want: 0,
		},
		{
			name: "same ip tie-break maps both directions to one flow",
			// Src and dst IP are equal, so canonicalKey falls through to the
			// port tie-break. Both directions must land on the same entry:
			// one flow counted, and FINs from each side must fully close it.
			packets: []connection.PacketInfo{
				pkt(clientAddr, 1000, clientAddr, 2000, syn),
				pkt(clientAddr, 2000, clientAddr, 1000, synAck),
			},
			want: 1,
		},
		{
			name: "same ip tie-break full close removes flow",
			packets: []connection.PacketInfo{
				pkt(clientAddr, 1000, clientAddr, 2000, syn),
				pkt(clientAddr, 2000, clientAddr, 1000, synAck),
				pkt(clientAddr, 1000, clientAddr, 2000, finAck),
				pkt(clientAddr, 2000, clientAddr, 1000, finAck),
			},
			want: 0,
		},
		{
			name:    "fin for unknown flow is ignored",
			packets: []connection.PacketInfo{fwd(finAck), rev(finAck)},
			want:    0,
		},
		{
			name:    "rst for unknown flow is ignored",
			packets: []connection.PacketInfo{fwd(rst)},
			want:    0,
		},
		{
			name: "concurrent flows tracked independently",
			packets: []connection.PacketInfo{
				// Flow 1: opened.
				pkt(clientAddr, 40000, serverAddr, 443, syn),
				pkt(serverAddr, 443, clientAddr, 40000, synAck),
				// Flow 2: opened then fully closed.
				pkt(clientAddr, 40001, serverAddr, 443, syn),
				pkt(serverAddr, 443, clientAddr, 40001, synAck),
				pkt(clientAddr, 40001, serverAddr, 443, finAck),
				pkt(serverAddr, 443, clientAddr, 40001, finAck),
				// Flow 3: opened then reset.
				pkt(clientAddr, 40002, serverAddr, 443, syn),
				pkt(serverAddr, 443, clientAddr, 40002, rst),
			},
			want: 1,
		},
		{
			name: "same address pair distinct ports are distinct flows",
			packets: []connection.PacketInfo{
				pkt(clientAddr, 40000, serverAddr, 443, syn),
				pkt(clientAddr, 40001, serverAddr, 443, syn),
			},
			want: 2,
		},
		{
			name: "non tcp packets ignored",
			packets: []connection.PacketInfo{
				{Protocol: connection.ProtocolUDP, SrcIP: clientAddr, SrcPort: 40000, DstIP: serverAddr, DstPort: 443},
			},
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTracker()
			for _, p := range tc.packets {
				tr.OnPacket(p)
			}
			assert.Equal(t, tc.want, tr.ActiveCount())
		})
	}
}

// fakeClock is an adjustable clock source for liveness tests.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTracker() (*Tracker, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	tr := NewTracker()
	tr.now = clk.now
	return tr, clk
}

func TestTrackerIdleFlowsNotCounted(t *testing.T) {
	tr, clk := newTestTracker()

	// Flow established, then goes silent (e.g. tunnel died without FIN/RST).
	tr.OnPacket(fwd(syn))
	tr.OnPacket(rev(synAck))
	require.Equal(t, 1, tr.ActiveCount())

	clk.advance(activeWindow + time.Second)
	assert.Equal(t, 0, tr.ActiveCount(), "flow idle past activeWindow must not block drain")
}

func TestTrackerDataPacketsRefreshLiveness(t *testing.T) {
	tr, clk := newTestTracker()

	tr.OnPacket(fwd(syn))
	tr.OnPacket(rev(synAck))

	// Keep the flow busy with plain data/ACK packets past the idle window.
	for i := 0; i < 3; i++ {
		clk.advance(activeWindow / 2)
		tr.OnPacket(fwd(ack))
	}
	assert.Equal(t, 1, tr.ActiveCount(), "flow with recent data traffic must stay counted")
}

func TestTrackerSweepEvictsDeadFlows(t *testing.T) {
	tr, clk := newTestTracker()

	// A flow that dies silently: no FIN/RST is ever observed.
	tr.OnPacket(fwd(syn))
	tr.OnPacket(rev(synAck))
	require.Len(t, tr.flows, 1)

	// Long after eviction eligibility, traffic on an unrelated flow
	// triggers the amortized sweep.
	clk.advance(evictAfter + time.Second)
	tr.OnPacket(pkt(clientAddr, 50000, serverAddr, 443, syn))

	tr.mu.Lock()
	defer tr.mu.Unlock()
	assert.Len(t, tr.flows, 1, "dead flow must be evicted; only the new flow remains")
}

// TestTrackerLeakRegression replays many complete connection lifecycles and
// asserts the tracker returns to zero. The original implementation leaked
// two entries per connection (SYN-ACK created a reverse-direction flow and
// FINs were recorded against separate directional entries), which froze
// tunnelproxy drains at a huge ActiveCount (APO-922).
func TestTrackerLeakRegression(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 1000; i++ {
		port := uint16(30000 + i)
		tr.OnPacket(pkt(clientAddr, port, serverAddr, 443, syn))
		tr.OnPacket(pkt(serverAddr, 443, clientAddr, port, synAck))
		tr.OnPacket(pkt(clientAddr, port, serverAddr, 443, ack))
		tr.OnPacket(pkt(clientAddr, port, serverAddr, 443, finAck))
		tr.OnPacket(pkt(serverAddr, 443, clientAddr, port, finAck))
		tr.OnPacket(pkt(clientAddr, port, serverAddr, 443, ack))
	}
	assert.Equal(t, 0, tr.ActiveCount())
}
