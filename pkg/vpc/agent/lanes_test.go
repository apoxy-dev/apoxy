// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// laneRelay records the RegisterLanes and RegisterSPI calls.
type laneRelay struct {
	dp.RelayClient
	err error // Result of RegisterLanes.

	mu    sync.Mutex
	lanes [][]uint32 // Ports of each RegisterLanes call.
	spis  []*dp.RegisterSPIRequest
}

func (r *laneRelay) RegisterLanes(_ context.Context, in *dp.RegisterLanesRequest) (*emptypb.Empty, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lanes = append(r.lanes, in.GetPorts())
	return &emptypb.Empty{}, r.err
}

func (r *laneRelay) RegisterSPI(_ context.Context, in *dp.RegisterSPIRequest) (*emptypb.Empty, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spis = append(r.spis, in)
	return &emptypb.Empty{}, nil
}

func (r *laneRelay) calls() [][]uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]uint32(nil), r.lanes...)
}

// sessionStream records the messages that the agent sends on its Session call.
type sessionStream struct {
	rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]
	mu   sync.Mutex
	sent int
}

func (s *sessionStream) Send(*dp.SessionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent++
	return nil
}

// setTxLanes makes registerLanes see n queues on the link to the relay.
func setTxLanes(t *testing.T, n int) {
	old := txLanes
	txLanes = func(netip.Addr) int { return n }
	t.Cleanup(func() { txLanes = old })
}

func TestRegisterLanes(t *testing.T) {
	w := newWorld(t)
	natIP := func(l netip.AddrPort) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), l.Port())
	}
	natPort := func(l netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(l.Addr(), l.Port()+1) }
	cases := []struct {
		name      string
		maxLanes  uint32
		queues    int
		reflexive func(local netip.AddrPort) netip.AddrPort // Nil means local.
		err       error
		wantPorts int // Ports of the call. -1 means no call.
		wantLanes uint32
	}{
		{name: "relay takes the lane ports", maxLanes: 15, queues: 4, wantPorts: 3, wantLanes: 4},
		{name: "relay limit below the queues", maxLanes: 2, queues: 8, wantPorts: 2, wantLanes: 3},
		{name: "address translation with the same port", maxLanes: 15, queues: 4, reflexive: natIP, wantPorts: 3, wantLanes: 4},
		{name: "relay takes no lane ports", maxLanes: 0, queues: 4, wantPorts: -1, wantLanes: 1},
		{name: "one queue", maxLanes: 15, queues: 1, wantPorts: -1, wantLanes: 1},
		{name: "port translation", maxLanes: 15, queues: 4, reflexive: natPort, wantPorts: -1, wantLanes: 1},
		{name: "relay refuses", maxLanes: 15, queues: 4, err: rpc.Errorf(rpc.AlreadyExists, "taken"), wantPorts: 3, wantLanes: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTxLanes(t, tc.queues)
			a := w.stubAgent(t, "a")
			rc := a.rc
			r := &laneRelay{err: tc.err}
			rc.c, rc.maxLanes = r, tc.maxLanes
			rc.local = rc.localAddr()
			rc.reflexive = rc.local
			if tc.reflexive != nil {
				rc.reflexive = tc.reflexive(rc.local)
			}

			rc.registerLanes(context.Background(), a.bind)
			assert.Equal(t, tc.wantLanes, rc.sendLanes())
			calls := r.calls()
			if tc.wantPorts < 0 {
				assert.Empty(t, calls)
				return
			}
			require.Len(t, calls, 1)
			require.Len(t, calls[0], tc.wantPorts)
			// The ports are the lane sockets of the binding, in lane order.
			conns := a.bind.LaneConns()
			require.GreaterOrEqual(t, len(conns), tc.wantPorts)
			for i, p := range calls[0] {
				assert.Equal(t, uint32(conns[i].LocalAddr().(*net.UDPAddr).Port), p, "lane %d", i+1)
			}
		})
	}
}

// TestPeerLanes checks the SAs that an agent offers for the send lanes of the
// peer, and the lanes of its SPIs at the relay.
func TestPeerLanes(t *testing.T) {
	w := newWorld(t)
	cert := w.relayCA.relayCert(t, "relay-1")
	cases := []struct {
		name      string
		peerLanes uint32 // From Open.
		ourLanes  int32  // Send lanes of this agent at its relay.
		wantSAs   int
		saLanes   []int    // Lanes of the SAs from the peer.
		wantSPI   []uint32 // Lanes of RegisterSPI. Nil means none.
	}{
		{name: "old peer", peerLanes: 0, ourLanes: 1, wantSAs: 1, saLanes: []int{0}},
		{name: "peer with one lane", peerLanes: 1, ourLanes: 1, wantSAs: 1, saLanes: []int{0}},
		{name: "peer with 4 lanes", peerLanes: 4, ourLanes: 4, wantSAs: 4, saLanes: []int{0, 1, 2, 3}, wantSPI: []uint32{0, 1, 2, 3}},
		{name: "more lanes than SAs", peerLanes: 40, ourLanes: 1, wantSAs: keys.MaxLanes, saLanes: []int{0, 1}},
		{name: "lanes above our lane ports", peerLanes: 2, ourLanes: 2, wantSAs: 2, saLanes: []int{0, 1, 2, 3}, wantSPI: []uint32{0, 1, 0, 0}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			r := &laneRelay{}
			a.rc.c = r
			a.rc.lanes.Store(tc.ourLanes)
			p, _ := stubPeer(a, "b", false)
			require.NoError(t, a.admit(p, signGrant(t, cert, "b", fmt.Sprintf("fd00:b%d::/96", i)), 7, dp.Mode_MODE_PSP, tc.peerLanes))
			req, err := p.bp.Offer(time.Now())
			require.NoError(t, err)
			assert.Len(t, req.SAs, tc.wantSAs)

			var sas []keys.SA
			for j, l := range tc.saLanes {
				sas = append(sas, testSA(uint32(100+j), l))
			}
			require.NoError(t, p.register(context.Background(), sas))
			require.Len(t, r.spis, 1)
			assert.Equal(t, tc.wantSPI, r.spis[0].GetLanes())

			// A refresh registers the same lanes.
			p.refreshSPIs()
			require.Len(t, r.spis, 2)
			got := map[uint32]uint32{}
			for j, spi := range r.spis[1].GetSpis() {
				if l := r.spis[1].GetLanes(); l != nil {
					got[spi] = l[j]
				}
			}
			for j, spi := range r.spis[0].GetSpis() {
				if tc.wantSPI != nil {
					assert.Equal(t, tc.wantSPI[j], got[spi], "SPI %d", spi)
				}
			}
		})
	}
}

// TestMovedLanes checks that a move of the agent stops the lane sockets of its
// peers and removes the lane ports at the relay.
func TestMovedLanes(t *testing.T) {
	w := newWorld(t)
	cert := w.relayCA.relayCert(t, "relay-1")
	cases := []struct {
		name      string
		lanes     int32
		wantCalls int
	}{
		{"lanes", 4, 1},
		{"no lanes", 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			r, st := &laneRelay{}, &sessionStream{}
			a.rc.c, a.rc.st = r, st
			a.rc.lanes.Store(tc.lanes)
			p, _ := stubPeer(a, "b", false)
			require.NoError(t, a.admit(p, signGrant(t, cert, "b", "fd00:b::/96"), 7, dp.Mode_MODE_PSP, 4))
			require.Equal(t, int(tc.lanes)-1, p.bp.SendLane(int(tc.lanes)-1))

			a.checkMoved()
			assert.Equal(t, uint32(1), a.rc.sendLanes())
			assert.Equal(t, 0, p.bp.SendLane(int(tc.lanes)-1))
			require.Eventually(t, func() bool {
				st.mu.Lock()
				defer st.mu.Unlock()
				return st.sent == 1 && len(r.calls()) == tc.wantCalls
			}, 5*time.Second, 10*time.Millisecond, "Moved and the lane port removal")
			for _, c := range r.calls() {
				assert.Empty(t, c)
			}
		})
	}
}

// TestLanes sends UDP flows between two agents through a relay. When the relay
// takes lane ports, the flows use more than one lane socket.
func TestLanes(t *testing.T) {
	const flows = 32
	cases := []struct {
		name       string
		relayLanes int // Lane port limit of the relay.
		wantLanes  uint32
	}{
		{"relay takes lane ports", relay.MaxLaneSources, 4},
		{"relay takes no lane ports", 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTxLanes(t, 4)
			w := newWorld(t)
			w.relayCfg = relay.Config{LaneSources: tc.relayLanes}
			r := w.relay(t, "relay-1")
			a := w.agent(t, "a", r, agentOptions{mode: TransportPSP})
			b := w.agent(t, "b", r, agentOptions{mode: TransportPSP})
			ea, eb := a.attached(t), b.attached(t)
			assert.Equal(t, tc.wantLanes, a.current().sendLanes())
			assert.Equal(t, tc.wantLanes, b.current().sendLanes())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, a.a.Connect(ctx, eb.addr))
			echo(t, b.stack, eb.addr, 9000)
			ping(t, a.stack, ea.addr, eb.addr, 9000, "first")

			buf := make([]byte, 64)
			for i := range flows {
				c, err := gonet.DialUDP(a.stack, fullAddr(ea.addr, 0), fullAddr(eb.addr, 9000), ipv6.ProtocolNumber)
				require.NoError(t, err)
				got := false
				for range 10 {
					_, err := c.Write([]byte("flow"))
					require.NoError(t, err)
					_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					if _, err := c.Read(buf); err == nil {
						got = true
						break
					}
				}
				_ = c.Close()
				require.True(t, got, "flow %d", i)
			}
			lanes := a.binding().LanePackets()
			assert.Equal(t, tc.wantLanes > 1, len(lanes) > 1, "packets of each lane: %v", lanes)
			assert.Zero(t, r.r.UnknownSourceDrops())
		})
	}
}
