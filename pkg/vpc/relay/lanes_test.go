// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestLaneKeepalive checks that the relay sends a lane to its lane port only after a keepalive
// from that port, when the agent reads the lane ports. New lane ports need a new keepalive.
func TestLaneKeepalive(t *testing.T) {
	cases := []struct {
		name    string
		receive bool
	}{
		{name: "the agent reads the lane ports", receive: true},
		{name: "the agent does not read the lane ports", receive: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			a := e.dial(t, "agent-a")
			a.open(dpv1.Mode_MODE_PSP)
			resA := a.attach()
			b := e.dial(t, "agent-b")
			b.open(dpv1.Mode_MODE_QUIC)
			resB := b.attach()
			sock := pspSocket(t)
			a.toPSP(e, sock, 1)
			a.keepPath(e, sock)

			// Agent SAs for lanes 1 to 3: the SPI of lane i is the lane 0 SPI + i.
			req := &dpv1.KeysRequest{Op: &dpv1.KeysRequest_Offer{Offer: &dpv1.OfferSAs{}}, Generation: 2}
			for lane := uint32(1); lane <= 3; lane++ {
				key := make([]byte, 16)
				_, _ = rand.Read(key)
				req.GetOffer().Sas = append(req.GetOffer().Sas, &dpv1.SA{
					Spi: a.rxSPI + lane, Key: key, Vni: netID, ExpiresIn: durationpb.New(time.Hour), Lane: lane,
				})
			}
			res, err := a.rc.Rekey(t.Context(), req)
			require.NoError(t, err)
			require.Empty(t, res.GetRefusedSpis())

			lanes := []*net.UDPConn{pspSocket(t), pspSocket(t), pspSocket(t)}
			register := func() {
				reg := &dpv1.RegisterLanesRequest{Receive: tc.receive}
				for _, l := range lanes {
					reg.Ports = append(reg.Ports, uint32(l.LocalAddr().(*net.UDPAddr).Port))
				}
				_, err := a.rc.RegisterLanes(t.Context(), reg)
				require.NoError(t, err)
			}
			// send sends packets of new flows from b to a. got returns the SPIs that each socket
			// got: the session socket first, then the lane sockets.
			send := func() {
				for range 64 {
					b.sendFrame(packet(addr(t, resB), addr(t, resA), 200))
				}
			}
			got := func() []map[uint32]int {
				out := []map[uint32]int{readSPIs(t, sock, 300*time.Millisecond)}
				for _, l := range lanes {
					out = append(out, readSPIs(t, l, 50*time.Millisecond))
				}
				return out
			}
			lane1 := a.rxSPI + 1
			allOnSession := func(step string) {
				send()
				g := got()
				assert.Positive(t, g[0][lane1], "%s: lane 1 on the session port", step)
				assert.Len(t, g[0], 4, "%s: all lanes on the session port", step)
				for i := 1; i <= 3; i++ {
					assert.Empty(t, g[i], "%s: lane port %d", step, i)
				}
			}

			register()
			allOnSession("before a keepalive")

			_, err = lanes[0].WriteToUDP([]byte{p2p.TypeKeepalive}, e.data)
			require.NoError(t, err)
			if !tc.receive {
				time.Sleep(300 * time.Millisecond)
				allOnSession("after a keepalive")
				return
			}
			require.Eventually(t, func() bool {
				send()
				return got()[1][lane1] > 0
			}, wait, 100*time.Millisecond, "lane 1 did not move to its lane port")
			send()
			g := got()
			assert.Equal(t, map[uint32]int{lane1: g[1][lane1]}, g[1], "lane port 1 gets lane 1 only")
			assert.Zero(t, g[0][lane1], "lane 1 on the session port")
			assert.Len(t, g[0], 3, "lanes 0, 2 and 3 on the session port")
			assert.Empty(t, g[2], "lane port 2 had no keepalive")
			assert.Empty(t, g[3], "lane port 3 had no keepalive")

			register()
			allOnSession("after new lane ports")
		})
	}
}

// readSPIs reads the PSP packets on sock until none comes in d, and counts them by SPI. It skips
// the probes of the relay.
func readSPIs(t *testing.T, sock *net.UDPConn, d time.Duration) map[uint32]int {
	t.Helper()
	out := map[uint32]int{}
	buf := make([]byte, 2048)
	for {
		require.NoError(t, sock.SetReadDeadline(time.Now().Add(d)))
		n, err := sock.Read(buf)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return out
		}
		require.NoError(t, err)
		if n > 0 && buf[0] == p2p.TypeProbe {
			continue
		}
		h, err := psp.ParseHeader(buf[:n])
		require.NoError(t, err)
		out[h.SPI]++
	}
}
