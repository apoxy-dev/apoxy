// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// openImpair opens the impair map with no entries, and clears it after the test. It needs bpffs at
// /sys/fs/bpf.
func openImpair(t *testing.T) *dp.Impair {
	t.Helper()
	im, err := dp.OpenImpair()
	require.NoError(t, err)
	require.NoError(t, im.Clear())
	t.Cleanup(func() {
		assert.NoError(t, im.Clear())
		im.Close()
	})
	return im
}

var payloadSeq atomic.Uint64

// sendTime sends a datagram from the relay port to the peer socket c at to, and returns the time
// until c gets it.
func (e *env) sendTime(t *testing.T, c *net.UDPConn, port uint16, to netip.AddrPort) time.Duration {
	t.Helper()
	payload := fmt.Appendf(nil, "impair %d", payloadSeq.Add(1))
	start := time.Now()
	switch port {
	case 443:
		_, err := e.d.PacketConn().WriteTo(payload, net.UDPAddrFromAddrPort(to))
		require.NoError(t, err)
	case dp.PortData:
		po := &p4.PacketOut{Payload: payload, Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: to}.Metadata()}
		require.NoError(t, e.d.Target().PacketOut(po))
	}
	require.NoError(t, c.SetReadDeadline(start.Add(3*time.Second)))
	buf := make([]byte, 64)
	for {
		n, _, err := c.ReadFromUDPAddrPort(buf)
		require.NoError(t, err, "no datagram from port %d", port)
		if bytes.Equal(buf[:n], payload) {
			return time.Since(start)
		}
	}
}

// reach sends from the relay to the peer socket c at to until c gets a datagram, so that the relay
// knows the next-hop MAC.
func (e *env) reach(t *testing.T, c *net.UDPConn, to netip.AddrPort) {
	t.Helper()
	raw := &p4.PacketOut{Payload: []byte("reach"), Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: to}.Metadata()}
	buf := make([]byte, 64)
	for range 40 {
		require.NoError(t, e.d.Target().PacketOut(raw))
		require.NoError(t, c.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
		if _, _, err := c.ReadFromUDPAddrPort(buf); err == nil {
			return
		}
	}
	t.Fatalf("no datagram to %s", to)
}

func TestImpair(t *testing.T) {
	e := newEnv(t, 1)
	im := openImpair(t)

	from4 := netip.AddrPortFrom(peer4.Addr(), 7101)
	from6 := netip.AddrPortFrom(peer6.Addr(), 7101)
	c4, c6 := e.listen(t, from4), e.listen(t, from6)
	e.reach(t, c4, from4)
	e.reach(t, c6, from6)

	const probes = 5
	probeKey := [32]byte{1}
	probe := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{9}, Counter: 1}, 0, &probeKey)
	const delay = 300 * time.Millisecond

	cases := []struct {
		name string
		set  []dp.Impairment
		// punts is the number of probes of each peer to port 1000 that reach the pipeline.
		punts map[netip.AddrPort]int
		// held is the least time of a send from each relay port to peer4. A send to peer6 takes
		// less than delay.
		held time.Duration
		// show is the result of Show after the probes.
		show []dp.Impairment
	}{
		{
			name:  "an empty map changes nothing",
			punts: map[netip.AddrPort]int{from4: probes, from6: probes},
		},
		{
			name:  "a drop of 1 cuts a peer and counts its packets",
			set:   []dp.Impairment{{Port: dp.PortData, Peer: netip.PrefixFrom(peer4.Addr(), 32), Drop: 1}},
			punts: map[netip.AddrPort]int{from4: 0, from6: probes},
			show:  []dp.Impairment{{Port: dp.PortData, Peer: netip.PrefixFrom(peer4.Addr(), 32), Drop: 1, Dropped: probes}},
		},
		{
			name:  "a /0 entry matches all peers on its port",
			set:   []dp.Impairment{{Port: dp.PortData, Peer: netip.MustParsePrefix("::/0"), Drop: 1}},
			punts: map[netip.AddrPort]int{from4: 0, from6: 0},
			show:  []dp.Impairment{{Port: dp.PortData, Peer: netip.MustParsePrefix("::/0"), Drop: 1, Dropped: 2 * probes}},
		},
		{
			name: "a delay holds a send for at least the delay",
			set: []dp.Impairment{
				{Port: 443, Peer: netip.PrefixFrom(peer4.Addr(), 32), Delay: delay},
				{Port: dp.PortData, Peer: peer4.Masked(), Delay: delay},
			},
			punts: map[netip.AddrPort]int{from4: probes, from6: probes},
			held:  delay,
			show: []dp.Impairment{
				{Port: 443, Peer: netip.PrefixFrom(peer4.Addr(), 32), Delay: delay},
				{Port: dp.PortData, Peer: peer4.Masked(), Delay: delay},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, im.Clear())
			for _, s := range tc.set {
				require.NoError(t, im.Set(s.Port, s.Peer, s.Drop, s.Delay, s.Jitter))
			}

			for range probes {
				_, err := c4.WriteToUDPAddrPort(probe, netip.AddrPortFrom(relay4.Addr(), dp.PortData))
				require.NoError(t, err)
				_, err = c6.WriteToUDPAddrPort(probe, netip.AddrPortFrom(relay6.Addr(), dp.PortData))
				require.NoError(t, err)
			}
			punts := map[netip.AddrPort]int{from4: 0, from6: 0}
			end := time.After(time.Second)
		collect:
			for {
				select {
				case p := <-e.packets:
					md, err := dp.DecodePacketInMeta(p.GetMetadata())
					require.NoError(t, err)
					if md.Kind == dp.KindPunt {
						punts[md.From]++
					}
				case <-end:
					break collect
				}
			}
			assert.Equal(t, tc.punts, punts, "probes that reach the pipeline")

			// No entry is on port 443 for a receive.
			_, err := c4.WriteToUDPAddrPort([]byte("quic"), netip.AddrPortFrom(relay4.Addr(), 443))
			require.NoError(t, err)
			require.NoError(t, e.d.PacketConn().SetReadDeadline(time.Now().Add(3*time.Second)))
			buf := make([]byte, 64)
			n, _, err := e.d.PacketConn().ReadFrom(buf)
			require.NoError(t, err, "no datagram on port 443")
			assert.Equal(t, "quic", string(buf[:n]))

			for _, port := range []uint16{443, dp.PortData} {
				if tc.held > 0 {
					// The device reads the map each second.
					for deadline := time.Now().Add(5 * time.Second); e.sendTime(t, c4, port, from4) < tc.held; {
						require.True(t, time.Now().Before(deadline), "a send from port %d is not held", port)
					}
					assert.GreaterOrEqual(t, e.sendTime(t, c4, port, from4), tc.held, "port %d", port)
				} else {
					assert.Less(t, e.sendTime(t, c4, port, from4), delay, "port %d", port)
				}
				assert.Less(t, e.sendTime(t, c6, port, from6), delay, "port %d to peer6", port)
			}

			got, err := im.Show()
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.show, got)
		})
	}
}

func TestImpairSet(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for bpffs")
	}
	im := openImpair(t)
	peer := netip.PrefixFrom(peer4.Addr(), 32)
	cases := []struct {
		name          string
		port          uint16
		peer          netip.Prefix
		drop          float64
		delay, jitter time.Duration
	}{
		{name: "a port that is not a relay port", port: 80, peer: peer},
		{name: "no peer prefix", port: dp.PortData},
		{name: "a drop above 1", port: dp.PortData, peer: peer, drop: 1.5},
		{name: "a drop below 0", port: dp.PortData, peer: peer, drop: -0.1},
		{name: "a drop that is not a number", port: dp.PortData, peer: peer, drop: math.NaN()},
		{name: "a negative delay", port: dp.PortData, peer: peer, delay: -time.Millisecond},
		{name: "a negative jitter", port: dp.PortData, peer: peer, jitter: -time.Millisecond},
		{name: "a delay that is too long", port: dp.PortData, peer: peer, delay: 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, im.Set(tc.port, tc.peer, tc.drop, tc.delay, tc.jitter))
			got, err := im.Show()
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}
