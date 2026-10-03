// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// pspPacket seals an IPv6 packet to dst with SPI spi and a random key.
func pspPacket(t *testing.T, spi uint32, dst netip.Addr) []byte {
	t.Helper()
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	aead, err := pspwire.NewAEAD(key)
	require.NoError(t, err)
	inner := make([]byte, 48)
	inner[0] = 0x60
	copy(inner[24:40], dst.AsSlice())
	out := make([]byte, len(inner)+pspwire.Overhead)
	n, err := pspwire.Seal(aead, pspwire.Header{SPI: spi, VNI: 0x0a0b0c}, out, inner)
	require.NoError(t, err)
	return out[:n]
}

// geneve returns a Geneve packet with optWords words of options and an IPv6
// payload of n bytes.
func geneve(optWords, n int) []byte {
	b := make([]byte, 8+4*optWords+n)
	b[0] = byte(optWords)
	b[2], b[3] = 0x86, 0xdd
	b[4], b[5], b[6] = 0x0a, 0x0b, 0x0c
	b[8+4*optWords] = 0x60
	return b
}

// TestPacketHandler sends packets to the relay socket, and checks that the
// relay forwards PSP packets by the SPI rows of the sender and drops the
// others. Only the read loop of the relay transport calls the handler.
func TestPacketHandler(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	snd := h.mustDial(t, ca.agentCert(t, vpcA, "sender"))
	rcv := h.mustDial(t, ca.agentCert(t, vpcA, "receiver"))
	res := attach(t, rcv, &dp.AttachRequest{Vpc: ref(vpcA), Name: "receiver"})
	claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
	require.NoError(t, err)
	dst := netip.MustParsePrefix(claims.Addresses[0]).Addr().Next()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = snd.c.RegisterSPI(ctx, register(vpcA, dst.String(), time.Minute, 7))
	require.NoError(t, err)
	sndSession, rcvSession := h.session(t, snd), h.session(t, rcv)
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer other.Close()

	cases := []struct {
		name       string
		from       func(b []byte, addr net.Addr) (int, error)
		pkt        []byte
		wantSent   bool
		wantDrops  [2]uint64 // DropUnknownSPI of the sender and of the receiver.
		wantSource uint64    // Drops for an unknown source.
		wantBad    uint64    // Drops of packets that are not PSP.
	}{
		{name: "unknown SPI", from: snd.tr.WriteTo, pkt: pspPacket(t, 8, dst), wantDrops: [2]uint64{1, 0}},
		{name: "SPI of another sender", from: rcv.tr.WriteTo, pkt: pspPacket(t, 7, dst), wantDrops: [2]uint64{0, 1}},
		{name: "unknown source", from: other.WriteTo, pkt: pspPacket(t, 7, dst), wantSource: 1},
		{name: "path probe", from: snd.tr.WriteTo, pkt: []byte{0x02, 1, 2, 3}, wantBad: 1},
		{name: "Geneve", from: snd.tr.WriteTo, pkt: geneve(0, 64), wantBad: 1},
		{name: "Geneve with options", from: snd.tr.WriteTo, pkt: geneve(4, 64), wantBad: 1},
		{name: "good", from: snd.tr.WriteTo, pkt: pspPacket(t, 7, dst), wantSent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drops := func() [2]uint64 {
				return [2]uint64{h.r.SenderStats(sndSession).DropUnknownSPI, h.r.SenderStats(rcvSession).DropUnknownSPI}
			}
			before, source, bad := drops(), h.r.UnknownSourceDrops(), h.r.MalformedDrops()
			changed := func() ([2]uint64, uint64, uint64) {
				d := drops()
				return [2]uint64{d[0] - before[0], d[1] - before[1]}, h.r.UnknownSourceDrops() - source, h.r.MalformedDrops() - bad
			}
			_, err := tc.from(tc.pkt, h.ln.Addr())
			require.NoError(t, err)
			if tc.wantSent {
				buf := make([]byte, 1500)
				n, from, err := rcv.tr.ReadNonQUICPacket(ctx, buf)
				require.NoError(t, err)
				assert.Equal(t, tc.pkt, buf[:n])
				assert.Equal(t, h.ln.Addr().String(), from.String())
			} else {
				require.Eventually(t, func() bool {
					d, s, b := changed()
					return d != [2]uint64{} || s != 0 || b != 0
				}, 5*time.Second, time.Millisecond, "the relay did not count the packet")
			}
			d, s, b := changed()
			assert.Equal(t, tc.wantDrops, d)
			assert.Equal(t, tc.wantSource, s)
			assert.Equal(t, tc.wantBad, b)
		})
	}
	st := h.r.SenderStats(sndSession)
	require.Len(t, st.Lanes, 1)
	assert.Equal(t, uint64(1), st.Lanes[0].Packets)
}

// TestAddrCache checks that the cache gives the address of each destination.
func TestAddrCache(t *testing.T) {
	var c addrCache
	cases := []string{"192.0.2.1:1", "192.0.2.1:2", "[fd00::1]:1", "[::ffff:192.0.2.1]:1", "192.0.2.1:1"}
	for _, a := range cases {
		ap := netip.MustParseAddrPort(a)
		u := c.get(ap)
		assert.Equal(t, ap, u.AddrPort(), a)
		assert.Same(t, u, c.get(ap), "%s second get", a)
	}
}

// BenchmarkPacketHandler measures one PSP packet that the relay forwards by
// the SPI row of its sender.
func BenchmarkPacketHandler(b *testing.B) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{name: "no limits"},
		{name: "lane limit", cfg: Config{LaneRate: 1 << 40}},
		{name: "tunnel limit", cfg: Config{TunnelRate: 1 << 40}},
		{name: "lane and tunnel limits", cfg: Config{LaneRate: 1 << 40, TunnelRate: 1 << 40}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			r, handle := localRouterConfig(b, tc.cfg)
			s := localSession(b, r, "s", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_PSP)
			localSession(b, r, "d", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_PSP)
			require.NoError(b, r.registerSPI(s, register(vpcA, "fd00:2::1", time.Hour, 7), time.Now()))
			aead, err := pspwire.NewAEAD(make([]byte, 16))
			require.NoError(b, err)
			inner := ipPacket(netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:2::1"), make([]byte, 1200))
			pkt := make([]byte, len(inner)+pspwire.Overhead)
			n, err := pspwire.Seal(aead, pspwire.Header{SPI: 7, VNI: testVNI}, pkt, inner)
			require.NoError(b, err)
			from := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:1"))
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				handle(pkt[:n], from)
			}
			b.StopTimer()
			st := r.SenderStats(s)
			require.Len(b, st.Lanes, 1)
			require.Positive(b, st.Lanes[0].Packets)
			require.Zero(b, st.DropUnknownSPI)
			require.Zero(b, st.DropTunnelLimit)
		})
	}
}
