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

// TestPacketHandler checks that the relay forwards PSP packets by the SPI rows
// of the sender before the handler returns, and drops the others.
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
	handle := h.tr.NonQUICPacketHandler
	require.NotNil(t, handle)

	cases := []struct {
		name       string
		from       netip.AddrPort
		pkt        []byte
		wantSent   bool
		wantDrops  [2]uint64 // DropUnknownSPI of the sender and of the receiver.
		wantSource uint64    // Drops for an unknown source.
	}{
		{name: "unknown SPI", from: snd.src, pkt: pspPacket(t, 8, dst), wantDrops: [2]uint64{1, 0}},
		{name: "SPI of another sender", from: rcv.src, pkt: pspPacket(t, 7, dst), wantDrops: [2]uint64{0, 1}},
		{name: "unknown source", from: netip.MustParseAddrPort("192.0.2.1:9"), pkt: pspPacket(t, 7, dst), wantSource: 1},
		{name: "path probe", from: snd.src, pkt: []byte{0x02, 1, 2, 3}},
		{name: "good", from: snd.src, pkt: pspPacket(t, 7, dst), wantSent: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := [2]uint64{h.r.SenderStats(sndSession).DropUnknownSPI, h.r.SenderStats(rcvSession).DropUnknownSPI}
			source := h.r.UnknownSourceDrops()
			b := append([]byte{}, tc.pkt...)
			handle(b, net.UDPAddrFromAddrPort(tc.from))
			// The handler must not keep b.
			clear(b)
			after := [2]uint64{h.r.SenderStats(sndSession).DropUnknownSPI, h.r.SenderStats(rcvSession).DropUnknownSPI}
			assert.Equal(t, tc.wantDrops, [2]uint64{after[0] - before[0], after[1] - before[1]})
			assert.Equal(t, tc.wantSource, h.r.UnknownSourceDrops()-source)
			if !tc.wantSent {
				return
			}
			buf := make([]byte, 1500)
			n, from, err := rcv.tr.ReadNonQUICPacket(ctx, buf)
			require.NoError(t, err)
			assert.Equal(t, tc.pkt, buf[:n])
			assert.Equal(t, h.ln.Addr().String(), from.String())
		})
	}
	st := h.r.SenderStats(sndSession)
	require.Len(t, st.Lanes, 1)
	assert.Equal(t, uint64(1), st.Lanes[0].Packets)

	// A packet on the relay socket goes through the same handler.
	good := pspPacket(t, 7, dst)
	_, err = snd.tr.WriteTo(good, h.ln.Addr())
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, _, err := rcv.tr.ReadNonQUICPacket(ctx, buf)
	require.NoError(t, err)
	assert.Equal(t, good, buf[:n])
}
