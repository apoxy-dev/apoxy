// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/steer"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// peerFrame returns the frame that an agent sends.
func peerFrame(dst, src netip.Addr, pkt string) []byte {
	return peerconn.EncodeToRelay(nil, dst, src, []byte(pkt))
}

func TestForwardDatagram(t *testing.T) {
	addr := netip.MustParseAddr
	cases := []struct {
		name   string
		frame  []byte
		permit Permit
		to     string // Session that gets the frame; empty if the relay drops it.
	}{
		{"to b", peerFrame(addr("fd00:2::1"), addr("fd00:1::1"), "hi"), nil, "b"},
		{"to an IPv4 route of b", peerFrame(addr("10.2.0.9"), addr("fd00:1::1"), "hi"), nil, "b"},
		{"empty packet", peerFrame(addr("fd00:2::1"), addr("fd00:1::1"), ""), nil, "b"},
		{"source of b", peerFrame(addr("fd00:2::1"), addr("fd00:2::1"), "hi"), nil, ""},
		{"source of no session", peerFrame(addr("fd00:2::1"), addr("fd00:9::1"), "hi"), nil, ""},
		{"no route", peerFrame(addr("fd00:9::1"), addr("fd00:1::1"), "hi"), nil, ""},
		{"route in another VPC", peerFrame(addr("fd00:3::1"), addr("fd00:1::1"), "hi"), nil, ""},
		{"Permit denies", peerFrame(addr("fd00:2::1"), addr("fd00:1::1"), "hi"),
			func(VPCKey, string, VPCKey, netip.Addr) bool { return false }, ""},
		{"other frame type", append([]byte{peerconn.TypeProbe}, peerFrame(addr("fd00:2::1"), addr("fd00:1::1"), "hi")[1:]...), nil, ""},
		{"short", peerFrame(addr("fd00:2::1"), addr("fd00:1::1"), "")[:peerconn.ToRelayLen-1], nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			got := map[string][][]byte{}
			sess := map[string]testSession{
				"a": addSession(t, r, vpcA, "a", "192.0.2.1:1", "fd00:1::/96"),
				"b": addSession(t, r, vpcA, "b", "192.0.2.2:1", "fd00:2::/96", "10.2.0.0/16"),
				"c": addSession(t, r, vpcB, "c", "192.0.2.3:1", "fd00:3::/96"),
			}
			for name, s := range sess {
				s.sendDatagram = func(b []byte) error {
					got[name] = append(got[name], append([]byte{}, b...))
					return nil
				}
			}
			if tc.permit != nil {
				r.SetPermit(tc.permit)
			}
			sent := r.forwardDatagram(sess["a"].Session, append([]byte{}, tc.frame...), t0)
			if tc.to == "" {
				assert.False(t, sent)
				assert.Empty(t, got)
				return
			}
			assert.True(t, sent)
			_, src, pkt, err := peerconn.DecodeToRelay(tc.frame)
			require.NoError(t, err)
			assert.Equal(t, map[string][][]byte{tc.to: {peerconn.EncodeFromRelay(nil, src, pkt)}}, got)
		})
	}
}

// TestDatagrams sends peer frames both ways between two agents.
func TestDatagrams(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	agents := []agent{h.mustDial(t, ca.agentCert(t, vpcA, "a")), h.mustDial(t, ca.agentCert(t, vpcA, "b"))}
	var addrs []netip.Addr
	for i, a := range agents {
		res := attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: string(rune('a' + i))})
		claims, err := VerifyGrant(res.Grant, h.relayRoots, time.Now())
		require.NoError(t, err)
		addrs = append(addrs, netip.MustParsePrefix(claims.Addresses[0]).Addr().Next())
	}
	for i, from := range agents {
		to, dst, src := agents[1-i], addrs[1-i], addrs[i]
		require.NoError(t, from.qc.SendDatagram(peerFrame(dst, src, "ping")))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, err := to.qc.ReceiveDatagram(ctx)
		cancel()
		require.NoError(t, err)
		assert.Equal(t, peerconn.EncodeFromRelay(nil, src, []byte("ping")), b)
	}
}

// A data frame with a 1280 B packet goes through at MinPacketSize, with the
// 8 B connection IDs of the relay, before and after the first ACK.
func TestMinPacketSize(t *testing.T) {
	cert, _ := relayCert(t, "relay-1", newKey(t))
	cfg := &quic.Config{EnableDatagrams: true, InitialPacketSize: MinPacketSize, DisablePathMTUDiscovery: true}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp, ConnectionIDGenerator: steer.ConnIDs{}}
	defer tr.Close()
	ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"t"}}, cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"t"}}, cfg)
	require.NoError(t, err)
	defer qc.CloseWithError(0, "")
	sc, err := ln.Accept(ctx)
	require.NoError(t, err)

	frame := peerconn.EncodeData(nil, 1, make([]byte, vpcv1alpha1.DefaultMTU))
	for range 3 {
		for _, c := range []struct{ from, to quic.Connection }{{qc, sc}, {sc, qc}} {
			require.NoError(t, c.from.SendDatagram(frame))
			b, err := c.to.ReceiveDatagram(ctx)
			require.NoError(t, err)
			assert.Equal(t, frame, b)
		}
	}
}
