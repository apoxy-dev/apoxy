// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/vtep/netstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// TestVisits checks the link of a packet whose source no link has: the visit
// link of its destination, else the default link, on both send paths and modes.
func TestVisits(t *testing.T) {
	a, b := newPair(t)
	now := time.Now()
	offer(t, now, a, b)
	l2, err := a.b.AddLink()
	require.NoError(t, err)
	p2, err := l2.AddRelay(netip.MustParseAddrPort("192.0.2.1:1"))
	require.NoError(t, err)
	require.NoError(t, a.b.AddRoute(netip.PrefixFrom(b.v4, 32), p2))
	// p2 gets transmit SAs from another receiver.
	x, _ := newPair(t)
	req, err := x.peer.Offer(now)
	require.NoError(t, err)
	_, err = p2.Apply(req, now)
	require.NoError(t, err)
	// The visit set can still name this removed link.
	l3, err := a.b.AddLink()
	require.NoError(t, err)
	p3, err := l3.AddRelay(netip.MustParseAddrPort("192.0.2.3:1"))
	require.NoError(t, err)
	require.NoError(t, a.b.AddRoute(netip.PrefixFrom(b.v4, 32), p3))
	a.b.RemovePeer(p3)
	a.b.RemoveLink(l3)

	own2 := netip.MustParseAddr("10.0.1.1")
	require.NoError(t, a.l.AddSource(netip.PrefixFrom(a.v4, 32)))
	require.NoError(t, l2.AddSource(netip.PrefixFrom(own2, 32)))
	a.b.SetDefault(a.l)
	advertised := netip.MustParseAddr("10.7.0.5")
	slot := netip.MustParsePrefix("10.0.0.0/30") // The slot has b.v4.

	cases := []struct {
		name   string
		visits map[netip.Prefix]*Link
		src    netip.Addr
		want   *Peer
	}{
		{name: "advertised source, no visit", src: advertised, want: a.peer},
		{name: "advertised source, visit", visits: map[netip.Prefix]*Link{slot: l2}, src: advertised, want: p2},
		{name: "advertised source, visit of another slot", visits: map[netip.Prefix]*Link{netip.MustParsePrefix("10.0.0.4/30"): l2}, src: advertised, want: a.peer},
		{name: "source of the default link, visit", visits: map[netip.Prefix]*Link{slot: l2}, src: a.v4, want: a.peer},
		{name: "source of the visit link, no visit", src: own2, want: p2},
		{name: "advertised source, visit of a removed link", visits: map[netip.Prefix]*Link{slot: l3}, src: advertised, want: a.peer},
	}
	modes := []struct {
		name string
		quic bool
	}{{name: "PSP"}, {name: "QUIC", quic: true}}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			if m.quic {
				for _, p := range []*Peer{a.peer, p2} {
					require.NoError(t, p.UseQUIC(&peerconn.Conn{}))
					t.Cleanup(func() { _ = p.UseQUIC(nil) })
				}
			}
			// peerOf returns the peer of the send frame f.
			peerOf := func(f netstack.TxFrame) *Peer {
				for _, p := range []*Peer{a.peer, p2} {
					if m.quic && f.SA == nil && f.Lane == int(p.slot.Load()) || !m.quic && f.SA != nil && f.Dst == p.Addr() {
						return p
					}
				}
				return nil
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					a.b.SetVisits(tc.visits)
					defer a.b.SetVisits(nil)
					var f netstack.TxFrame
					require.NoError(t, a.b.prepare(packet(tc.src, b.v4, 17, 1, 2, 100), &f), "plain path")
					assert.Same(t, tc.want, peerOf(f), "plain path")
					f = netstack.TxFrame{}
					require.True(t, a.b.prepareSegs(packet(tc.src, b.v4, 6, 1, 2, 40), 2, 100, 200, &f), "segmented path")
					assert.Same(t, tc.want, peerOf(f), "segmented path")
				})
			}
		})
	}
}
