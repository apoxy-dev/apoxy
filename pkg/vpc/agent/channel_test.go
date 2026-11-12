// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// sentConn keeps a copy of each datagram that it sends.
type sentConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *sentConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, bytes.Clone(p))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

// datagrams returns the datagrams that c sent.
func (c *sentConn) datagrams() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sent)
}

// handshake runs one QUIC handshake, as a pair dial does, and returns the datagrams of the client and
// the first datagram of the server. With retry, the server first sends a Retry.
func handshake(t *testing.T, retry bool) (client [][]byte, server []byte) {
	ca := newCA(t)
	sc, cc := &sentConn{PacketConn: loopback(t)}, &sentConn{PacketConn: loopback(t)}
	t.Cleanup(func() { _ = sc.Close(); _ = cc.Close() })
	str := &quic.Transport{Conn: sc, VerifySourceAddress: func(net.Addr) bool { return retry }}
	t.Cleanup(func() { _ = str.Close() })
	ln, err := str.Listen(&tls.Config{Certificates: []tls.Certificate{*ca.relayCert(t, "r1")}, NextProtos: []string{"t"}}, peerQUIC)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	ctr := &quic.Transport{Conn: cc}
	t.Cleanup(func() { _ = ctr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := ctr.Dial(ctx, sc.LocalAddr(), &tls.Config{RootCAs: ca.Pool(), ServerName: "r1", NextProtos: []string{"t"}}, peerQUIC)
	require.NoError(t, err)
	_ = qc.CloseWithError(0, "")
	client, sent := cc.datagrams(), sc.datagrams()
	require.NotEmpty(t, client)
	require.NotEmpty(t, sent)
	return client, sent[0]
}

// initialToken returns the token length of the Initial b.
func initialToken(t *testing.T, b []byte) uint64 {
	n := int(b[5])
	token, _, err := quicvarint.Parse(b[7+n+int(b[6+n]):])
	require.NoError(t, err)
	return token
}

// TestTakeInitial gives the take-out handler packets of no known flow. Only an Initial that can start
// a QUIC connection goes to the root, also from another agent with a held prefix.
func TestTakeInitial(t *testing.T) {
	client, server := handshake(t, false)
	retried, _ := handshake(t, true)
	require.True(t, isInitial(client[0]), "the first datagram of the client is an Initial")
	require.True(t, isInitial(server), "the first datagram of the server is an Initial")
	// The first flight of the client can be two Initials. The Initial after the Retry has the token.
	i := slices.IndexFunc(retried, func(b []byte) bool { return isInitial(b) && initialToken(t, b) > 0 })
	require.GreaterOrEqual(t, i, 0, "the client sends an Initial with the token of the Retry")
	afterRetry := retried[i]
	require.Less(t, int(afterRetry[5]), 8, "the Initial after the Retry has the short ID of the server")
	cases := []struct {
		name string
		data []byte
		root bool // The packet goes to the root.
	}{
		{name: "first Initial of a dial", data: client[0], root: true},
		{name: "Initial with the token of a Retry", data: afterRetry, root: true},
		{name: "Initial of the server to a dial", data: server},
		{name: "Initial that ends after the ID length", data: client[0][:6]},
		{name: "packet that is not an Initial", data: []byte{0x40, 1, 2, 3, 4, 5}},
	}
	own, _ := slotAddr(1)
	peer, _ := slotAddr(2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tbl := newChanTable(true)
			ownPfx := netip.PrefixFrom(own.Addr(), 96).Masked()
			tbl.own.Store(&ownSet{list: []netip.Prefix{ownPfx}, all: []netip.Prefix{ownPfx}, vpc: testNetwork})
			pkt, err := chanPacket(tcpip.AddrFrom16(peer.Addr().As16()), tcpip.AddrFrom16(own.Addr().As16()), tc.data)
			require.NoError(t, err)
			tbl.take(pkt, psp.Source{Link: &psp.Link{}})
			got := tbl.initials.Take()
			if !tc.root {
				assert.Zero(t, len(got), "the packet drops")
				return
			}
			require.Len(t, got, 1, "the packet goes to the root")
			m := got[0].(initialMsg)
			assert.Equal(t, flow{own: own.Addr(), peer: peer.Addr()}, m.flow)
			assert.Equal(t, tc.data, m.pkt.data)
		})
	}
}
