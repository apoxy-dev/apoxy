// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"context"
	"crypto/tls"
	"io"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The QUIC configs of the agent (agent.relayQUIC and agent.peerQUIC).
var (
	relayQUIC = &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 5 * time.Second, InitialPacketSize: 1350}
	peerQUIC  = &quic.Config{KeepAlivePeriod: 15 * time.Second, InitialPacketSize: 1200, DisablePathMTUDiscovery: true}
)

// TestPeerSession runs an mTLS peer session through a fake relay. The session
// continues after agent a moves to a new relay session.
func TestPeerSession(t *testing.T) {
	p := newPKI(t)
	r := newRelay(t, p, relayQUIC)
	srcA, srcB := netip.MustParseAddr("fd00::a"), netip.MustParseAddr("10.0.0.2")
	ca := New(r.attach(t, srcA, relayQUIC), srcA)
	cb := New(r.attach(t, srcB, relayQUIC), srcB)
	ta, tb := peerTransport(t, ca), peerTransport(t, cb)

	ln, err := tb.Listen(&tls.Config{
		Certificates: []tls.Certificate{p.issue(t, "b.test")},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		NextProtos:   []string{alpnPeer},
	}, peerQUIC)
	require.NoError(t, err)
	accepted := make(chan quic.Connection, 1)
	go func() {
		qc, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		accepted <- qc
		for {
			s, err := qc.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(s, s)
				_ = s.Close()
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	qc, err := ta.Dial(ctx, udpAddr(srcB.String()), &tls.Config{
		Certificates: []tls.Certificate{p.issue(t, "a.test")},
		RootCAs:      p.pool,
		ServerName:   "b.test",
		NextProtos:   []string{alpnPeer},
	}, peerQUIC)
	require.NoError(t, err)
	defer qc.CloseWithError(0, "")
	peer := <-accepted
	assert.Equal(t, []string{"a.test"}, peer.ConnectionState().TLS.PeerCertificates[0].DNSNames)
	assert.Equal(t, udpAddr(srcA.String()), peer.RemoteAddr())

	call(t, ctx, qc, "first call")
	assert.Equal(t, Stats{}, ca.Stats())
	assert.Equal(t, Stats{}, cb.Stats())
	assert.Zero(t, r.drops.Load())

	// Move a to a new relay session and close the old one.
	old := ca.sess.Load().qc
	ca.SetConn(r.attach(t, srcA, relayQUIC))
	require.NoError(t, old.CloseWithError(0, "reconnect"))
	call(t, ctx, qc, "call after the reconnect")
	assert.Equal(t, Stats{}, cb.Stats())
}

// call sends msg on a new stream and checks the echo.
func call(t *testing.T, ctx context.Context, qc quic.Connection, msg string) {
	t.Helper()
	s, err := qc.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = s.Write([]byte(msg))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	got, err := io.ReadAll(s)
	require.NoError(t, err)
	assert.Equal(t, msg, string(got))
}

// peerTransport runs quic-go on c. Its cleanup checks that Close ends.
func peerTransport(t *testing.T, c *Conn) *quic.Transport {
	tr := &quic.Transport{Conn: c}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			_ = tr.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("quic.Transport.Close did not end")
		}
		_ = c.Close()
	})
	return tr
}

// TestFrameFits sends a 1200 B packet (a 1233 B frame) through the relay.
// quic-go sends datagrams up to InitialPacketSize - 37 B.
func TestFrameFits(t *testing.T) {
	cases := []struct {
		packetSize uint16
		fits       bool
	}{
		{1200, false},
		{1270, true},
		{1280, true}, // The quic-go default.
		{1350, true}, // The agent and the relay.
	}
	p := newPKI(t)
	pkt := make([]byte, peerQUIC.InitialPacketSize)
	srcA, srcB := netip.MustParseAddr("fd00::a"), netip.MustParseAddr("fd00::b")
	for _, tc := range cases {
		t.Run(strconv.Itoa(int(tc.packetSize)), func(t *testing.T) {
			cfg := &quic.Config{EnableDatagrams: true, InitialPacketSize: tc.packetSize, DisablePathMTUDiscovery: true}
			r := newRelay(t, p, cfg)
			ca := New(r.attach(t, srcA, cfg), srcA)
			defer ca.Close()
			cb := New(r.attach(t, srcB, cfg), srcB)
			defer cb.Close()
			_, err := ca.WriteTo(pkt, udpAddr(srcB.String()))
			require.NoError(t, err)
			if !tc.fits {
				assert.Equal(t, Stats{WriteDrops: 1}, ca.Stats())
				err := r.side(srcB).SendDatagram(EncodeFromRelay(nil, srcA, pkt))
				var tooLarge *quic.DatagramTooLargeError
				assert.ErrorAs(t, err, &tooLarge)
				return
			}
			require.NoError(t, cb.SetReadDeadline(time.Now().Add(5*time.Second)))
			n, addr, err := cb.ReadFrom(make([]byte, 1500))
			require.NoError(t, err)
			assert.Equal(t, len(pkt), n)
			assert.Equal(t, udpAddr(srcA.String()), addr)
			assert.Equal(t, Stats{}, ca.Stats())
		})
	}
}
