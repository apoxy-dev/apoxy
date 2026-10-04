// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

const probeSize = 1452

// probeKeys returns the probe keys of agent a.
func probeKeys(t *testing.T, a agent) p2p.ProbeKeys {
	t.Helper()
	k, err := p2p.NewProbeKeys(a.qc.ConnectionState().TLS)
	require.NoError(t, err)
	return k
}

// readProbes makes tr keep the non-QUIC packets that arrive from now on.
func readProbes(tr *quic.Transport) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _ = tr.ReadNonQUICPacket(ctx, nil)
}

// nextReply returns the next path probe reply on tr, or false after wait.
func nextReply(t *testing.T, tr *quic.Transport, k p2p.ProbeKeys, wait time.Duration) (p2p.Probe, int, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	buf := make([]byte, 2048)
	n, _, err := tr.ReadNonQUICPacket(ctx, buf)
	if errors.Is(err, context.DeadlineExceeded) {
		return p2p.Probe{}, 0, false
	}
	require.NoError(t, err)
	p, err := p2p.OpenProbe(buf[:n], &k.Listener)
	require.NoError(t, err)
	return p, n, true
}

func TestAnswerProbe(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	cases := []struct {
		name  string
		probe func(k p2p.ProbeKeys) []byte // The probe with Round 1.
		other bool                         // Send from another socket.
		early bool                         // Send before the relay adds the session.
		reply bool
	}{
		{name: "probe", reply: true, probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, TxID: [12]byte{7}, Round: 1}, probeSize, &k.Dialer)
		}},
		{name: "probe before the session", early: true, reply: true, probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, TxID: [12]byte{7}, Round: 1}, probeSize, &k.Dialer)
		}},
		{name: "small probe", reply: true, probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 1}, p2p.MinProbeLen, &k.Dialer)
		}},
		{name: "unknown SID", probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{1}, Round: 1}, probeSize, &k.Dialer)
		}},
		{name: "listener key", probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 1}, probeSize, &k.Listener)
		}},
		{name: "reply", probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{Reply: true, SID: k.SID, Round: 1}, probeSize, &k.Dialer)
		}},
		{name: "other source", other: true, probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 1}, probeSize, &k.Dialer)
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := h.mustDial(t, ca.agentCert(t, vpcA, fmt.Sprintf("a%d", i)))
			if !tc.early {
				h.session(t, a)
			}
			k := probeKeys(t, a)
			readProbes(a.tr)
			pkt := tc.probe(k)
			if tc.other {
				udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				defer udp.Close()
				_, err = udp.WriteTo(pkt, h.ln.Addr())
				require.NoError(t, err)
			} else {
				_, err := a.tr.WriteTo(pkt, h.ln.Addr())
				require.NoError(t, err)
			}
			// A good probe after it shows which ones got a reply. The relay can
			// answer it first when the session opens between the two.
			if !tc.early {
				_, err := a.tr.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 2}, probeSize, &k.Dialer), h.ln.Addr())
				require.NoError(t, err)
			}
			got, n, ok := nextReply(t, a.tr, k, 5*time.Second)
			require.True(t, ok)
			assert.True(t, got.Reply)
			assert.Equal(t, a.src, got.Seen)
			if !tc.reply {
				assert.Equal(t, uint32(2), got.Round)
				return
			}
			want, err := p2p.OpenProbe(pkt, &k.Dialer)
			require.NoError(t, err)
			want.Reply, want.Seen = true, a.src
			assert.Equal(t, want, got)
			assert.Equal(t, len(pkt), n)
		})
	}
}

func TestProbeRate(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	a := h.mustDial(t, ca.agentCert(t, vpcA, "a"))
	s := h.session(t, a)
	k := probeKeys(t, a)
	readProbes(a.tr)
	for i := range 2 * probeRate {
		_, err := a.tr.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: uint32(i)}, probeSize, &k.Dialer), h.ln.Addr())
		require.NoError(t, err)
	}
	replies := 0
	for {
		if _, _, ok := nextReply(t, a.tr, k, 300*time.Millisecond); !ok {
			break
		}
		replies++
	}
	assert.Equal(t, probeRate, replies)

	// The SID goes with the session.
	_ = a.qc.CloseWithError(0, "")
	assert.Eventually(t, func() bool {
		h.r.mu.RLock()
		defer h.r.mu.RUnlock()
		return h.r.probes[s.probe.keys.SID] == nil
	}, 5*time.Second, 10*time.Millisecond)
}

// TestEarlyProbe sends a probe before the relay adds its session. The relay
// answers it when it adds the session.
func TestEarlyProbe(t *testing.T) {
	cases := []struct {
		name     string
		other    bool          // The probe comes from another address.
		listener bool          // The probe has the tag of the listener key.
		age      time.Duration // Age of the probe when the session opens.
		after    int           // Early probes of other sessions that come after it.
		reply    bool
		wantBad  uint64 // Malformed drops.
	}{
		{name: "probe", reply: true},
		{name: "list has room", after: earlyProbes - 1, reply: true},
		{name: "list is full", after: earlyProbes, wantBad: 1},
		{name: "other source", other: true, wantBad: 1},
		{name: "listener key", listener: true, wantBad: 1},
		{name: "too old", age: 2 * earlyProbeAge, wantBad: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(&fakeTrust{}, Config{})
			relayUDP := loopbackUDP(t)
			tr := &quic.Transport{Conn: relayUDP}
			defer tr.Close()
			agentUDP := loopbackUDP(t)
			src := netip.MustParseAddrPort(agentUDP.LocalAddr().String())
			from := src
			if tc.other {
				from = netip.MustParseAddrPort(loopbackUDP(t).LocalAddr().String())
			}

			var k p2p.ProbeKeys
			_, _ = rand.Read(k.SID[:])
			_, _ = rand.Read(k.Dialer[:])
			_, _ = rand.Read(k.Listener[:])
			key := &k.Dialer
			if tc.listener {
				key = &k.Listener
			}
			pkt := p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, TxID: [12]byte{7}}, probeSize, key)
			require.True(t, r.answerProbe(tr, pkt, net.UDPAddrFromAddrPort(from)))
			for i := range tc.after {
				other := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{byte(i), 1}}, probeSize, &k.Dialer)
				require.True(t, r.answerProbe(tr, other, net.UDPAddrFromAddrPort(src)))
			}
			for i := range r.early.list {
				r.early.list[i].at = r.early.list[i].at.Add(-tc.age)
			}

			s := newSession(Identity{VPC: vpcA, ID: "a"}, func() netip.AddrPort { return src })
			s.probe = &prober{keys: k, limit: rate.NewLimiter(probeRate, probeRate)}
			r.addSession(s, time.Now())
			r.answerEarly(s)

			buf := make([]byte, 2048)
			require.NoError(t, agentUDP.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
			n, err := agentUDP.Read(buf)
			if !tc.reply {
				require.Error(t, err, "reply to the early probe")
			} else {
				require.NoError(t, err)
				got, err := p2p.OpenProbe(buf[:n], &k.Listener)
				require.NoError(t, err)
				assert.Equal(t, p2p.Probe{Reply: true, SID: k.SID, TxID: [12]byte{7}, Seen: src}, got)
				assert.Equal(t, len(pkt), n)
			}
			assert.Equal(t, tc.wantBad, r.MalformedDrops())
		})
	}
}

// BenchmarkEarlyProbe measures a probe for a session that the relay does not
// have, as the read loop keeps it.
func BenchmarkEarlyProbe(b *testing.B) {
	r := NewRouter(&fakeTrust{}, Config{})
	from := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1000}
	pkt := p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{1}}, probeSize, &[32]byte{})
	b.ReportAllocs()
	for b.Loop() {
		r.answerProbe(nil, pkt, from)
	}
}

// loopbackUDP opens a UDP socket on 127.0.0.1 that closes at the end of the test.
func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	return udp
}
