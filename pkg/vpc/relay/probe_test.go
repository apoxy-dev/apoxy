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
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
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

// TestAnswerProbe sends path probes to the PSP socket of the relay.
func TestAnswerProbe(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	cases := []struct {
		name  string
		probe func(k p2p.ProbeKeys) []byte // The probe with Round 1.
		reply bool
	}{
		{name: "probe", reply: true, probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, TxID: [12]byte{7}, Round: 1, Counter: 1}, probeSize, &k.Dialer)
		}},
		{name: "small probe", reply: true, probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 1, Counter: 1}, p2p.MinProbeLen, &k.Dialer)
		}},
		{name: "unknown SID", probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: [8]byte{1}, Round: 1, Counter: 1}, probeSize, &k.Dialer)
		}},
		{name: "listener key", probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 1, Counter: 1}, probeSize, &k.Listener)
		}},
		{name: "reply", probe: func(k p2p.ProbeKeys) []byte {
			return p2p.AppendProbe(nil, p2p.Probe{Reply: true, SID: k.SID, Round: 1, Counter: 1}, probeSize, &k.Dialer)
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := h.mustDial(t, ca.agentCert(t, vpcA, fmt.Sprintf("a%d", i)))
			s := h.session(t, a)
			k := probeKeys(t, a)
			readProbes(a.tr)
			pkt := tc.probe(k)
			_, err := a.tr.WriteTo(pkt, h.pspAddr)
			require.NoError(t, err)
			// A good probe after it shows which ones got a reply.
			_, err = a.tr.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 2, Counter: 2}, probeSize, &k.Dialer), h.pspAddr)
			require.NoError(t, err)
			got, n, ok := nextReply(t, a.tr, k, 5*time.Second)
			require.True(t, ok)
			assert.True(t, got.Reply)
			assert.Equal(t, a.src, got.Seen)
			assert.Equal(t, a.src, h.r.Addr(s))
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
		_, err := a.tr.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: uint32(i), Counter: uint64(i + 1)}, probeSize, &k.Dialer), h.pspAddr)
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

// TestQUICSocketDrops sends packets that are not QUIC to the QUIC socket. The
// relay drops each one, sends no reply, and learns no PSP address from it.
func TestQUICSocketDrops(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	a := h.mustDial(t, ca.agentCert(t, vpcA, "a"))
	s := h.session(t, a)
	k := probeKeys(t, a)
	readProbes(a.tr)
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"PSP packet", pspPacket(t, 7, netip.MustParseAddr("fd00::1"))},
		{"path probe", p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Counter: 1}, probeSize, &k.Dialer)},
		{"small path probe", p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Counter: 2}, p2p.MinProbeLen, &k.Dialer)},
		{"Geneve", geneve(0, 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, classes := h.r.drops[dropNotQUIC].Load(), socketCounts(h.r)
			_, err := a.tr.WriteTo(tc.pkt, h.ln.Addr())
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return h.r.drops[dropNotQUIC].Load() == before+1
			}, 5*time.Second, time.Millisecond, "the relay did not count the packet")
			_, _, ok := nextReply(t, a.tr, k, 50*time.Millisecond)
			assert.False(t, ok, "reply from the QUIC socket")
			assert.False(t, h.r.Addr(s).IsValid(), "PSP address from the QUIC socket")
			assert.Equal(t, classes, socketCounts(h.r), "PSP packet counted on the QUIC socket")
			assert.Zero(t, h.r.MalformedDrops())
			assert.Zero(t, h.r.UnknownSourceDrops())
		})
	}
}

// TestProbeAddress checks which path probes set the PSP address of a session.
// The QUIC connection of the session is at 192.0.2.1.
func TestProbeAddress(t *testing.T) {
	conn := netip.MustParseAddrPort("192.0.2.1:40000")
	p1, p2 := netip.MustParseAddrPort("192.0.2.1:1001"), netip.MustParseAddrPort("192.0.2.1:1002")
	otherIP := netip.MustParseAddrPort("192.0.2.9:1001")
	type step struct {
		from    netip.AddrPort
		counter uint64
		reply   bool
		addr    netip.AddrPort // PSP address after the step.
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"probe", []step{{p1, 1, true, p1}}},
		{"probe from the socket of the connection", []step{{conn, 1, true, conn}}},
		{"probe from another IP address", []step{{otherIP, 1, false, netip.AddrPort{}}}},
		{"counter zero", []step{{p1, 0, true, netip.AddrPort{}}}},
		{"old counter from another port", []step{{p1, 5, true, p1}, {p2, 4, true, p1}}},
		{"same counter from another port", []step{{p1, 5, true, p1}, {p2, 5, true, p1}}},
		{"newer counter from another port", []step{{p1, 5, true, p1}, {p2, 6, true, p2}}},
		{"old counter after a move", []step{{p1, 5, true, p1}, {p2, 6, true, p2}, {p1, 5, true, p2}}},
		{"newer counter from another IP address", []step{{p1, 5, true, p1}, {otherIP, 6, false, p1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(&fakeTrust{}, Config{})
			tr := &quic.Transport{Conn: loopbackUDP(t)}
			defer tr.Close()
			var k p2p.ProbeKeys
			_, _ = rand.Read(k.SID[:])
			_, _ = rand.Read(k.Dialer[:])
			s := newSession(Identity{VPC: vpcA, ID: "a"}, func() netip.AddrPort { return conn })
			s.probe = &prober{keys: k, limit: rate.NewLimiter(probeRate, probeRate)}
			r.addSession(s, time.Now())
			assert.False(t, r.Addr(s).IsValid(), "PSP address before a probe")
			for i, st := range tc.steps {
				pkt := p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Counter: st.counter}, p2p.MinProbeLen, &k.Dialer)
				assert.Equal(t, st.reply, r.answerProbe(tr, pkt, net.UDPAddrFromAddrPort(st.from)), "step %d", i)
				assert.Equal(t, st.addr, r.Addr(s), "step %d", i)
			}
		})
	}
}

// TestProbeMovesData moves a PSP-mode agent to a new port with a newer path
// probe. The relay then sends its packets to the new port, and takes packets from it.
func TestProbeMovesData(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	q := newEnd(t, h, ca, "q", dp.Mode_MODE_QUIC)
	p := newEnd(t, h, ca, "p", dp.Mode_MODE_PSP)
	p.giveSAs(t)
	old := h.r.Addr(p.s)
	require.Equal(t, p.src, old)

	udp := loopbackUDP(t)
	moved := netip.MustParseAddrPort(udp.LocalAddr().String())
	k := probeKeys(t, p.agent)
	probe := func(counter uint64) {
		t.Helper()
		_, err := udp.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Counter: counter}, p2p.MinProbeLen, &k.Dialer), h.pspAddr)
		require.NoError(t, err)
		buf := make([]byte, 2048)
		require.NoError(t, udp.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, err := udp.Read(buf)
		require.NoError(t, err)
		got, err := p2p.OpenProbe(buf[:n], &k.Listener)
		require.NoError(t, err)
		assert.Equal(t, moved, got.Seen)
	}
	// A replay of an old probe from the new port gets a reply and moves nothing.
	probe(1)
	require.Equal(t, old, h.r.Addr(p.s))
	inner := ipPacket(q.addr, p.addr, []byte("before"))
	q.send(t, inner)
	got, _ := p.recv(t)
	assert.Equal(t, inner, got)

	probe(testCounter.Add(1))
	require.Equal(t, moved, h.r.Addr(p.s))
	inner = ipPacket(q.addr, p.addr, []byte("after"))
	q.send(t, inner)
	buf := make([]byte, 2048)
	require.NoError(t, udp.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, from, err := udp.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, h.pspAddr.String(), from.String())
	got, _, err = p.psp.rxq.Receive(buf[:n])
	require.NoError(t, err)
	assert.Equal(t, inner, got)

	inner = ipPacket(p.addr, q.addr, []byte("from the new port"))
	_, err = udp.WriteTo(p.psp.seal(t, inner), h.pspAddr)
	require.NoError(t, err)
	got, _ = q.recv(t)
	assert.Equal(t, inner, got)
}

// loopbackUDP opens a UDP socket on 127.0.0.1 that closes at the end of the test.
func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	return udp
}
