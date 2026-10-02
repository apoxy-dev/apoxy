// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		reply bool
	}{
		{name: "probe", reply: true, probe: func(k p2p.ProbeKeys) []byte {
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
			h.session(t, a)
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
			// A good probe after it shows which ones got a reply.
			_, err := a.tr.WriteTo(p2p.AppendProbe(nil, p2p.Probe{SID: k.SID, Round: 2}, probeSize, &k.Dialer), h.ln.Addr())
			require.NoError(t, err)
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
