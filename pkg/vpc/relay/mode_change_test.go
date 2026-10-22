// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// TestRekeyFromQUIC checks the Rekey call of a session in QUIC mode: it
// changes the session to PSP mode, or it changes nothing.
func TestRekeyFromQUIC(t *testing.T) {
	offer := func(spi, vni uint32) keys.Request {
		return keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: spi, Key: make([]byte, 16), VNI: vni, ExpiresIn: time.Hour}}}
	}
	cases := []struct {
		name     string
		noBridge bool
		prep     func(t *testing.T, r *Router, s *Session)
		req      keys.Request
		gen      uint64 // Key attempt of the request.
		code     rpc.Code
		refused  []uint32
		mode     dp.Mode // Mode after the call.
		rekeys   int     // Rekey messages for the Session stream, and mode changes.
	}{
		{name: "change", req: offer(0x1001, testVNI), mode: dp.Mode_MODE_PSP, rekeys: 1},
		{name: "change with a key attempt", req: offer(0x1001, testVNI), gen: 3, mode: dp.Mode_MODE_PSP, rekeys: 1},
		{name: "each SPI refused", req: offer(0x1001, testVNI), refused: []uint32{0x1001}, mode: dp.Mode_MODE_QUIC,
			prep: func(t *testing.T, r *Router, _ *Session) {
				p := localSession(t, r, "p", "192.0.2.2:1", "fd00:2::/96", dp.Mode_MODE_PSP)
				_, err := r.rekey(p, offer(0x1001, testVNI), 0, t0)
				require.NoError(t, err)
			}},
		{name: "no SA", req: keys.Request{Op: keys.OpRevoke, SPIs: []uint32{0x1001}}, mode: dp.Mode_MODE_QUIC},
		{name: "SA with no key", req: keys.Request{Op: keys.OpOffer, SAs: []keys.SA{{SPI: 0x1001, VNI: testVNI, ExpiresIn: time.Hour}}},
			code: rpc.InvalidArgument, mode: dp.Mode_MODE_QUIC},
		{name: "VNI of another VPC", req: offer(0x1001, testVNI+1), code: rpc.InvalidArgument, mode: dp.Mode_MODE_QUIC},
		{name: "closed session", req: offer(0x1001, testVNI), code: rpc.Unauthenticated, mode: dp.Mode_MODE_QUIC,
			prep: func(_ *testing.T, r *Router, s *Session) { r.removeSession(s) }},
		{name: "full session queue", req: offer(0x1001, testVNI), code: rpc.Unavailable, mode: dp.Mode_MODE_QUIC,
			prep: func(_ *testing.T, r *Router, s *Session) {
				r.mu.Lock()
				defer r.mu.Unlock()
				for range maxSyncQueue {
					s.queue(&dp.SessionResponse{})
				}
			}},
		{name: "relay with no bridge", noBridge: true, req: offer(0x1001, testVNI), code: rpc.Unavailable, mode: dp.Mode_MODE_QUIC},
		{name: "second Rekey", req: offer(0x1002, testVNI), mode: dp.Mode_MODE_PSP,
			prep: func(t *testing.T, r *Router, s *Session) {
				_, err := r.rekey(s, offer(0x1001, testVNI), 0, t0)
				require.NoError(t, err)
				r.takeSync(s)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			if !tc.noBridge {
				r, _ = localRouter(t)
			}
			s := localSession(t, r, "q", "192.0.2.1:1", "fd00:1::/96", dp.Mode_MODE_QUIC)
			r.takeSync(s)
			if tc.prep != nil {
				tc.prep(t, r, s)
			}
			changes := testutil.ToFloat64(modeChanges)

			refused, err := r.rekey(s, tc.req, tc.gen, t0)
			require.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
			assert.Equal(t, tc.refused, refused)
			r.mu.RLock()
			mode := s.sync.mode
			r.mu.RUnlock()
			assert.Equal(t, tc.mode, mode)
			rekeys := 0
			for _, m := range r.takeSync(s) {
				if m.GetRekey() != nil {
					rekeys++
					assert.Equal(t, tc.gen, m.GetRekey().GetGeneration(), "the Offer has the key attempt of the request")
				}
			}
			assert.Equal(t, tc.rekeys, rekeys)
			assert.Equal(t, changes+float64(tc.rekeys), testutil.ToFloat64(modeChanges))
			if tc.mode == dp.Mode_MODE_PSP {
				// The session has the relay SAs of one offer.
				assert.Len(t, s.relaySAs, 1)
				return
			}
			// A session that stays in QUIC mode has no relay SAs and no rows for them.
			assert.Nil(t, s.rx)
			assert.Empty(t, s.relaySAs)
			if br := r.bridge.Load(); br != nil {
				assert.Empty(t, br.peers)
				assert.Empty(t, br.senders)
				assert.Empty(t, br.local.inbound)
			}
		})
	}
}

// TestWelcomeMaxLanes checks that Welcome has the lane port limit of the relay
// in each data mode.
func TestWelcomeMaxLanes(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca, func(r *Router) { r.cfg.LaneSources = 3 })
	for name, mode := range map[string]dp.Mode{"psp": dp.Mode_MODE_PSP, "quic": dp.Mode_MODE_QUIC} {
		t.Run(name, func(t *testing.T) {
			_, w, _, _ := openMode(t, h.mustDial(t, ca.agentCert(t, vpcA, name)), mode)
			assert.EqualValues(t, 3, w.GetMaxLanes())
		})
	}
}
