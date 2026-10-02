// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// fakeConn is a peer session connection that records its close.
type fakeConn struct {
	quic.Connection
	ctx    context.Context
	cancel context.CancelCauseFunc
	code   quic.ApplicationErrorCode
}

func newFakeConn() *fakeConn {
	c := &fakeConn{}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	return c
}

func (c *fakeConn) Context() context.Context { return c.ctx }

func (c *fakeConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	c.code = code
	c.cancel(errors.New(msg))
	return nil
}

func (c *fakeConn) closed() bool { return c.ctx.Err() != nil }

// stubAgent returns agent name with a binding and an unconnected relay session.
func (w *world) stubAgent(t *testing.T, name string) *Agent {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	a := New(Config{RelayRoots: w.relayCA.pool(), Transport: tr})
	b, err := psp.New(psp.Config{Transport: tr, Demux: &a.demux, VNI: testVNI})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = b.Close()
		_ = tr.Close()
		_ = udp.Close()
	})
	a.bind = b
	a.rc = &relayConn{
		a:         a,
		qc:        newFakeConn(),
		cred:      w.agentCA.credential(t, testProject, testVPC, name, time.Hour),
		roots:     a.cfg.RelayRoots,
		ref:       &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC, NetworkId: testVNI},
		relayAddr: netip.MustParseAddrPort("127.0.0.1:443"),
		sem:       make(chan struct{}, maxInFlight),
	}
	a.conns[a.rc] = struct{}{}
	a.rc.ctx, a.rc.cancel = context.WithCancel(context.Background())
	t.Cleanup(a.rc.cancel)
	a.rc.relay, err = b.AddPeer(a.rc.relayAddr)
	require.NoError(t, err)
	return a
}

// stubPeer adds a peer session from the agent called name to a.
func stubPeer(a *Agent, name string, dialer bool) (*peer, *fakeConn) {
	qc := newFakeConn()
	p := &peer{
		rc:      a.rc,
		qc:      qc,
		conn:    &rpc.Conn{},
		dialer:  dialer,
		subject: identity.ID{Project: testProject, VPC: testVPC, Agent: name}.String(),
		ready:   make(chan struct{}),
		granted: make(chan struct{}),
		keyed:   make(chan struct{}),
		offered: make(chan struct{}),
		spis:    map[uint32]time.Time{},
	}
	a.mu.Lock()
	a.peers[p.conn] = p
	a.mu.Unlock()
	return p, qc
}

func TestAdmit(t *testing.T) {
	w := newWorld(t)
	relayCert := w.relayCA.relayCert(t, "relay-1")
	otherRelayCert := newCA(t).relayCert(t, "relay-1")
	grant := func(t *testing.T, cert *tls.Certificate, change func(*dp.GrantClaims)) *dp.AttachmentGrant {
		c := &dp.GrantClaims{
			Vpc:          &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC, NetworkId: testVNI},
			AttachmentId: "attachment-b",
			Subject:      identity.ID{Project: testProject, VPC: testVPC, Agent: "b"}.String(),
			Addresses:    []string{"fd00:b::/96"},
			RelayId:      "relay-1",
			NotAfter:     timestamppb.New(time.Now().Add(time.Hour)),
		}
		if change != nil {
			change(c)
		}
		g, err := relay.SignGrant(cert, c)
		require.NoError(t, err)
		return g
	}

	// old is an open peer session with agent b before the new one.
	type old struct {
		dialer   bool
		instance uint64
		mode     dp.Mode // Unspecified means PSP.
	}
	cases := []struct {
		name     string
		self     string // Name of this agent. Empty means "a".
		cert     *tls.Certificate
		claims   func(*dp.GrantClaims)
		mode     dp.Mode
		selfQUIC bool // This agent is in QUIC mode.
		instance uint64
		dialer   bool // This agent dialed the new session.
		old      *old
		taken    bool // Another peer routes fd00:b::/96.
		wantErr  error
		wantText string
		keepOld  bool
		wantQUIC bool
	}{
		{name: "good"},
		{name: "unknown mode", mode: dp.Mode(9), wantText: "not supported"},
		{name: "peer in QUIC mode", mode: dp.Mode_MODE_QUIC, wantQUIC: true},
		{name: "this agent in QUIC mode", selfQUIC: true, wantQUIC: true},
		{name: "QUIC pair with a bad grant", mode: dp.Mode_MODE_QUIC, claims: func(c *dp.GrantClaims) { c.Vpc.VpcUid = "vpc-2" }, wantText: "another VPC"},
		{name: "QUIC pair route taken", mode: dp.Mode_MODE_QUIC, taken: true, wantErr: engine.ErrRouteTaken},
		{name: "peer moved to QUIC mode", mode: dp.Mode_MODE_QUIC, old: &old{instance: 7}, instance: 7, wantQUIC: true},
		{name: "QUIC pair with crossed dials", mode: dp.Mode_MODE_QUIC, old: &old{dialer: true, instance: 7, mode: dp.Mode_MODE_QUIC}, instance: 7, keepOld: true, wantQUIC: true},
		{name: "other relay CA", cert: otherRelayCert, wantText: "unknown authority"},
		{name: "other project", claims: func(c *dp.GrantClaims) { c.Vpc.ProjectId = "project-b" }, wantText: "another VPC"},
		{name: "other VPC", claims: func(c *dp.GrantClaims) { c.Vpc.VpcUid = "vpc-2" }, wantText: "another VPC"},
		{name: "other network", claims: func(c *dp.GrantClaims) { c.Vpc.NetworkId++ }, wantText: "another VPC"},
		{
			name: "other subject",
			claims: func(c *dp.GrantClaims) {
				c.Subject = identity.ID{Project: testProject, VPC: testVPC, Agent: "c"}.String()
			},
			wantText: "not for the peer cert",
		},
		{name: "ended", claims: func(c *dp.GrantClaims) { c.NotAfter = timestamppb.New(time.Now().Add(-time.Minute)) }, wantText: "has ended"},
		{name: "no addresses", claims: func(c *dp.GrantClaims) { c.Addresses = nil }, wantText: "no addresses"},
		{name: "route taken", taken: true, wantErr: engine.ErrRouteTaken},
		// This agent is a, or c with "self". The peer b is between them.
		{name: "peer dials over the session of a lower ID", old: &old{dialer: true, instance: 7}, instance: 7, wantErr: errDuplicate, keepOld: true},
		{name: "peer dials over the session of a higher ID", self: "c", old: &old{dialer: true, instance: 7}, instance: 7},
		{name: "lower ID dials over the session of the peer", old: &old{instance: 7}, dialer: true, instance: 7},
		{name: "higher ID dials over the session of the peer", self: "c", old: &old{instance: 7}, dialer: true, instance: 7, wantErr: errDuplicate, keepOld: true},
		{name: "peer dials again", old: &old{instance: 7}, instance: 7},
		{name: "peer dials a higher ID again", self: "c", old: &old{instance: 7}, instance: 7},
		{name: "peer restarted", old: &old{dialer: true, instance: 6}, instance: 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			self := tc.self
			if self == "" {
				self = "a"
			}
			a := w.stubAgent(t, self)
			if tc.selfQUIC {
				a.rc.mode = dp.Mode_MODE_QUIC
			}
			if tc.taken {
				bp, err := a.bind.AddPeer(netip.MustParseAddrPort("127.0.0.1:443"))
				require.NoError(t, err)
				require.NoError(t, a.bind.AddRoute(netip.MustParsePrefix("fd00:b::/96"), bp))
			}
			var oldConn *fakeConn
			if tc.old != nil {
				op, qc := stubPeer(a, "b", tc.old.dialer)
				mode := cmp.Or(tc.old.mode, dp.Mode_MODE_PSP)
				require.NoError(t, a.admit(op, grant(t, relayCert, nil), tc.old.instance, mode))
				oldConn = qc
			}
			cert := tc.cert
			if cert == nil {
				cert = relayCert
			}
			mode := cmp.Or(tc.mode, dp.Mode_MODE_PSP)
			p, _ := stubPeer(a, "b", tc.dialer)

			err := a.admit(p, grant(t, cert, tc.claims), tc.instance, mode)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.wantText != "":
				require.ErrorContains(t, err, tc.wantText)
			default:
				require.NoError(t, err)
				assert.NotNil(t, p.bp)
				assert.Equal(t, tc.wantQUIC, p.quic)
				assert.Equal(t, tc.wantQUIC, p.bp == a.rc.relay, "QUIC pairs use the relay peer")
				assert.Equal(t, netip.MustParseAddr("fd00:b::1"), p.addr)
				assert.Equal(t, "attachment-b", p.attachmentID())
				select {
				case <-p.ready:
				default:
					t.Error("ready is open")
				}
			}
			if oldConn == nil {
				return
			}
			assert.Equal(t, !tc.keepOld, oldConn.closed())
			if !tc.keepOld {
				assert.Equal(t, quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE), oldConn.code)
				assert.Equal(t, 1, peerCount(a), "only the new session stays")
			} else if tc.wantErr == nil {
				assert.Equal(t, 2, peerCount(a), "both sessions stay")
			}
		})
	}
}

// TestAdmitCrossed admits both sessions of crossed dials at the same time. The
// session that a dialed stays, because a has the lower ID.
func TestAdmitCrossed(t *testing.T) {
	w := newWorld(t)
	g, err := relay.SignGrant(w.relayCA.relayCert(t, "relay-1"), &dp.GrantClaims{
		Vpc:          &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC, NetworkId: testVNI},
		AttachmentId: "attachment-b",
		Subject:      identity.ID{Project: testProject, VPC: testVPC, Agent: "b"}.String(),
		Addresses:    []string{"fd00:b::/96"},
		RelayId:      "relay-1",
		NotAfter:     timestamppb.New(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)
	a := w.stubAgent(t, "a")
	dup := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
	for round := range 200 {
		dialed, dialedConn := stubPeer(a, "b", true)
		accepted, acceptedConn := stubPeer(a, "b", false)
		var errDialed, errAccepted error
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Go(func() { <-start; errDialed = a.admit(dialed, g, 7, dp.Mode_MODE_PSP) })
		wg.Go(func() { <-start; errAccepted = a.admit(accepted, g, 7, dp.Mode_MODE_PSP) })
		close(start)
		wg.Wait()

		require.NoError(t, errDialed, "round %d", round)
		require.NotNil(t, dialed.bp, "round %d", round)
		require.False(t, dialedConn.closed(), "round %d", round)
		// Admit refuses the accepted session, or the dialed session closes it.
		if errAccepted != nil {
			require.ErrorIs(t, errAccepted, errDuplicate, "round %d", round)
		} else {
			require.True(t, acceptedConn.closed(), "round %d", round)
			require.Equal(t, dup, acceptedConn.code, "round %d", round)
		}
		a.dropPeer(dialed)
		a.dropPeer(accepted)
	}
}

func TestVerifyPeer(t *testing.T) {
	w := newWorld(t)
	m := identity.NewManager(filepath.Join(t.TempDir(), "cred.json"), func(context.Context) (*identity.Credential, error) {
		return w.agentCA.credential(t, testProject, testVPC, "a", time.Hour), nil
	})
	require.NoError(t, m.Start(context.Background()))
	a := New(Config{Identity: m})

	cases := []struct {
		name    string
		cred    *identity.Credential
		wantErr bool
	}{
		{name: "same VPC", cred: w.agentCA.credential(t, testProject, testVPC, "b", time.Hour)},
		{name: "other CA", cred: newCA(t).credential(t, testProject, testVPC, "b", time.Hour), wantErr: true},
		{name: "other VPC", cred: w.agentCA.credential(t, testProject, "vpc-2", "b", time.Hour), wantErr: true},
		{name: "other project", cred: w.agentCA.credential(t, "project-b", testVPC, "b", time.Hour), wantErr: true},
		{name: "ended", cred: w.agentCA.credential(t, testProject, testVPC, "b", -time.Millisecond), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := a.verifyPeer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{tc.cred.Cert}})
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRefusedDuplicate(t *testing.T) {
	dup := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
	bad := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT)
	cases := []struct {
		name  string
		err   error
		close error // Cause of the connection close; nil if open.
		want  bool
	}{
		{name: "status AlreadyExists", err: rpc.Errorf(rpc.AlreadyExists, "dup"), want: true},
		{name: "remote close DUPLICATE", err: errors.New("stream reset"), close: &quic.ApplicationError{Remote: true, ErrorCode: dup}, want: true},
		{name: "local close DUPLICATE", err: errors.New("stream reset"), close: &quic.ApplicationError{ErrorCode: dup}},
		{name: "remote close BAD_GRANT", err: errors.New("stream reset"), close: &quic.ApplicationError{Remote: true, ErrorCode: bad}},
		{name: "status PermissionDenied", err: rpc.Errorf(rpc.PermissionDenied, "bad grant")},
		// The call can end before the close cause is set.
		{name: "remote DUPLICATE in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", &quic.ApplicationError{Remote: true, ErrorCode: dup}), want: true},
		{name: "local DUPLICATE in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", &quic.ApplicationError{ErrorCode: dup})},
		{name: "remote BAD_GRANT in the call error", err: rpc.Errorf(rpc.Unavailable, "%w", &quic.ApplicationError{Remote: true, ErrorCode: bad})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qc := newFakeConn()
			if tc.close != nil {
				qc.cancel(tc.close)
			}
			assert.Equal(t, tc.want, refusedDuplicate(qc, tc.err))
		})
	}
}

func TestWaitKeys(t *testing.T) {
	w := newWorld(t)
	dup := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_DUPLICATE)
	bad := quic.ApplicationErrorCode(dp.PeerCloseCode_PEER_CLOSE_CODE_BAD_GRANT)
	cases := []struct {
		name    string
		close   error // Cause of the close of the first session; nil if it gets keys.
		next    bool  // Another session with the peer opens and gets keys.
		wantErr bool
	}{
		{name: "keys"},
		{name: "local replace", close: &quic.ApplicationError{ErrorCode: dup}, next: true},
		{name: "remote replace", close: &quic.ApplicationError{Remote: true, ErrorCode: dup}, next: true},
		{name: "replace with no new session", close: &quic.ApplicationError{ErrorCode: dup}, wantErr: true},
		{name: "other close", close: &quic.ApplicationError{Remote: true, ErrorCode: bad}, next: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			open := func() (*peer, *fakeConn) {
				p, qc := stubPeer(a, "b", true)
				var err error
				p.bp, err = a.bind.AddPeer(a.rc.relayAddr)
				require.NoError(t, err)
				p.prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:b::/96")}
				return p, qc
			}
			p, qc := open()
			if tc.close == nil {
				close(p.keyed)
				close(p.offered)
			} else {
				qc.cancel(tc.close)
			}
			if tc.next {
				q, _ := open()
				a.mu.Lock()
				close(a.admitted)
				a.admitted = make(chan struct{})
				a.mu.Unlock()
				close(q.keyed)
				close(q.offered)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			err := a.waitKeys(ctx, p, netip.MustParseAddr("fd00:b::1"))
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// spiRelay records the SPI calls and which of their SPIs the binding sends with.
type spiRelay struct {
	dp.RelayClient
	t     *testing.T
	probe *psp.Peer // Another peer of the binding, to find the SPIs that it sends with.
	err   error     // Result of RegisterSPI.
	calls []string
}

func (r *spiRelay) RegisterSPI(_ context.Context, in *dp.RegisterSPIRequest) (*emptypb.Empty, error) {
	r.record("register", in.GetSpis())
	return &emptypb.Empty{}, r.err
}

func (r *spiRelay) UnregisterSPI(_ context.Context, in *dp.UnregisterSPIRequest) (*emptypb.Empty, error) {
	r.record("unregister", in.GetSpis())
	return &emptypb.Empty{}, nil
}

func (r *spiRelay) record(op string, spis []uint32) {
	r.calls = append(r.calls, fmt.Sprintf("%s %v, sending %v", op, spis, r.sending(spis)))
}

// sending returns the SPIs that the binding refuses to the probe.
func (r *spiRelay) sending(spis []uint32) []uint32 {
	out := []uint32{}
	for _, spi := range spis {
		refused, err := r.probe.Apply(keys.Request{Op: keys.OpOffer, SAs: []keys.SA{testSA(spi, 0)}}, time.Now())
		require.NoError(r.t, err)
		if len(refused) > 0 {
			out = append(out, spi)
			continue
		}
		_, err = r.probe.Apply(keys.Request{Op: keys.OpRevoke, SPIs: []uint32{spi}}, time.Now())
		require.NoError(r.t, err)
	}
	return out
}

func testSA(spi uint32, lane int) keys.SA {
	return keys.SA{SPI: spi, Key: make([]byte, 16), VNI: testVNI, ExpiresIn: time.Minute, Lane: lane}
}

func TestApplyKeys(t *testing.T) {
	w := newWorld(t)
	sas := func(op keys.Op, spis ...uint32) keys.Request {
		req := keys.Request{Op: op}
		for i, spi := range spis {
			req.SAs = append(req.SAs, testSA(spi, i))
		}
		return req
	}
	offer := sas(keys.OpOffer, 1, 2)
	badSA := testSA(1, 0)
	badSA.VNI++
	cases := []struct {
		name        string
		before      *keys.Request // Key change from the peer before req.
		other       []uint32      // SPIs that another peer has in the binding.
		relayErr    error
		req         keys.Request
		wantCode    rpc.Code
		wantRefused []uint32
		wantCalls   []string
		wantKeyed   bool
		wantRows    []uint32 // SPIs that the agent registered for the peer.
		wantSending []uint32 // SPIs that the binding sends with after req.
	}{
		{
			name: "offer", req: offer,
			wantCalls: []string{"register [1 2], sending []"},
			wantKeyed: true, wantRows: []uint32{1, 2}, wantSending: []uint32{1, 2},
		},
		{
			name: "rekey", before: &offer, req: sas(keys.OpRekey, 3),
			wantCalls: []string{"register [3], sending []"},
			wantKeyed: true, wantRows: []uint32{1, 2, 3}, wantSending: []uint32{2, 3},
		},
		{
			name: "revoke", before: &offer, req: keys.Request{Op: keys.OpRevoke, SPIs: []uint32{1}},
			wantCalls: []string{"unregister [1], sending []"},
			wantKeyed: true, wantRows: []uint32{2}, wantSending: []uint32{2},
		},
		{
			name: "relay has an SPI for another peer", other: []uint32{1},
			relayErr: rpc.Errorf(rpc.AlreadyExists, "held"), req: offer,
			wantRefused: []uint32{1, 2},
			wantCalls:   []string{"register [1 2], sending [1]"},
			wantSending: []uint32{1},
		},
		{
			name: "binding has an SPI for another peer", other: []uint32{1}, req: offer,
			wantRefused: []uint32{1},
			wantCalls:   []string{"register [1 2], sending [1]", "unregister [1], sending [1]"},
			wantKeyed:   true, wantRows: []uint32{2}, wantSending: []uint32{1, 2},
		},
		{
			name: "relay fails", relayErr: rpc.Errorf(rpc.Unavailable, "down"), req: offer,
			wantCode:  rpc.Unavailable,
			wantCalls: []string{"register [1 2], sending []"},
		},
		{
			name: "bad SA", req: keys.Request{Op: keys.OpOffer, SAs: []keys.SA{badSA}},
			wantCode:  rpc.InvalidArgument,
			wantCalls: []string{"register [1], sending []", "unregister [1], sending []"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := w.stubAgent(t, "a")
			p, _ := stubPeer(a, "b", false)
			p.addr = netip.MustParseAddr("fd00:b::1")
			var err error
			p.bp, err = a.bind.AddPeer(a.rc.relayAddr)
			require.NoError(t, err)
			probe, err := a.bind.AddPeer(a.rc.relayAddr)
			require.NoError(t, err)
			r := &spiRelay{t: t, probe: probe}
			a.rc.c = r
			if tc.other != nil {
				q, err := a.bind.AddPeer(a.rc.relayAddr)
				require.NoError(t, err)
				_, err = q.Apply(sas(keys.OpOffer, tc.other...), time.Now())
				require.NoError(t, err)
			}
			if tc.before != nil {
				_, err := p.applyKeys(context.Background(), *tc.before)
				require.NoError(t, err)
				r.calls = nil
			}
			r.err = tc.relayErr

			res, err := p.applyKeys(context.Background(), tc.req)
			assert.Equal(t, tc.wantCode, rpc.CodeOf(err), "error: %v", err)
			assert.ElementsMatch(t, tc.wantRefused, res.GetRefusedSpis())
			assert.Equal(t, tc.wantCalls, r.calls)
			select {
			case <-p.keyed:
				assert.True(t, tc.wantKeyed, "keyed")
			default:
				assert.False(t, tc.wantKeyed, "keyed")
			}
			assert.ElementsMatch(t, tc.wantRows, slices.Collect(maps.Keys(p.spis)))
			assert.ElementsMatch(t, tc.wantSending, r.sending([]uint32{1, 2, 3}))
		})
	}
}

// signGrant returns a grant on relay-1 for the agent called name.
func signGrant(t *testing.T, cert *tls.Certificate, name, prefix string) *dp.AttachmentGrant {
	t.Helper()
	g, err := relay.SignGrant(cert, &dp.GrantClaims{
		Vpc:          &dp.VPCRef{ProjectId: testProject, VpcUid: testVPC, NetworkId: testVNI},
		AttachmentId: "attachment-" + name,
		Subject:      identity.ID{Project: testProject, VPC: testVPC, Agent: name}.String(),
		Addresses:    []string{prefix},
		RelayId:      "relay-1",
		NotAfter:     timestamppb.New(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)
	return g
}

// TestQUICRoutes checks that a closed QUIC pair removes only the routes that
// no other QUIC pair has, and keeps the relay peer.
func TestQUICRoutes(t *testing.T) {
	w := newWorld(t)
	cert := w.relayCA.relayCert(t, "relay-1")
	a := w.stubAgent(t, "a")
	other, err := a.bind.AddPeer(netip.MustParseAddrPort("127.0.0.1:444"))
	require.NoError(t, err)
	// routed reports whether a route to the relay peer has pfx.
	routed := func(pfx string) bool {
		p := netip.MustParsePrefix(pfx)
		err := a.bind.AddRoute(p, other)
		if err == nil {
			a.bind.RemoveRoute(p, other)
		}
		return errors.Is(err, engine.ErrRouteTaken)
	}
	admit := func(name string, dialer bool, prefix string) *peer {
		p, _ := stubPeer(a, name, dialer)
		require.NoError(t, a.admit(p, signGrant(t, cert, name, prefix), 7, dp.Mode_MODE_QUIC))
		return p
	}
	// Crossed dials with b leave two sessions.
	b1, b2 := admit("b", true, "fd00:b::/96"), admit("b", false, "fd00:b::/96")
	c := admit("c", true, "fd00:c::/96")

	a.dropPeer(b1)
	assert.True(t, routed("fd00:b::/96"), "the other session with b keeps the route")
	a.dropPeer(b2)
	assert.False(t, routed("fd00:b::/96"))
	assert.True(t, routed("fd00:c::/96"))
	a.dropPeer(c)
	assert.False(t, routed("fd00:c::/96"))
	assert.NoError(t, a.bind.AddRoute(netip.MustParsePrefix("fd00:b::/96"), a.rc.relay), "the relay peer stays")
}

func TestGiveKeys(t *testing.T) {
	w := newWorld(t)
	cases := []struct {
		name      string
		refuse    int // Calls that refuse all SAs before a call takes them.
		sendErr   error
		wantErr   string
		wantCalls int
	}{
		{name: "taken", wantCalls: 1},
		{name: "refused once", refuse: 1, wantCalls: 2},
		{name: "refused too many times", refuse: maxRefusals, wantErr: "too many times", wantCalls: maxRefusals},
		{name: "send fails", sendErr: errors.New("stream reset"), wantErr: "stream reset", wantCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bp := w.stubAgent(t, "a").rc.relay
			req, err := bp.Offer(time.Now())
			require.NoError(t, err)
			calls := 0
			var refused []uint32
			send := func(_ context.Context, m *dp.KeysRequest) (*dp.KeysResponse, error) {
				calls++
				if tc.sendErr != nil {
					return nil, tc.sendErr
				}
				var spis []uint32
				for _, sa := range append(m.GetOffer().GetSas(), m.GetRekey().GetSas()...) {
					spis = append(spis, sa.GetSpi())
				}
				require.NotEmpty(t, spis)
				for _, spi := range spis {
					assert.NotContains(t, refused, spi, "a refused SPI comes back")
				}
				if calls > tc.refuse {
					return &dp.KeysResponse{}, nil
				}
				refused = append(refused, spis...)
				return &dp.KeysResponse{RefusedSpis: spis}, nil
			}
			err = giveKeys(context.Background(), bp, req, send)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.wantCalls, calls)
		})
	}
}
