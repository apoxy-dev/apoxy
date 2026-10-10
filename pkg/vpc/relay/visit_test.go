// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// In the visit tests, server has brServer on relay-a, which the test plays. A
// second session of server visits the relay of the test, which has q, p and laptop.
const (
	homeID      = "relay-a.example.net" // Relay ID that relay-a gives in Open.
	strangerID  = "relay-z.example.net" // Relay ID that no member gives.
	visitSocket = "192.0.2.30:1"        // Socket of the visitor session.
	spareSocket = "192.0.2.32:1"        // Socket of one more session.
	visitSpan   = 10 * time.Second      // Time to the end of a grant.
	phoneNet    = "fd00:d::/96"         // Prefix of phone, a second agent of relay-a.
)

var (
	phone = agentID(vpcA, "phone")
	other = agentID(vpcA, "other")
)

// visitCerts are the relay certs of the visit tests. They are valid on the
// real clock and on the fake clock.
type visitCerts struct {
	roots    *x509.CertPool   // Relay roots of the relay of the test.
	home     *tls.Certificate // Cert of relay-a, which names homeID.
	stranger *tls.Certificate // Cert from the same CA, which names strangerID.
	rogue    *tls.Certificate // Cert that names homeID, from a CA that is not in roots.
}

func newVisitCerts(t *testing.T) *visitCerts {
	t.Helper()
	from, to := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	newCA := func() *testCA {
		key := newKey(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay CA"}, NotBefore: from, NotAfter: to,
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return &testCA{cert: cert, key: key}
	}
	leaf := func(ca *testCA, id string) *tls.Certificate {
		key := newKey(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3), NotBefore: from, NotAfter: to, DNSNames: []string{id},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
		require.NoError(t, err)
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	good, bad := newCA(), newCA()
	return &visitCerts{roots: good.pool(), home: leaf(good, homeID), stranger: leaf(good, strangerID), rogue: leaf(bad, homeID)}
}

// visitRig is a rowRig with relay roots, and with the agents q in QUIC mode and
// p in PSP mode. v is a session of server with a Session call and no attachment.
type visitRig struct {
	*rowRig
	certs *visitCerts
	trust *fakeTrust
	q, p  *bridgeEnd
	v     *bridgeEnd
	ends  map[string]*bridgeEnd // The sessions that via names.
}

// newVisitRig links relay-a, which has the ID homeID, at this revision.
// relay-a has server and phone. v has the mode mode.
func newVisitRig(t *testing.T, cfg MeshConfig, certs *visitCerts, mode dp.Mode) *visitRig {
	t.Helper()
	g := &visitRig{rowRig: newRowRig(t, cfg), certs: certs, trust: &fakeTrust{roots: certs.roots}}
	g.r.trust = g.trust
	g.ref = &dp.RelayRef{Id: homeID}
	g.q = g.bridgeEnd(dp.Mode_MODE_QUIC, "q", brQSocket, brQNet, brQNet4)
	g.p = g.bridgeEnd(dp.Mode_MODE_PSP, "p", brPSocket, brPNet)
	g.giveSAs(g.p)
	g.link(dp.Revision)
	require.NoError(t, g.tk.rowsFrom(g.sess))
	g.announce(atGen(liveEntry("ph", phone, "base", phoneTag, phoneNet), 10))
	g.v = g.guest(mode, server, visitSocket)
	g.ends = map[string]*bridgeEnd{"visitor": g.v, "q": g.q, "p": g.p}
	return g
}

// localOnly is the Hello of a session that takes only the routes of this relay.
func localOnly() *dp.Hello {
	return &dp.Hello{Version: dp.LocalVersion("test"), Name: "base", LocalRoutesOnly: true}
}

// guest adds a session of subject at socket, with a Session call in mode that
// takes only the routes of this relay, and with no attachment.
func (g *visitRig) guest(mode dp.Mode, subject, socket string) *bridgeEnd {
	g.t.Helper()
	return g.sessionOf(mode, subject, socket, localOnly())
}

// sessionOf is guest with the Hello h. With no h, the session has no Session call.
func (g *visitRig) sessionOf(mode dp.Mode, subject, socket string, h *dp.Hello) *bridgeEnd {
	g.t.Helper()
	e := &bridgeEnd{socket: netip.MustParseAddrPort(socket)}
	e.s = newSession(Identity{VPC: vpcA, ID: subject}, func() netip.AddrPort { return e.socket })
	e.s.sendDatagram = func(b []byte) error {
		e.frames = append(e.frames, slices.Clone(b))
		return nil
	}
	g.r.addSession(e.s, time.Now())
	if h == nil {
		return e
	}
	require.NoError(g.t, g.r.checkRevision(e.s, h.GetVersion()))
	require.NoError(g.t, g.r.openSync(e.s, mode, ref(vpcA), h))
	if mode == dp.Mode_MODE_PSP {
		offer, err := g.r.offer(e.s, Network{ID: testVNI, MTU: 1280}, time.Now())
		require.NoError(g.t, err)
		e.psp = newPSPAgent(g.t, offer.GetRekey(), time.Now())
		g.giveSAs(e)
	}
	return e
}

// claims are the claims of the grant of relay-a for the attachment x of
// server, which has prefixA. The grant ends visitSpan from now.
func (g *visitRig) claims() *dp.GrantClaims {
	return &dp.GrantClaims{
		Vpc: ref(vpcA), AttachmentId: "x", Subject: server, Addresses: []string{prefixA},
		RelayId: homeID, NotAfter: timestamppb.New(time.Now().Add(visitSpan)),
	}
}

// claimsOf is claims for the attachment id of subject with prefix.
func (g *visitRig) claimsOf(subject, id, prefix string) *dp.GrantClaims {
	c := g.claims()
	c.Subject, c.AttachmentId, c.Addresses = subject, id, []string{prefix}
	return c
}

// visit calls Visit for e with addr and the grant of the claims c, which the
// cert of relay-a signs.
func (g *visitRig) visit(e *bridgeEnd, addr string, c *dp.GrantClaims) error {
	g.t.Helper()
	grant, err := SignGrant(g.certs.home, c)
	require.NoError(g.t, err)
	return g.r.startVisit(e.s, &dp.VisitRequest{Vpc: ref(vpcA), Address: addr, Grant: grant}, time.Now())
}

// enter makes v a visitor with the grant of relay-a.
func (g *visitRig) enter() {
	g.t.Helper()
	require.NoError(g.t, g.visit(g.v, brServer, g.claims()))
}

// local adds the QUIC-mode agent name of the relay of the test with prefixes,
// and via names it.
func (g *visitRig) local(name, socket string, prefixes ...string) *bridgeEnd {
	g.t.Helper()
	e := g.bridgeEnd(dp.Mode_MODE_QUIC, name, socket, prefixes...)
	g.ends[name] = e
	return e
}

// expire lets the time to the end of a grant pass, and sweeps the router.
func (g *visitRig) expire() {
	time.Sleep(visitSpan)
	synctest.Wait()
	g.r.Sweep(time.Now())
}

// visitOf returns the prefixes of the visits of s, the oldest first. It is
// empty with no visit.
func (g *visitRig) visitOf(s *Session) string {
	g.r.mu.RLock()
	defer g.r.mu.RUnlock()
	var out []string
	if vs := s.visit.Load(); vs != nil {
		for _, v := range *vs {
			out = append(out, v.prefix.String())
		}
	}
	return strings.Join(out, ",")
}

// visitors returns the number of visitor sessions that the router keeps.
func (g *visitRig) visitors() int {
	g.r.mu.RLock()
	defer g.r.mu.RUnlock()
	n := 0
	for _, d := range g.r.domains {
		for _, ss := range d.visits.by {
			n += len(ss)
		}
		// The lengths are those of the prefixes in use.
		lens := map[int]bool{}
		for p := range d.visits.by {
			lens[p.Bits()] = true
		}
		assert.Len(g.t, d.visits.lens, len(lens), "prefix lengths of the visits")
	}
	return n
}

// via runs send and returns who got something from the relay for it, in name
// order: "relay-a", "laptop", or a name of ends. Empty is nobody.
func (g *visitRig) via(send func()) string {
	g.t.Helper()
	g.packets()
	stub := g.stubs[g.sess]
	stub.mu.Lock()
	stub.sent = nil
	stub.mu.Unlock()
	for _, e := range g.ends {
		e.frames = nil
	}
	send()
	var got []string
	for _, pkt := range g.packets() {
		name := pkt.to.String()
		switch pkt.to {
		case g.addr:
			name = "relay-a"
		case netip.MustParseAddrPort(rowSrc):
			name = "laptop"
		}
		for n, e := range g.ends {
			if pkt.to == e.socket {
				name = n
			}
		}
		got = append(got, name)
	}
	for n, e := range g.ends {
		for range e.frames {
			got = append(got, n)
		}
	}
	stub.mu.Lock()
	for range stub.sent {
		got = append(got, "relay-a")
	}
	stub.mu.Unlock()
	slices.Sort(got)
	return strings.Join(got, ",")
}

// frame returns the send of a peer frame of e from src to dst.
func (g *visitRig) frame(e *bridgeEnd, src, dst string) func() {
	return func() {
		b := peerconn.EncodeToRelay(nil, netip.MustParseAddr(dst), netip.MustParseAddr(src), []byte("hi"))
		g.r.forwardDatagram(e.s, b, time.Now())
	}
}

// data returns the send of an inner packet of e from src to dst: a data frame,
// or in PSP mode a PSP packet with the relay SA from the socket of e.
func (g *visitRig) data(e *bridgeEnd, src, dst string) func() {
	return func() {
		inner := innerOf(src, dst, 100)
		if e.psp != nil {
			g.handle(e.psp.seal(g.t, inner), net.UDPAddrFromAddrPort(e.socket))
			return
		}
		g.r.forwardData(e.s, peerconn.EncodeData(nil, testVNI, inner), make([]byte, maxUDP), time.Now())
	}
}

// psp returns the send of a PSP packet with spi from socket, for a row.
func (g *visitRig) psp(socket string, spi uint32) func() {
	return func() {
		g.handle(pspOfSize(g.t, spi, 100), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(socket)))
	}
}

// member returns the send of a peer frame from src to dst that relay-a carries
// for its session with tag.
func (g *visitRig) member(tag uint32, src, dst string) func() {
	return func() { g.m.pres.datagram(g.r, g.sess, memberFrame(tag, dst, src, "hi")) }
}

// trunkData returns the send of an inner packet from src to dst in a trunk
// packet of relay-a, for its session with tag.
func (g *visitRig) trunkData(tag uint32, src, dst string) func() {
	return func() {
		g.handle(g.sealed(trunkLane, tag, innerOf(src, dst, 100), false), net.UDPAddrFromAddrPort(g.addr))
	}
}

// trunkPSP returns the send of a PSP packet with spi from the address of
// relay-a, for a row that relay-a gave.
func (g *visitRig) trunkPSP(spi uint32) func() {
	return func() {
		g.handle(pspOfSize(g.t, spi, 100), net.UDPAddrFromAddrPort(g.addr))
	}
}

// receiver returns who has the row of sender s with spi: "relay-a", or a name
// of ends. Empty is no row. A packet of the row from socket must go there.
func (g *visitRig) receiver(s *Session, socket string, spi uint32) string {
	g.t.Helper()
	name := ""
	v, ok := g.rowOf(s, spi)
	to, verdict := g.r.Forward(netip.MustParseAddrPort(socket), spi, 100, time.Now())
	switch {
	case !ok:
		assert.Equal(g.t, DropUnknownSPI, verdict)
	case v.trunked:
		name = v.home
		assert.Equal(g.t, g.addr, to)
	default:
		for n, e := range g.ends {
			if e.s == v.receiver {
				name = n
				assert.Equal(g.t, e.socket, to)
			}
		}
		require.NotEmpty(g.t, name, "the receiver of the row is a session of ends")
	}
	assert.Equal(g.t, name, g.via(g.psp(socket, spi)), "packet of the row")
	return name
}

// TestVisitCall checks which Visit calls the relay accepts, and the error of
// each call that it refuses. The caller is v, or the session that caller makes.
func TestVisitCall(t *testing.T) {
	// more makes n more sessions of subject visit with prefix.
	more := func(n int, subject, prefix string) func(t *testing.T, g *visitRig) {
		return func(t *testing.T, g *visitRig) {
			for i := range n {
				e := g.guest(dp.Mode_MODE_QUIC, subject, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.50"), uint16(i+1)).String())
				require.NoError(t, g.visit(e, netip.MustParsePrefix(prefix).Addr().Next().String(), g.claimsOf(subject, "x", prefix)))
				g.ends[subject+string(rune('0'+i))] = e
			}
		}
	}
	lost := func(_ *testing.T, g *visitRig) {
		g.end(g.sess, meshLost)
		time.Sleep(time.Minute)
		g.deliver()
	}
	restart := func(_ *testing.T, g *visitRig) {
		g.end(g.sess, meshRestart)
		g.deliver()
	}
	cases := []struct {
		name   string
		setup  func(t *testing.T, g *visitRig)
		caller func(t *testing.T, g *visitRig) *bridgeEnd // Nil is v.
		claims func(c *dp.GrantClaims)                    // Changes the claims before the signature.
		cert   func(c *visitCerts) *tls.Certificate       // Cert that signs. Nil is the cert of relay-a.
		grant  func(g *dp.AttachmentGrant)                // Changes the signed grant.
		vpc    VPCKey                                     // VPC of the request. Zero is vpcA.
		addr   string                                     // Address of the request. Empty is brServer.
		code   rpc.Code
		msg    string // A part of the error message.
		prefix string // Prefix of the visit of an accepted call. Empty is prefixA.
	}{
		{name: "grant of the caller"},
		{
			name:   "address in the second prefix of the grant",
			claims: func(c *dp.GrantClaims) { c.Addresses = []string{prefixA, "fd00:a2::/96"} },
			addr:   "fd00:a2::7", prefix: "fd00:a2::/96",
		},
		{name: "prefix of the grant with host bits", claims: func(c *dp.GrantClaims) { c.Addresses = []string{"fd00:a::1/96"} }},
		{name: "last address of the prefix", addr: "fd00:a::ffff:ffff"},

		// The grant and the caller.
		{name: "no grant", grant: func(g *dp.AttachmentGrant) { g.Reset() }, code: rpc.PermissionDenied, msg: "no relay cert"},
		{
			name:  "claims that changed after the signature",
			grant: func(g *dp.AttachmentGrant) { g.Claims = append(g.Claims, 0x38, 0x01) },
			code:  rpc.PermissionDenied, msg: "signature does not verify",
		},
		{
			name: "relay cert from a CA that is not in the roots",
			cert: func(c *visitCerts) *tls.Certificate { return c.rogue },
			code: rpc.PermissionDenied, msg: "does not verify",
		},
		{
			name: "relay cert that does not name the relay of the grant",
			cert: func(c *visitCerts) *tls.Certificate { return c.stranger },
			code: rpc.PermissionDenied, msg: "does not name relay",
		},
		{
			name:   "grant that ends now",
			claims: func(c *dp.GrantClaims) { c.NotAfter = timestamppb.New(time.Now()) },
			code:   rpc.PermissionDenied, msg: "grant has ended",
		},
		{
			name:   "grant that ends in a millisecond",
			claims: func(c *dp.GrantClaims) { c.NotAfter = timestamppb.New(time.Now().Add(time.Millisecond)) },
		},
		{
			name:   "grant of another subject",
			claims: func(c *dp.GrantClaims) { c.Subject = phone },
			code:   rpc.PermissionDenied, msg: "not of the caller",
		},
		{
			name:   "grant of another VPC",
			claims: func(c *dp.GrantClaims) { c.Vpc = ref(vpcB) },
			code:   rpc.PermissionDenied, msg: "not of the caller",
		},
		{
			name:   "grant with no VPC",
			claims: func(c *dp.GrantClaims) { c.Vpc = nil },
			code:   rpc.PermissionDenied, msg: "not of the caller",
		},
		{name: "request for another VPC", vpc: vpcB, code: rpc.PermissionDenied, msg: "not the VPC of the agent cert"},
		{name: "address that is not valid", addr: "fd00:a::g", code: rpc.InvalidArgument, msg: "address"},
		{name: "address that is not in the grant", addr: "fd00:b::1", code: rpc.PermissionDenied, msg: "not in the grant"},
		{
			name:   "grant with a prefix that is not valid",
			claims: func(c *dp.GrantClaims) { c.Addresses = []string{"fd00:a::/200"} },
			code:   rpc.PermissionDenied, msg: "not in the grant",
		},
		{name: "Permit denies", setup: func(_ *testing.T, g *visitRig) { g.r.SetPermit(denyAll) }, code: rpc.PermissionDenied, msg: "permit denies"},

		// The relay roots.
		{
			name:  "relay roots with an error",
			setup: func(_ *testing.T, g *visitRig) { g.trust.rootsErr = errors.New("snapshot too old") },
			code:  rpc.Unavailable, msg: "snapshot too old",
		},
		{name: "no trust data", setup: func(_ *testing.T, g *visitRig) { g.r.trust = nil }, code: rpc.Unavailable, msg: "no trust data"},
		{
			// A nil pool is the system roots, which do not have the CA of the test.
			name:  "system roots",
			setup: func(_ *testing.T, g *visitRig) { g.trust.roots = nil },
			code:  rpc.PermissionDenied, msg: "does not verify",
		},

		// The relay of the grant is a member.
		{
			name:   "relay ID that no member gave",
			claims: func(c *dp.GrantClaims) { c.RelayId = strangerID },
			cert:   func(c *visitCerts) *tls.Certificate { return c.stranger },
			code:   rpc.PermissionDenied, msg: "not a member",
		},
		{
			name: "member whose newest session gave no relay ID",
			setup: func(_ *testing.T, g *visitRig) {
				g.ref = nil
				g.join(dp.Revision)
			},
			code: rpc.PermissionDenied, msg: "not a member",
		},
		{
			name: "member whose newest session gave another relay ID",
			setup: func(_ *testing.T, g *visitRig) {
				g.ref = &dp.RelayRef{Id: strangerID}
				g.join(dp.Revision)
			},
			code: rpc.PermissionDenied, msg: "not a member",
		},
		{
			name: "relay ID of the newest session of a member",
			setup: func(_ *testing.T, g *visitRig) {
				g.ref = &dp.RelayRef{Id: strangerID}
				g.join(dp.Revision)
			},
			claims: func(c *dp.GrantClaims) { c.RelayId = strangerID },
			cert:   func(c *visitCerts) *tls.Certificate { return c.stranger },
		},
		{name: "member that is lost", setup: lost},
		{name: "member that said restart", setup: restart, code: rpc.PermissionDenied, msg: "not a member"},
		{
			name: "member that came back after a restart",
			setup: func(t *testing.T, g *visitRig) {
				restart(t, g)
				g.join(dp.Revision)
			},
		},
		{
			name: "member that left the member set",
			setup: func(_ *testing.T, g *visitRig) {
				g.m.SetMembers(nil)
				g.deliver()
			},
			code: rpc.PermissionDenied, msg: "not a member",
		},

		// The session of the caller.
		{
			name: "session with no Session call",
			caller: func(_ *testing.T, g *visitRig) *bridgeEnd {
				return g.sessionOf(dp.Mode_MODE_QUIC, server, spareSocket, nil)
			},
			code: rpc.FailedPrecondition, msg: "local_routes_only",
		},
		{
			name: "Session call that takes the routes of other relays",
			caller: func(_ *testing.T, g *visitRig) *bridgeEnd {
				return g.sessionOf(dp.Mode_MODE_QUIC, server, spareSocket, &dp.Hello{Version: dp.LocalVersion("test"), Name: "base"})
			},
			code: rpc.FailedPrecondition, msg: "local_routes_only",
		},
		{
			name: "session with an attachment",
			caller: func(t *testing.T, g *visitRig) *bridgeEnd {
				e := g.guest(dp.Mode_MODE_QUIC, server, spareSocket)
				require.NoError(t, g.r.attach(e.s, attachment("z", "fd00:7::/96")))
				return e
			},
			code: rpc.FailedPrecondition, msg: "attachment",
		},
		{
			name: "session that had an attachment",
			caller: func(t *testing.T, g *visitRig) *bridgeEnd {
				e := g.guest(dp.Mode_MODE_QUIC, server, spareSocket)
				require.NoError(t, g.r.attach(e.s, attachment("z", "fd00:7::/96")))
				_, _, err := g.r.detach(e.s, "z")
				require.NoError(t, err)
				return e
			},
			code: rpc.FailedPrecondition, msg: "attachment",
		},
		{
			name: "session with a route",
			caller: func(t *testing.T, g *visitRig) *bridgeEnd {
				e := g.guest(dp.Mode_MODE_QUIC, server, spareSocket)
				require.NoError(t, g.r.AddRoute(e.s, netip.MustParsePrefix("fd00:7::/96"), "z"))
				return e
			},
			code: rpc.FailedPrecondition, msg: "attachment",
		},
		{
			name:  "closed session",
			setup: func(_ *testing.T, g *visitRig) { g.r.removeSession(g.v.s) },
			code:  rpc.Unauthenticated, msg: "closed",
		},

		// The owner that the address has now.
		{
			name: "address of an attachment of this relay",
			setup: func(_ *testing.T, g *visitRig) {
				g.local("o", spareSocket, prefixA)
			},
			code: rpc.AlreadyExists, msg: "another owner",
		},
		{
			name:  "address of an attachment of the agent on this relay",
			setup: func(_ *testing.T, g *visitRig) { g.local("server", spareSocket, prefixA) },
			code:  rpc.AlreadyExists, msg: "another owner",
		},
		{
			name: "presence shows another agent on the address",
			setup: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", other, "base", 8, prefixA), 20))
			},
			code: rpc.AlreadyExists, msg: "another owner",
		},
		{
			name: "presence shows another agent of the subject on the address",
			setup: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", server, "second", 8, prefixA), 20))
			},
			code: rpc.AlreadyExists, msg: "another owner",
		},
		{
			name: "presence shows the agent of the caller by its name",
			setup: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", server, "base", 8, prefixA), 20))
			},
		},
		{name: "presence has no entry for the address", setup: func(_ *testing.T, g *visitRig) { g.announce(goneAt("x", 20)) }},
		{
			name: "presence shows another agent in a shorter route",
			setup: func(_ *testing.T, g *visitRig) {
				g.announce(goneAt("x", 20), atGen(liveEntry("y", other, "base", 8, "fd00:a::/64"), 20))
			},
		},
		{
			name: "visitor of another agent has the address",
			setup: func(t *testing.T, g *visitRig) {
				g.announce(goneAt("x", 20))
				more(1, other, prefixA)(t, g)
			},
			code: rpc.AlreadyExists, msg: "another visitor",
		},

		// The limit.
		{name: "one more visitor session of the agent", setup: more(1, server, prefixA)},
		{name: "two more visitor sessions of the agent", setup: more(2, server, prefixA), code: rpc.ResourceExhausted, msg: "limit"},
		{
			name: "two more visitor sessions of the agent with another prefix",
			setup: func(t *testing.T, g *visitRig) {
				more(2, server, "fd00:a2::/96")(t, g)
			},
			code: rpc.ResourceExhausted, msg: "limit",
		},
		{
			name: "two more visitor sessions of the agent, and one ended",
			setup: func(t *testing.T, g *visitRig) {
				more(2, server, prefixA)(t, g)
				g.r.removeSession(g.ends[server+"0"].s)
			},
		},
		{name: "two visitor sessions of another agent", setup: more(2, phone, phoneNet)},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
				defer g.stop()
				if tc.setup != nil {
					tc.setup(t, g)
				}
				e := g.v
				if tc.caller != nil {
					e = tc.caller(t, g)
				}
				before, n := g.visitOf(e.s), g.visitors()
				c, cert := g.claims(), certs.home
				if tc.claims != nil {
					tc.claims(c)
				}
				if tc.cert != nil {
					cert = tc.cert(certs)
				}
				grant, err := SignGrant(cert, c)
				require.NoError(t, err)
				if tc.grant != nil {
					tc.grant(grant)
				}
				vpc := vpcA
				if tc.vpc != (VPCKey{}) {
					vpc = tc.vpc
				}
				err = g.r.startVisit(e.s, &dp.VisitRequest{Vpc: ref(vpc), Address: cmp.Or(tc.addr, brServer), Grant: grant}, time.Now())

				assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
				if tc.code != rpc.OK {
					assert.ErrorContains(t, err, tc.msg)
					assert.Equal(t, before, g.visitOf(e.s), "a call that the relay refuses changes no visit")
					assert.Equal(t, n, g.visitors())
					return
				}
				assert.Equal(t, cmp.Or(tc.prefix, prefixA), g.visitOf(e.s))
				assert.Equal(t, n+1, g.visitors())
				// The sessions of the relay reach the address on the session of the caller.
				g.ends["caller"] = e
				assert.Contains(t, g.via(g.frame(g.q, brQ, cmp.Or(tc.addr, brServer))), "caller")
			})
		})
	}
}

// TestVisitNoMesh calls Visit on a relay with no mesh.
func TestVisitNoMesh(t *testing.T) {
	ca := newCA(t)
	h := newHarness(t, ca)
	a := h.mustDial(t, ca.agentCert(t, vpcA, "laptop"))
	open(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := a.c.Visit(ctx, &dp.VisitRequest{Vpc: ref(vpcA), Address: brServer})
	assert.Equal(t, rpc.Unimplemented, rpc.CodeOf(err), "error: %v", err)
}

// TestVisitPaths sends one thing before a visit, in the visit and after the
// end of its grant, and checks who gets it each time.
func TestVisitPaths(t *testing.T) {
	// noEntry ends the attachment of server on relay-a, so its address has no route.
	noEntry := func(_ *testing.T, g *visitRig) { g.announce(goneAt("x", 20)) }
	// second makes a session of phone visit for all of the test.
	second := func(t *testing.T, g *visitRig) {
		w := g.guest(dp.Mode_MODE_QUIC, phone, spareSocket)
		c := g.claimsOf(phone, "ph", phoneNet)
		c.NotAfter = timestamppb.New(time.Now().Add(time.Hour))
		require.NoError(t, g.visit(w, phoneAddr, c))
		g.ends["w"] = w
	}
	cases := []struct {
		name  string
		psp   bool // The visitor session is in PSP mode.
		setup func(t *testing.T, g *visitRig)
		send  func(g *visitRig) func()
		// Who gets it before the visit, in the visit and after it.
		before, during, after string
	}{
		// From a session of this relay to the address of the visitor.
		{
			name:   "peer frame of an agent of this relay",
			send:   func(g *visitRig) func() { return g.frame(g.q, brQ, brServer) },
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			name: "peer frame when the home relay has no entry", setup: noEntry,
			send:   func(g *visitRig) func() { return g.frame(g.q, brQ, brServer) },
			during: "visitor",
		},
		{
			name:   "data frame of an agent of this relay",
			send:   func(g *visitRig) func() { return g.data(g.q, brQ, brServer) },
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			name: "data frame to a PSP-mode visitor", psp: true,
			send:   func(g *visitRig) func() { return g.data(g.q, brQ, brServer) },
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			name:   "PSP packet to the relay of a PSP-mode agent",
			send:   func(g *visitRig) func() { return g.data(g.p, brP, brServer) },
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			name:   "PSP packet of a row",
			setup:  func(t *testing.T, g *visitRig) { require.NoError(t, g.register(brServer, rowTTL, 5)) },
			send:   func(g *visitRig) func() { return g.psp(rowSrc, 5) },
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			// The grant has only the addresses of the attachment.
			name:   "advertised route of the home attachment",
			send:   func(g *visitRig) func() { return g.data(g.q, brQ4, brServer4) },
			before: "relay-a", during: "relay-a", after: "relay-a",
		},
		{
			name:   "address in a longer route of this relay",
			setup:  func(_ *testing.T, g *visitRig) { g.local("o", spareSocket, "fd00:a::8000:0/113") },
			send:   func(g *visitRig) func() { return g.frame(g.q, brQ, "fd00:a::8000:1") },
			before: "o", during: "o", after: "o",
		},
		{
			name: "address in a shorter route of this relay",
			setup: func(t *testing.T, g *visitRig) {
				noEntry(t, g)
				g.local("o", spareSocket, "fd00:a::/64")
			},
			send:   func(g *visitRig) func() { return g.frame(g.q, brQ, brServer) },
			before: "o", during: "visitor", after: "o",
		},

		// From the visitor. A session of a subject sends data from the routes of
		// its subject, also before its visit.
		{
			name:   "peer frame of the visitor to an agent of this relay",
			send:   func(g *visitRig) func() { return g.frame(g.v, brServer, brQ) },
			during: "q",
		},
		{
			name: "peer frame of the visitor to an address of another relay",
			send: func(g *visitRig) func() { return g.frame(g.v, brServer, phoneAddr) },
		},
		{
			name:   "peer frame of an agent of this relay to that address",
			send:   func(g *visitRig) func() { return g.frame(g.q, brQ, phoneAddr) },
			before: "relay-a", during: "relay-a", after: "relay-a",
		},
		{
			name: "peer frame of the visitor to another visitor", setup: second,
			send: func(g *visitRig) func() { return g.frame(g.v, brServer, phoneAddr) },
		},
		{
			name: "peer frame of an agent of this relay to that visitor", setup: second,
			send:   func(g *visitRig) func() { return g.frame(g.q, brQ, phoneAddr) },
			before: "w", during: "w", after: "w",
		},
		{
			name: "peer frame of the visitor from an address of another agent",
			send: func(g *visitRig) func() { return g.frame(g.v, phoneAddr, brQ) },
		},
		{
			name: "peer frame of the visitor from an advertised route of its agent",
			send: func(g *visitRig) func() { return g.frame(g.v, brServer4, brQ) },
		},
		{
			name:   "data frame of the visitor to an agent of this relay",
			send:   func(g *visitRig) func() { return g.data(g.v, brServer, brQ) },
			before: "q", during: "q", after: "q",
		},
		{
			name: "data frame of the visitor when the home relay has no entry", setup: noEntry,
			send:   func(g *visitRig) func() { return g.data(g.v, brServer, brQ) },
			during: "q",
		},
		{
			name: "data frame of the visitor from an address of another agent", setup: noEntry,
			send: func(g *visitRig) func() { return g.data(g.v, phoneAddr, brQ) },
		},
		{
			name: "data frame of the visitor to an address of another relay",
			send: func(g *visitRig) func() { return g.data(g.v, brServer, phoneAddr) },
		},
		{
			name:   "data frame of an agent of this relay to that address",
			send:   func(g *visitRig) func() { return g.data(g.q, brQ, phoneAddr) },
			before: "relay-a", during: "relay-a", after: "relay-a",
		},
		{
			// The session reaches the other visitor only while it is no visitor itself.
			name: "data frame of the visitor to another visitor", setup: second,
			send:   func(g *visitRig) func() { return g.data(g.v, brServer, phoneAddr) },
			before: "w", after: "w",
		},
		{
			name: "PSP packet to the relay of a PSP-mode visitor", psp: true, setup: noEntry,
			send:   func(g *visitRig) func() { return g.data(g.v, brServer, brQ) },
			during: "q",
		},
		{
			name: "PSP packet to the relay of a PSP-mode visitor to an address of another relay", psp: true,
			send: func(g *visitRig) func() { return g.data(g.v, brServer, phoneAddr) },
		},

		// From another relay.
		{
			name: "peer frame of another relay to the address of the visitor",
			send: func(g *visitRig) func() { return g.member(phoneTag, phoneAddr, brServer) },
		},
		{
			name:   "peer frame of another relay to an agent of this relay",
			send:   func(g *visitRig) func() { return g.member(phoneTag, phoneAddr, brQ) },
			before: "q", during: "q", after: "q",
		},
		{
			name:   "peer frame of the agent of the visitor through its home relay",
			send:   func(g *visitRig) func() { return g.member(inTag, brServer, brQ) },
			before: "q", during: "q", after: "q",
		},
		{
			name: "trunk packet of another relay to the address of the visitor",
			send: func(g *visitRig) func() { return g.trunkData(phoneTag, phoneAddr, brServer) },
		},
		{
			name: "trunk packet of another relay to a PSP-mode visitor", psp: true,
			send: func(g *visitRig) func() { return g.trunkData(phoneTag, phoneAddr, brServer) },
		},
		{
			name:   "trunk packet of another relay to an agent of this relay",
			send:   func(g *visitRig) func() { return g.trunkData(phoneTag, phoneAddr, brQ) },
			before: "q", during: "q", after: "q",
		},
		{
			name:   "trunk packet of the agent of the visitor through its home relay",
			send:   func(g *visitRig) func() { return g.trunkData(inTag, brServer, brQ) },
			before: "q", during: "q", after: "q",
		},
		{
			name: "row of another relay to the address of the visitor",
			setup: func(_ *testing.T, g *visitRig) {
				g.give(&dp.SPIRow{Vpc: ref(vpcA), SenderTag: phoneTag, Spi: 0x90, Destination: brServer, ExpiresIn: durationpb.New(inTTL)})
			},
			send: func(g *visitRig) func() { return g.trunkPSP(0x90) },
		},
		{
			name:   "row of the agent of the visitor through its home relay",
			setup:  func(_ *testing.T, g *visitRig) { g.give(serverRow(0x91, inTTL)) },
			send:   func(g *visitRig) func() { return g.trunkPSP(0x91) },
			before: "laptop", during: "laptop", after: "laptop",
		},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mode := dp.Mode_MODE_QUIC
				if tc.psp {
					mode = dp.Mode_MODE_PSP
				}
				g := newVisitRig(t, cfg, certs, mode)
				defer g.stop()
				if tc.setup != nil {
					tc.setup(t, g)
				}
				send := tc.send(g)
				assert.Equal(t, tc.before, g.via(send), "before the visit")
				g.enter()
				assert.Equal(t, tc.during, g.via(send), "in the visit")
				g.expire()
				require.Empty(t, g.visitOf(g.v.s), "the visit ends with its grant")
				assert.Equal(t, tc.after, g.via(send), "after the visit")
			})
		})
	}
}

// TestVisitContent checks the bytes that a visitor gets: a peer frame, the PSP
// packet of a row, and a NoRoute for an address of another relay.
func TestVisitContent(t *testing.T) {
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	synctest.Test(t, func(t *testing.T) {
		g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
		defer g.stop()
		require.NoError(t, g.register(brServer, rowTTL, 5))
		g.enter()

		require.Equal(t, "visitor", g.via(g.frame(g.q, brQ, brServer)))
		assert.Equal(t, [][]byte{peerconn.EncodeFromRelay(nil, netip.MustParseAddr(brQ), []byte("hi"))}, g.v.frames)

		pkt, out := g.packet(5, 100)
		require.Len(t, out, 1)
		assert.Equal(t, netip.MustParseAddrPort(visitSocket), out[0].to)
		assert.Equal(t, pkt, out[0].b, "the PSP packet does not change")

		noRoutes(g.r, g.v.s)
		g.via(g.frame(g.v, brServer, phoneAddr))
		assert.Equal(t, []string{phoneAddr}, noRoutes(g.r, g.v.s), "NoRoute for a peer frame")
		time.Sleep(noRouteInterval)
		g.via(g.data(g.v, brServer, phoneAddr))
		assert.Equal(t, []string{phoneAddr}, noRoutes(g.r, g.v.s), "NoRoute for a data frame")
		assert.Empty(t, noRoutes(g.r, g.q.s))
	})
}

// TestVisitRows checks where the rows to the address of a visitor go at the
// start and at the end of the visit, and what relay-a learns of them.
func TestVisitRows(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, g *visitRig)
		late  bool // The row starts in the visit, not before it.
		// spare makes a session of laptop with no attachment, so with no tag, the
		// sender. Its row must start in the visit.
		spare bool
		end   func(t *testing.T, g *visitRig) // Ends the visit. Nil closes the session.
		// Messages that relay-a gets at the start of the visit and at its end.
		atStart, atEnd [][]*dp.SPIRow
		// Receiver of the row before the visit, in it and after it.
		before, during, after string
	}{
		{
			name:    "row from before the visit",
			atStart: [][]*dp.SPIRow{{goneRow(5)}}, atEnd: [][]*dp.SPIRow{{liveRow(5, rowTTL)}},
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			name:    "visit that ends with its grant",
			end:     func(_ *testing.T, g *visitRig) { g.expire() },
			atStart: [][]*dp.SPIRow{{goneRow(5)}}, atEnd: [][]*dp.SPIRow{{liveRow(5, rowTTL-visitSpan)}},
			before: "relay-a", during: "visitor", after: "relay-a",
		},
		{
			name:   "row that starts in the visit",
			late:   true,
			atEnd:  [][]*dp.SPIRow{{liveRow(5, rowTTL)}},
			during: "visitor", after: "relay-a",
		},
		{
			// The row has no receiver at the end.
			name: "entry of the home relay ends in the visit",
			end: func(_ *testing.T, g *visitRig) {
				g.announce(goneAt("x", 20))
				g.r.removeSession(g.v.s)
			},
			atStart: [][]*dp.SPIRow{{goneRow(5)}},
			before:  "relay-a", during: "visitor",
		},
		{
			// A sender with no tag has no row to another relay.
			name: "sender with no tag",
			late: true, spare: true,
			during: "visitor",
		},
		{
			name:    "attachment of this relay takes the prefix",
			end:     func(_ *testing.T, g *visitRig) { g.local("o", "192.0.2.40:1", prefixA) },
			atStart: [][]*dp.SPIRow{{goneRow(5)}},
			before:  "relay-a", during: "visitor", after: "o",
		},
		{
			name: "row to a shorter route of this relay",
			setup: func(_ *testing.T, g *visitRig) {
				g.announce(goneAt("x", 20))
				g.local("o", "192.0.2.40:1", "fd00:a::/64")
			},
			before: "o", during: "visitor", after: "o",
		},
		{
			name: "row to a longer route of this relay",
			setup: func(_ *testing.T, g *visitRig) {
				g.local("o", "192.0.2.40:1", "fd00:a::/112")
			},
			before: "o", during: "o", after: "o",
		},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
				defer g.stop()
				if tc.setup != nil {
					tc.setup(t, g)
				}
				sender, socket := g.laptop, rowSrc
				if tc.spare {
					sender, socket = g.guest(dp.Mode_MODE_PSP, laptop, spareSocket).s, spareSocket
				}
				row := func() error {
					return g.r.registerSPI(sender, register(vpcA, brServer, rowTTL, 5), time.Now())
				}
				if !tc.late {
					require.NoError(t, row())
				} else if tc.spare {
					assert.Equal(t, rpc.NotFound, rpc.CodeOf(row()), "row to another relay of a sender with no tag")
				}
				g.a.take()
				assert.Equal(t, tc.before, g.receiver(sender, socket, 5), "before the visit")

				g.enter()
				assert.Empty(t, diffRows(tc.atStart, g.a.take()), "rows that relay-a gets at the start")
				if tc.late {
					require.NoError(t, row())
					assert.Empty(t, g.a.take(), "relay-a gets no row to a visitor")
				}
				assert.Equal(t, tc.during, g.receiver(sender, socket, 5), "in the visit")

				if tc.end != nil {
					tc.end(t, g)
				} else {
					g.r.removeSession(g.v.s)
				}
				require.Empty(t, g.visitOf(g.v.s))
				assert.Empty(t, diffRows(tc.atEnd, g.a.take()), "rows that relay-a gets at the end")
				assert.Equal(t, tc.after, g.receiver(sender, socket, 5), "after the visit")
				g.r.mu.RLock()
				assert.Empty(t, g.v.s.inbound, "rows to a session with no visit")
				g.r.mu.RUnlock()
			})
		})
	}
}

// TestVisitTwoSessions checks that the newest visitor session of an agent gets
// what goes to the address, and then the session before it.
func TestVisitTwoSessions(t *testing.T) {
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	synctest.Test(t, func(t *testing.T) {
		g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
		defer g.stop()
		require.NoError(t, g.register(brServer, rowTTL, 5))
		frame := g.frame(g.q, brQ, brServer)
		g.enter()
		require.Equal(t, "visitor", g.receiver(g.laptop, rowSrc, 5))
		g.a.take()

		newer := g.guest(dp.Mode_MODE_QUIC, server, spareSocket)
		g.ends["newer"] = newer
		require.NoError(t, g.visit(newer, brServer, g.claims()))
		assert.Equal(t, "newer", g.receiver(g.laptop, rowSrc, 5))
		assert.Equal(t, "newer", g.via(frame))
		// The two sessions send from the address.
		assert.Equal(t, "q", g.via(g.frame(g.v, brServer, brQ)))
		assert.Equal(t, "q", g.via(g.frame(newer, brServer, brQ)))

		g.r.removeSession(newer.s)
		assert.Equal(t, "visitor", g.receiver(g.laptop, rowSrc, 5))
		assert.Equal(t, "visitor", g.via(frame))
		assert.Empty(t, g.a.take(), "relay-a gets no row while the agent has a visitor session")

		g.r.removeSession(g.v.s)
		assert.Equal(t, "relay-a", g.receiver(g.laptop, rowSrc, 5))
		assert.Equal(t, "relay-a", g.via(frame))
		assert.Empty(t, diffRows([][]*dp.SPIRow{{liveRow(5, rowTTL)}}, g.a.take()))
		assert.Zero(t, g.visitors())
	})
}

// TestVisitEnd checks what ends a visit and what does not. A peer frame of q
// to the address shows who has it then.
func TestVisitEnd(t *testing.T) {
	cases := []struct {
		name  string
		step  func(t *testing.T, g *visitRig)
		stays bool
		frame string // Who gets the peer frame after the step.
	}{
		{name: "session closes", step: func(_ *testing.T, g *visitRig) { g.r.removeSession(g.v.s) }, frame: "relay-a"},
		{
			name: "one second before the end of the grant",
			step: func(_ *testing.T, g *visitRig) {
				time.Sleep(visitSpan - time.Second)
				synctest.Wait()
				g.r.Sweep(time.Now())
			},
			stays: true, frame: "visitor",
		},
		{name: "end of the grant", step: func(_ *testing.T, g *visitRig) { g.expire() }, frame: "relay-a"},
		{
			name:  "attachment of another agent on this relay takes the prefix",
			step:  func(_ *testing.T, g *visitRig) { g.local("o", spareSocket, prefixA) },
			frame: "o",
		},
		{
			name:  "attachment of the agent on this relay takes the prefix",
			step:  func(_ *testing.T, g *visitRig) { g.local("server", spareSocket, prefixA) },
			frame: "server",
		},
		{
			name: "presence gives the prefix to another agent",
			step: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", other, "base", 8, prefixA), 20))
			},
			frame: "relay-a",
		},
		{
			name: "presence gives the prefix to another agent of the subject",
			step: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", server, "second", 8, prefixA), 20))
			},
			frame: "relay-a",
		},
		{
			name: "presence gives the prefix to another session of the agent",
			step: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", server, "base", 8, prefixA), 20))
			},
			stays: true, frame: "visitor",
		},
		{
			name:  "attachment of the home relay ends",
			step:  func(_ *testing.T, g *visitRig) { g.announce(goneAt("x", 20)) },
			stays: true, frame: "visitor",
		},
		{
			name: "home relay says restart",
			step: func(_ *testing.T, g *visitRig) {
				g.end(g.sess, meshRestart)
				g.deliver()
			},
			stays: true, frame: "visitor",
		},
		{
			name: "home relay is lost",
			step: func(_ *testing.T, g *visitRig) {
				g.end(g.sess, meshLost)
				time.Sleep(meshDownAfter + time.Second)
				g.deliver()
			},
			stays: true, frame: "visitor",
		},
		{
			name: "home relay leaves the member set",
			step: func(_ *testing.T, g *visitRig) {
				g.m.SetMembers(nil)
				g.deliver()
			},
			stays: true, frame: "visitor",
		},
		{
			name: "relay roots change",
			step: func(_ *testing.T, g *visitRig) {
				g.trust.mu.Lock()
				defer g.trust.mu.Unlock()
				g.trust.roots, g.trust.rootsErr = x509.NewCertPool(), errors.New("snapshot too old")
			},
			stays: true, frame: "visitor",
		},
		{
			// Permit runs for each frame.
			name:  "Permit denies all",
			step:  func(_ *testing.T, g *visitRig) { g.r.SetPermit(denyAll) },
			stays: true,
		},
		{
			name: "session asks for an attachment",
			step: func(t *testing.T, g *visitRig) {
				err := g.r.attach(g.v.s, attachment("z", "fd00:7::/96"))
				assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)
				assert.Empty(t, routeTable(g.r, vpcA)["fd00:7::/96"])
			},
			stays: true, frame: "visitor",
		},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
				defer g.stop()
				g.enter()
				require.Equal(t, "visitor", g.via(g.frame(g.q, brQ, brServer)))

				tc.step(t, g)
				// The sweep of each second ends no visit before its time.
				g.r.Sweep(time.Now())
				if tc.stays {
					assert.Equal(t, prefixA, g.visitOf(g.v.s))
					assert.Equal(t, 1, g.visitors())
				} else {
					assert.Empty(t, g.visitOf(g.v.s))
					assert.Zero(t, g.visitors())
				}
				assert.Equal(t, tc.frame, g.via(g.frame(g.q, brQ, brServer)))
			})
		})
	}
}

// TestVisitNoRouteChange checks that a visit changes the routes of no session:
// the address keeps the route that it has, or has none.
func TestVisitNoRouteChange(t *testing.T) {
	cases := []struct {
		name  string
		setup func(g *visitRig)
	}{
		{name: "address with a route of the home relay"},
		{name: "address with no route", setup: func(g *visitRig) { g.announce(goneAt("x", 20)) }},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
				defer g.stop()
				// watcher takes the routes of other relays, and q does not.
				watcher := g.sessionOf(dp.Mode_MODE_QUIC, agentID(vpcA, "watcher"), spareSocket, thisRevision())
				require.Contains(t, routeChanges(g.r, watcher.s), "+x "+prefixA)
				if tc.setup != nil {
					tc.setup(g)
				}
				// The visitor has the routes of the attachments of this relay only.
				assert.ElementsMatch(t, []string{
					"+att-" + rowSrc + " fd00:1::/96", "+att-q " + brQNet, "+att-q " + brQNet4, "+att-p " + brPNet,
				}, routeChanges(g.r, g.v.s))
				sessions := []*Session{watcher.s, g.q.s, g.laptop, g.v.s}
				for _, s := range sessions {
					routeChanges(g.r, s)
				}
				table := routeTable(g.r, vpcA)

				g.enter()
				for _, s := range sessions {
					assert.Empty(t, routeChanges(g.r, s), "route changes of %s at the start", s.id.ID)
				}
				assert.Equal(t, table, routeTable(g.r, vpcA))
				g.r.removeSession(g.v.s)
				for _, s := range sessions[:3] {
					assert.Empty(t, routeChanges(g.r, s), "route changes of %s at the end", s.id.ID)
				}
				assert.Equal(t, table, routeTable(g.r, vpcA))
			})
		})
	}
}

// TestVisitorRows checks the rows that a visitor can have as their sender:
// to the attachments of this relay only.
func TestVisitorRows(t *testing.T) {
	cases := []struct {
		name   string
		sender string // "visitor", or "laptop", which has an attachment.
		dst    string
		code   rpc.Code
		to     string // Receiver of the row.
	}{
		{name: "to an agent of this relay", sender: "visitor", dst: brQ, to: "q"},
		{name: "to an address of another relay", sender: "visitor", dst: phoneAddr, code: rpc.NotFound},
		{name: "to the address of another visitor", sender: "visitor", dst: "fd00:a2::1", code: rpc.NotFound},
		{name: "to an address with no route", sender: "visitor", dst: "fd00:f::1", code: rpc.NotFound},
		{name: "agent with an attachment to an address of another relay", sender: "laptop", dst: phoneAddr, to: "relay-a"},
		{name: "agent with an attachment to the address of another visitor", sender: "laptop", dst: "fd00:a2::1", to: "w"},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_PSP)
				defer g.stop()
				// w is a visitor of phone with an address that has no route.
				w := g.guest(dp.Mode_MODE_QUIC, phone, spareSocket)
				require.NoError(t, g.visit(w, "fd00:a2::1", g.claimsOf(phone, "ph2", "fd00:a2::/96")))
				g.ends["w"] = w
				g.enter()
				sender, socket := g.v.s, visitSocket
				if tc.sender == "laptop" {
					sender, socket = g.laptop, rowSrc
				}
				err := g.r.registerSPI(sender, register(vpcA, tc.dst, rowTTL, 5), time.Now())
				assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
				assert.Equal(t, tc.to, g.receiver(sender, socket, 5))
			})
		})
	}
}

// TestVisitResolvePeer checks the ResolvePeer answers in a visit. A visitor gets
// no peer on another relay, and its address stays an address of its home relay.
func TestVisitResolvePeer(t *testing.T) {
	cases := []struct {
		name    string
		visitor bool // The caller is the visitor. If not, it is an agent with an attachment.
		dst     string
		want    dp.Reach // Zero is NotFound.
	}{
		{name: "visitor for an agent of this relay", visitor: true, dst: brQ, want: dp.Reach_REACH_LOCAL},
		{name: "visitor for an address of another relay", visitor: true, dst: phoneAddr},
		{name: "agent of this relay for that address", dst: phoneAddr, want: dp.Reach_REACH_TRUNK},
		{name: "agent of this relay for the address of the visitor", dst: brServer, want: dp.Reach_REACH_TRUNK},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_PSP)
				defer g.stop()
				g.enter()
				s := g.v.s
				if !tc.visitor {
					s = g.caller(reachCaller{rev: dp.Revision, mode: dp.Mode_MODE_PSP})
				}
				res, err := g.resolve(s, tc.dst)
				if tc.want == dp.Reach_REACH_UNSPECIFIED {
					assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "answer: %v, error: %v", res, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.want, res.GetReach())
			})
		})
	}
}

// TestVisitsIndex checks the visitor sessions that a domain keeps by prefix.
func TestVisitsIndex(t *testing.T) {
	a, b, c := &Session{}, &Session{}, &Session{}
	wide, narrow, far := netip.MustParsePrefix("fd00:a::/64"), netip.MustParsePrefix("fd00:a::/96"), netip.MustParsePrefix("fd00:b::/96")
	type step struct {
		remove bool
		p      netip.Prefix
		s      *Session
	}
	cases := []struct {
		name  string
		steps []step
		addr  string
		want  *Session
		bits  int
		lens  []int
	}{
		{name: "no visit", addr: "fd00:a::1"},
		{name: "one visit", steps: []step{{p: narrow, s: a}}, addr: "fd00:a::1", want: a, bits: 96, lens: []int{96}},
		{name: "address out of the prefix", steps: []step{{p: narrow, s: a}}, addr: "fd00:a:0:0:1::1", lens: []int{96}},
		{name: "IPv4 address", steps: []step{{p: narrow, s: a}}, addr: "10.0.0.1", lens: []int{96}},
		{
			name:  "newest session of a prefix",
			steps: []step{{p: narrow, s: a}, {p: narrow, s: b}},
			addr:  "fd00:a::1", want: b, bits: 96, lens: []int{96},
		},
		{
			name:  "session before the newest, after it ended",
			steps: []step{{p: narrow, s: a}, {p: narrow, s: b}, {remove: true, p: narrow, s: b}},
			addr:  "fd00:a::1", want: a, bits: 96, lens: []int{96},
		},
		{
			name:  "newest session, after the one before it ended",
			steps: []step{{p: narrow, s: a}, {p: narrow, s: b}, {remove: true, p: narrow, s: a}},
			addr:  "fd00:a::1", want: b, bits: 96, lens: []int{96},
		},
		{
			name:  "longest prefix",
			steps: []step{{p: narrow, s: a}, {p: wide, s: b}},
			addr:  "fd00:a::1", want: a, bits: 96, lens: []int{96, 64},
		},
		{
			name:  "shorter prefix for an address out of the longer one",
			steps: []step{{p: wide, s: b}, {p: narrow, s: a}},
			addr:  "fd00:a::1:0:1", want: b, bits: 64, lens: []int{96, 64},
		},
		{
			name:  "shorter prefix after the longer one ended",
			steps: []step{{p: wide, s: b}, {p: narrow, s: a}, {remove: true, p: narrow, s: a}},
			addr:  "fd00:a::1", want: b, bits: 64, lens: []int{64},
		},
		{
			name:  "length that another prefix still has",
			steps: []step{{p: narrow, s: a}, {p: far, s: c}, {remove: true, p: narrow, s: a}},
			addr:  "fd00:b::1", want: c, bits: 96, lens: []int{96},
		},
		{
			name:  "session that has no visit with the prefix",
			steps: []step{{p: narrow, s: a}, {remove: true, p: narrow, s: b}, {remove: true, p: far, s: a}},
			addr:  "fd00:a::1", want: a, bits: 96, lens: []int{96},
		},
		{name: "all ended", steps: []step{{p: narrow, s: a}, {remove: true, p: narrow, s: a}}, addr: "fd00:a::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v visits
			for _, st := range tc.steps {
				if st.remove {
					v.remove(st.p, st.s)
				} else {
					v.add(st.p, st.s)
				}
			}
			got, bits := v.of(netip.MustParseAddr(tc.addr))
			assert.Same(t, tc.want, got)
			assert.Equal(t, tc.bits, bits)
			assert.ElementsMatch(t, tc.lens, v.lens)
			assert.True(t, slices.IsSortedFunc(v.lens, func(a, b int) int { return b - a }), "longest first: %v", v.lens)
			for p, ss := range v.by {
				assert.NotEmpty(t, ss, "sessions of %s", p)
			}
		})
	}
}

// TestReachAllocs checks that the lookup of each packet makes no allocation,
// with no visit and with one.
func TestReachAllocs(t *testing.T) {
	cases := []struct {
		name    string
		visit   string // Prefix of a visit of a third session. Empty is no visit.
		visitor bool   // The sender is that session.
		want    string // Subject of the session that the sender reaches.
	}{
		{name: "no visit", want: "receiver"},
		{name: "visit with another prefix", visit: "fd00:9::/96", want: "receiver"},
		{name: "visit with the prefix of the destination", visit: "fd00::2/128", want: "guest"},
		{name: "sender is a visitor", visit: "fd00:9::/96", visitor: true, want: "receiver"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(nil, Config{})
			src := addSession(t, r, vpcA, "sender", "192.0.2.1:1000", "fd00::1/128").Session
			addSession(t, r, vpcA, "receiver", "192.0.2.2:2000", "fd00::2/128")
			guest := addSession(t, r, vpcA, "guest", "192.0.2.3:3000").Session
			if tc.visit != "" {
				p := netip.MustParsePrefix(tc.visit)
				r.mu.Lock()
				guest.visit.Store(&visitor{{prefix: p}})
				r.domains[vpcA].visits.add(p, guest)
				r.mu.Unlock()
			}
			if tc.visitor {
				src = guest
			}
			dst := netip.MustParseAddr("fd00::2")
			r.mu.RLock()
			defer r.mu.RUnlock()
			assert.Equal(t, tc.want, r.reach(src, dst).s.id.ID)
			assert.Zero(t, testing.AllocsPerRun(1000, func() { r.reach(src, dst) }))
		})
	}
}

// In the tests of more visits, v has the visit with prefixA and the grant of the
// attachment x. The attachment y of server on relay-a has moreNet.
const (
	moreNet  = "fd00:a2::/96"
	moreAddr = "fd00:a2::1"
)

// TestVisitMore checks the Visit calls on a session that is a visitor, and who
// gets the frames for the two addresses then.
func TestVisitMore(t *testing.T) {
	nth := func(i int) string { return fmt.Sprintf("fd00:b:%x::/96", i) }
	// fill gives v the visits with n more prefixes.
	fill := func(n int) func(t *testing.T, g *visitRig) {
		return func(t *testing.T, g *visitRig) {
			for i := range n {
				p := netip.MustParsePrefix(nth(i))
				require.NoError(t, g.visit(g.v, p.Addr().Next().String(), g.claimsOf(server, fmt.Sprint("n", i), p.String())))
			}
		}
	}
	second := func(subject, socket, prefix string) func(t *testing.T, g *visitRig) {
		return func(t *testing.T, g *visitRig) {
			e := g.guest(dp.Mode_MODE_QUIC, subject, socket)
			require.NoError(t, g.visit(e, netip.MustParsePrefix(prefix).Addr().Next().String(), g.claimsOf(subject, "x", prefix)))
		}
	}
	cases := []struct {
		name   string
		setup  func(t *testing.T, g *visitRig)
		claims func(g *visitRig) *dp.GrantClaims // Nil is the grant of y with moreNet.
		addr   string                            // Empty is moreAddr.
		code   rpc.Code
		msg    string
		want   string // Visits of v after the call. Empty is prefixA only.
		added  int    // Change of the number of visits that the router keeps.
		more   string // Who gets a peer frame of q to moreAddr after the call.
	}{
		{name: "grant of another attachment", want: prefixA + "," + moreNet, added: 1, more: "visitor"},
		{
			name:   "new grant for the prefix of the session",
			claims: func(g *visitRig) *dp.GrantClaims { return g.claimsOf(server, "x2", prefixA) },
			addr:   brServer, want: prefixA,
		},
		{
			name:   "second prefix of the first grant",
			claims: func(g *visitRig) *dp.GrantClaims { c := g.claims(); c.Addresses = []string{prefixA, moreNet}; return c },
			want:   prefixA + "," + moreNet, added: 1, more: "visitor",
		},
		{
			name:  "agent has the most visitor sessions",
			setup: func(t *testing.T, g *visitRig) { second(server, spareSocket, prefixA)(t, g) },
			want:  prefixA + "," + moreNet, added: 1, more: "visitor",
		},
		{
			name:  "session has one visit below the limit",
			setup: fill(maxVisitPrefixes - 2),
			added: 1, more: "visitor",
		},
		{
			name:  "session has the most visits",
			setup: fill(maxVisitPrefixes - 1),
			code:  rpc.ResourceExhausted, msg: "limit",
		},
		{
			name:   "session has the most visits, and the grant is for one of them",
			setup:  fill(maxVisitPrefixes - 1),
			claims: func(g *visitRig) *dp.GrantClaims { return g.claimsOf(server, "x2", prefixA) },
			addr:   brServer,
		},
		{
			name: "first visit has the grant of another relay",
			setup: func(_ *testing.T, g *visitRig) {
				g.r.mu.Lock()
				defer g.r.mu.Unlock()
				first := *(*g.v.s.visit.Load())[0]
				first.relay = strangerID
				g.v.s.visit.Store(&visitor{&first})
			},
			code: rpc.FailedPrecondition, msg: "relay-z",
		},
		{
			name:  "visitor of another agent has the prefix",
			setup: second(other, spareSocket, moreNet),
			code:  rpc.AlreadyExists, msg: "another visitor",
		},
		{
			name:   "grant of another subject",
			claims: func(g *visitRig) *dp.GrantClaims { return g.claimsOf(other, "y", moreNet) },
			code:   rpc.PermissionDenied, msg: "not of the caller",
		},
		{
			name:  "attachment of this relay has the prefix",
			setup: func(_ *testing.T, g *visitRig) { g.local("o", spareSocket, moreNet) },
			code:  rpc.AlreadyExists, msg: "another owner", more: "o",
		},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
				defer g.stop()
				g.enter()
				if tc.setup != nil {
					tc.setup(t, g)
				}
				before, n := g.visitOf(g.v.s), g.visitors()
				c := g.claimsOf(server, "y", moreNet)
				if tc.claims != nil {
					c = tc.claims(g)
				}
				err := g.visit(g.v, cmp.Or(tc.addr, moreAddr), c)

				assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
				if tc.code != rpc.OK {
					assert.ErrorContains(t, err, tc.msg)
					assert.Equal(t, before, g.visitOf(g.v.s), "a call that the relay refuses changes no visit")
				} else if tc.want != "" {
					assert.Equal(t, tc.want, g.visitOf(g.v.s))
				}
				assert.Equal(t, n+tc.added, g.visitors())
				assert.Equal(t, tc.more, g.via(g.frame(g.q, brQ, moreAddr)), "peer frame to the address of the second attachment")
				// The visitor sends from the second address only with its visit.
				from := ""
				if tc.more == "visitor" {
					from = "q"
					g.r.mu.RLock()
					to := g.r.reach(g.q.s, netip.MustParseAddr(moreAddr))
					g.r.mu.RUnlock()
					assert.Equal(t, c.GetAttachmentId(), to.origin, "attachment of the grant that has the second address")
				}
				assert.Equal(t, from, g.via(g.frame(g.v, moreAddr, brQ)), "peer frame from the address of the second attachment")
				assert.Equal(t, from, g.via(g.data(g.v, moreAddr, brQ)), "data frame from the address of the second attachment")
				assert.Equal(t, "q", g.via(g.frame(g.v, brServer, brQ)), "peer frame from the address of the first attachment")
			})
		})
	}
}

// TestVisitMoreEnd checks that each visit of a session ends alone. v has the
// visits with prefixA and with moreNet.
func TestVisitMoreEnd(t *testing.T) {
	cases := []struct {
		name string
		// late is the time from the end of the first grant to the end of the second.
		late time.Duration
		step func(t *testing.T, g *visitRig)
		want string // Visits of v after the step.
		// Who gets a peer frame of q to the first address and to the second.
		first, more string
	}{
		{
			name: "Detach with the attachment of the second grant",
			step: func(t *testing.T, g *visitRig) { assert.True(t, g.r.leave(g.v.s, "y")) },
			want: prefixA, first: "visitor",
		},
		{
			name: "Detach with the attachment of the first grant",
			step: func(t *testing.T, g *visitRig) { assert.True(t, g.r.leave(g.v.s, "x")) },
			want: moreNet, first: "relay-a", more: "visitor",
		},
		{
			name: "Detach with an attachment of no grant",
			step: func(t *testing.T, g *visitRig) { assert.False(t, g.r.leave(g.v.s, "z")) },
			want: prefixA + "," + moreNet, first: "visitor", more: "visitor",
		},
		{
			name: "end of the first grant", late: time.Second,
			step: func(_ *testing.T, g *visitRig) { g.expire() },
			want: moreNet, first: "relay-a", more: "visitor",
		},
		{
			name:  "end of the two grants",
			step:  func(_ *testing.T, g *visitRig) { g.expire() },
			first: "relay-a",
		},
		{
			name: "attachment of another agent on this relay takes the second prefix",
			step: func(_ *testing.T, g *visitRig) { g.local("o", spareSocket, moreNet) },
			want: prefixA, first: "visitor", more: "o",
		},
		{
			name: "presence gives the second prefix to another agent",
			step: func(_ *testing.T, g *visitRig) {
				g.announce(atGen(liveEntry("y", other, "base", 8, moreNet), 20))
			},
			want: prefixA, first: "visitor", more: "relay-a",
		},
		{
			name:  "session closes",
			step:  func(_ *testing.T, g *visitRig) { g.r.removeSession(g.v.s) },
			first: "relay-a",
		},
	}
	cfg, certs := trunkRigConfig(t), newVisitCerts(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newVisitRig(t, cfg, certs, dp.Mode_MODE_QUIC)
				defer g.stop()
				g.enter()
				c := g.claimsOf(server, "y", moreNet)
				c.NotAfter = timestamppb.New(time.Now().Add(visitSpan + tc.late))
				require.NoError(t, g.visit(g.v, moreAddr, c))
				require.Equal(t, 2, g.visitors())
				require.NoError(t, g.r.registerSPI(g.laptop, register(vpcA, moreAddr, rowTTL, 5), time.Now()))
				require.Equal(t, "visitor", g.receiver(g.laptop, rowSrc, 5))

				tc.step(t, g)

				assert.Equal(t, tc.want, g.visitOf(g.v.s))
				n := 0
				if tc.want != "" {
					n = strings.Count(tc.want, ",") + 1
				}
				assert.Equal(t, n, g.visitors())
				assert.Equal(t, tc.first, g.via(g.frame(g.q, brQ, brServer)), "peer frame to the first address")
				assert.Equal(t, tc.more, g.via(g.frame(g.q, brQ, moreAddr)), "peer frame to the second address")
				// The row to the second address stays with the visitor only in its visit.
				if tc.more == "visitor" {
					assert.Equal(t, "visitor", g.receiver(g.laptop, rowSrc, 5))
				} else {
					g.r.mu.RLock()
					for w := range g.v.s.inbound {
						assert.NotEqual(t, netip.MustParseAddr(moreAddr), w.dst, "row to a prefix with no visit")
					}
					g.r.mu.RUnlock()
				}
			})
		})
	}
}
