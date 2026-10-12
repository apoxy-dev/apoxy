// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/validation"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

type Attachment struct {
	ID        string
	VPC       VPCKey
	NetworkID uint32
	// Network is the name of the VPC network object, from Networks.
	Network string
	Name    string
	Labels  map[string]string
	// Subject is the SPIFFE ID of the agent.
	Subject string
	// Routes are the advertised prefixes that the relay accepted. The relay sets
	// them after Addresses.Assign.
	Routes []netip.Prefix
	// Addresses are the prefixes from Addresses.Assign.
	Addresses []netip.Prefix
	// Rank is the order that the agent gives to this connection among its
	// connections to relays. The lower one is selected first.
	Rank uint32

	seq   uint64    // Attach order in the router.
	since time.Time // Time of the attach.
	count *attCount // Counts of the packets to the attachment. Set at the attach.
	// attached is the presence generation of the attach. It does not change.
	attached uint64
	// gen is the last presence generation: that of the attach, then that of
	// each state change. Zero after the end.
	gen uint64
	// activeFrom is the end of the hold time: holdTime after the attach, or
	// after the last return to the normal state.
	activeFrom time.Time
}

// Addresses assigns overlay addresses to attachments. The relay host
// implements it.
type Addresses interface {
	// Assign returns the prefixes of a new attachment. It calls onLost when
	// the lease of the prefixes ends, also before Assign returns. At this call
	// a has no Routes.
	Assign(ctx context.Context, a *Attachment, onLost func()) ([]netip.Prefix, error)
	// Attached tells the host that the attach of a is complete. It must not
	// block. Release can come first when the session ends during the attach.
	Attached(a *Attachment)
	// Release frees the prefixes of an attachment that ended.
	Release(a *Attachment)
}

// OverlayAddr returns the address that an agent uses in a prefix from
// Addresses.Assign: the first address after the base.
func OverlayAddr(p netip.Prefix) netip.Addr {
	return p.Addr().Next()
}

// Attach adds an attachment to the session of the caller: addresses from
// Addresses, routes in the VPC, and a grant that the relay signs.
func (srv *Server) Attach(ctx context.Context, in *dp.AttachRequest) (*dp.AttachResponse, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	// The route table has the agent name and the instance of the Hello.
	if !srv.R.hasHello(s) {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "attach needs a Session call with Hello first")
	}
	key, err := s.vpc(in.GetVpc())
	if err != nil {
		return nil, err
	}
	a, routes, err := newAttachment(key, s.id.ID, in)
	if err != nil {
		return nil, err
	}
	n, err := srv.network(key)
	if err != nil {
		return nil, err
	}
	a.NetworkID, a.Network = n.ID, n.Name
	addrs, err := srv.Addresses.Assign(ctx, a, func() {
		// Remove forwarding state before the slot can be assigned again.
		srv.R.removeSession(s)
		s.close(dp.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "attachment address lease ended")
	})
	if err != nil {
		if rpc.CodeOf(err) == rpc.Unknown {
			err = rpc.Errorf(rpc.Unavailable, "no addresses: %v", err)
		}
		return nil, err
	}
	a.Addresses = addrs
	statuses := a.acceptRoutes(routes)
	notAfter := s.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(identity.CertLifetime)
	}
	// The grant of Attach cannot outlive the agent cert.
	grant, err := srv.signGrant(a, notAfter)
	if err == nil {
		err = srv.R.attach(s, a)
	}
	if err != nil {
		srv.Addresses.Release(a)
		return nil, err
	}
	srv.Addresses.Attached(a)
	// An agent below announcerRevision does not know the statuses.
	if !srv.R.agentAtLeast(s, announcerRevision) {
		statuses = nil
	}
	return &dp.AttachResponse{AttachmentId: a.ID, Grant: grant, Routes: statuses}, nil
}

// signGrant returns a grant for a that ends at notAfter.
func (srv *Server) signGrant(a *Attachment, notAfter time.Time) (*dp.AttachmentGrant, error) {
	cert, err := srv.cert()
	if err != nil {
		return nil, err
	}
	grant, err := SignGrant(cert, &dp.GrantClaims{
		Vpc:          vpcRef(a),
		AttachmentId: a.ID,
		Subject:      a.Subject,
		Addresses:    prefixStrings(a.Addresses),
		RelayId:      srv.RelayID,
		NotAfter:     timestamppb.New(notAfter),
	})
	if err != nil {
		return nil, rpc.Errorf(rpc.Internal, "grant: %v", err)
	}
	return grant, nil
}

// Grant returns a new grant for an attachment of the session of the caller. It
// has the claims of the grant of Attach, and it ends grantLife from now.
func (srv *Server) Grant(ctx context.Context, in *dp.GrantRequest) (*dp.GrantResponse, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	grant, err := srv.grant(s, in.GetAttachmentId(), time.Now())
	if err != nil {
		return nil, err
	}
	return &dp.GrantResponse{Grant: grant}, nil
}

func (srv *Server) grant(s *Session, id string, now time.Time) (*dp.AttachmentGrant, error) {
	a, err := srv.R.attachment(s, id)
	if err != nil {
		return nil, err
	}
	return srv.signGrant(a, now.Add(grantLife))
}

// attachment returns the attachment id of s. A visitor session has none.
func (r *Router) attachment(s *Session, id string) (*Attachment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// A closed session keeps its attachments for their last counters.
	if s.closed {
		return nil, rpc.Errorf(rpc.Unauthenticated, "relay session closed")
	}
	i := s.attachmentIndex(id)
	if i < 0 {
		return nil, rpc.Errorf(rpc.NotFound, "no attachment %q on this session", id)
	}
	return s.attachments[i], nil
}

// attachmentIndex returns the index of the attachment id of s, or -1.
// Router.mu must be held.
func (s *Session) attachmentIndex(id string) int {
	return slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.ID == id })
}

// routeResult returns the answer for the advertised route p of an attachment
// with the addresses addrs. An agent finds the VPC network in the same way.
func routeResult(p netip.Prefix, addrs []netip.Prefix) dp.RouteResult {
	inVPC := func(a netip.Prefix) bool { return p.Overlaps(tunnet.NetworkPrefixOf(a.Addr())) }
	switch {
	case p.Bits() == 0:
		return dp.RouteResult_ROUTE_RESULT_DEFAULT_ROUTE
	case p.Addr().Is4In6():
		return dp.RouteResult_ROUTE_RESULT_IPV4_MAPPED
	case slices.ContainsFunc(addrs, inVPC):
		return dp.RouteResult_ROUTE_RESULT_OVERLAPS_VPC
	}
	return dp.RouteResult_ROUTE_RESULT_ACCEPTED
}

// acceptRoutes gives a the routes that the relay accepts, and returns the
// answer for each route in the order of routes. Call it after a has addresses.
func (a *Attachment) acceptRoutes(routes []netip.Prefix) []*dp.RouteStatus {
	out := make([]*dp.RouteStatus, len(routes))
	for i, p := range routes {
		res := routeResult(p, a.Addresses)
		out[i] = &dp.RouteStatus{Prefix: p.String(), Result: res}
		if res == dp.RouteResult_ROUTE_RESULT_ACCEPTED {
			a.Routes = append(a.Routes, p)
			continue
		}
		slog.Info("Refused an advertised route", "vpc", a.VPC.UID, "attachment", a.ID, "prefix", p, "reason", res.String())
	}
	return out
}

// Detach removes an attachment of the session of the caller: its routes, and
// its addresses.
func (srv *Server) Detach(ctx context.Context, in *dp.DetachRequest) (*emptypb.Empty, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	// A visitor session has no attachment: the call ends its visit with that grant.
	if srv.R.leave(s, in.GetAttachmentId()) {
		return &emptypb.Empty{}, nil
	}
	a, last, err := srv.R.detach(s, in.GetAttachmentId())
	if err != nil {
		return nil, err
	}
	srv.R.ended(last)
	srv.Addresses.Release(a)
	return &emptypb.Empty{}, nil
}

// ValidateAttachment checks the name and the labels of an attachment.
func ValidateAttachment(name string, labels map[string]string) error {
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("name %q: %s", name, strings.Join(errs, "; "))
	}
	for k, v := range labels {
		errs := append(validation.IsQualifiedName(k), validation.IsValidLabelValue(v)...)
		if len(errs) > 0 {
			return fmt.Errorf("label %q: %s", k, strings.Join(errs, "; "))
		}
	}
	return nil
}

// newAttachment returns an attachment with no routes, and the advertised
// routes of the request in the masked form, which acceptRoutes checks.
func newAttachment(vpc VPCKey, subject string, in *dp.AttachRequest) (*Attachment, []netip.Prefix, error) {
	if err := ValidateAttachment(in.GetName(), in.GetLabels()); err != nil {
		return nil, nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	a := &Attachment{VPC: vpc, Name: in.GetName(), Labels: in.GetLabels(), Subject: subject, Rank: in.GetRank()}
	var routes []netip.Prefix
	for _, r := range in.GetRoutes() {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, nil, rpc.Errorf(rpc.InvalidArgument, "route: %v", err)
		}
		routes = append(routes, p.Masked())
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	a.ID = hex.EncodeToString(id[:])
	return a, routes, nil
}

// attach adds a to s, and an entry to the route table for each address and each
// advertised route of a. An advertised route that another attachment
// announces is no error: a gets one more entry in the set of its prefix.
func (r *Router) attach(s *Session, a *Attachment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.closed {
		return rpc.Errorf(rpc.FailedPrecondition, "session closed")
	}
	// The other relays of a mesh refuse an entry with more prefixes.
	if n := len(a.Addresses) + len(a.Routes); r.presence != nil && n > maxEntryPrefixes {
		return rpc.Errorf(rpc.InvalidArgument, "attachment has %d addresses and routes, and a relay with a mesh takes at most %d", n, maxEntryPrefixes)
	}
	if s.visit.Load() != nil {
		return rpc.Errorf(rpc.FailedPrecondition, "a visitor session takes no attachment")
	}
	d := r.domain(s.id.VPC)
	// Check all prefixes first, so that a failed attach changes nothing.
	for _, p := range slices.Concat(a.Addresses, a.Routes) {
		if !p.IsValid() {
			return rpc.Errorf(rpc.InvalidArgument, "prefix not valid")
		}
	}
	// This relay gives each address to one attachment. An entry of another relay
	// with the address stays: the selection has the two.
	for _, p := range a.Addresses {
		if d.announcedHere(p.Masked(), s) {
			return rpc.Errorf(rpc.AlreadyExists, "address %s has another attachment on this relay", p.Masked())
		}
	}
	// The first attachment of s gives s its trunk tag.
	if s.tag == 0 {
		if s.tag = r.newTag(); s.tag == 0 {
			return rpc.Errorf(rpc.ResourceExhausted, "relay has no free trunk tag")
		}
	}
	now := time.Now()
	r.attaches++
	a.seq, a.since, a.count = r.attaches, now, &attCount{}
	a.attached = r.nextGen(now)
	a.gen, a.activeFrom = a.attached, now.Add(holdTime)
	if len(s.attachments) == 0 {
		// The first attachment does not get what s sent before it.
		s.rxBase = r.rxOf(s, nil)
	}
	for _, p := range slices.Concat(a.Addresses, a.Routes) {
		p = p.Masked()
		t := target{s: s, origin: a.ID, att: a}
		// A new attachment has the state of its session.
		r.addAnnouncer(d, p, newAnnouncer(t, r.relayOf(s), p, a.attached, a.Rank, s.state, a.activeFrom))
	}
	s.attachments = append(s.attachments, a)
	r.announce(s, a)
	return nil
}

// announcedHere reports whether a session of this relay that is not s has an
// entry for p. Router.mu must be held.
func (d *domain) announcedHere(p netip.Prefix, s *Session) bool {
	set := d.routes[p]
	return set != nil && slices.ContainsFunc(set.entries, func(e *announcer) bool { return e.s != s && e.s.home == "" })
}

// detach removes the attachment id from s, with its entries in the route
// table. It returns the attachment and its last counters.
func (r *Router) detach(s *Session, id string) (*Attachment, AttachmentStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := s.attachmentIndex(id)
	if i < 0 {
		return nil, AttachmentStats{}, rpc.Errorf(rpc.NotFound, "no attachment %q on this session", id)
	}
	a := s.attachments[i]
	s.attachments = slices.Delete(s.attachments, i, i+1)
	if d := r.domains[s.id.VPC]; d != nil {
		for _, p := range slices.Concat(a.Addresses, a.Routes) {
			r.removeAnnouncer(d, p.Masked(), s, id)
		}
	}
	r.withdraw(a)
	// The sync adds the last XDP counts of the removed rows to the totals.
	r.syncXDP(time.Now())
	return a, r.last(s, a, i == 0), nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func (srv *Server) cert() (*tls.Certificate, error) {
	if srv.Cert == nil {
		return nil, rpc.Errorf(rpc.Unavailable, "relay has no grant key")
	}
	c, err := srv.Cert()
	if err != nil {
		return nil, rpc.Errorf(rpc.Unavailable, "relay cert: %v", err)
	}
	return c, nil
}

// SignGrant encodes claims and signs them with the key of cert. The grant
// carries the chain of cert.
func SignGrant(cert *tls.Certificate, claims *dp.GrantClaims) (*dp.AttachmentGrant, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("no relay cert")
	}
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("relay key type %T cannot sign", cert.PrivateKey)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(claims)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	var sig []byte
	switch key.Public().(type) {
	case ed25519.PublicKey:
		sig, err = key.Sign(rand.Reader, b, crypto.Hash(0))
	case *ecdsa.PublicKey:
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	case *rsa.PublicKey:
		sig, err = key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	default:
		return nil, fmt.Errorf("relay key type %T is not supported", key.Public())
	}
	if err != nil {
		return nil, err
	}
	return &dp.AttachmentGrant{Claims: b, Signature: sig, RelayChain: cert.Certificate}, nil
}

// ErrGrantRevision is the error of VerifyGrant for a grant that needs a newer
// protocol revision than this build has.
var ErrGrantRevision = errors.New("grant needs a newer protocol revision")

// grantAlgorithm is the signature algorithm of SignGrant for a key type.
var grantAlgorithm = map[x509.PublicKeyAlgorithm]x509.SignatureAlgorithm{
	x509.Ed25519: x509.PureEd25519,
	x509.ECDSA:   x509.ECDSAWithSHA256,
	x509.RSA:     x509.SHA256WithRSAPSS,
}

// VerifyGrant checks the relay chain, relay ID, signature, minimum revision and
// end of g, and returns its claims. The caller checks the VPC and the subject.
func VerifyGrant(g *dp.AttachmentGrant, roots *x509.CertPool, now time.Time) (*dp.GrantClaims, error) {
	chain := g.GetRelayChain()
	if len(chain) == 0 {
		return nil, errors.New("grant has no relay cert")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("grant relay cert: %w", err)
	}
	inter := x509.NewCertPool()
	for _, der := range chain[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("grant relay chain: %w", err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("grant relay cert does not verify: %w", err)
	}
	if err := leaf.CheckSignature(grantAlgorithm[leaf.PublicKeyAlgorithm], g.GetClaims(), g.GetSignature()); err != nil {
		return nil, fmt.Errorf("grant signature does not verify: %w", err)
	}
	c := &dp.GrantClaims{}
	if err := proto.Unmarshal(g.GetClaims(), c); err != nil {
		return nil, fmt.Errorf("grant claims: %w", err)
	}
	if err := leaf.VerifyHostname(c.GetRelayId()); err != nil {
		return nil, fmt.Errorf("grant relay cert does not name relay %q", c.GetRelayId())
	}
	// A build of a lower revision does not know all claims that limit the grant.
	if need := c.GetMinRevision(); need > dp.Revision {
		return nil, fmt.Errorf("%w: the grant needs revision %d, and the verifier has revision %d", ErrGrantRevision, need, dp.Revision)
	}
	if !now.Before(c.GetNotAfter().AsTime()) {
		return nil, errors.New("grant has ended")
	}
	return c, nil
}
