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
	"net/netip"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

type Attachment struct {
	ID        string
	VPC       VPCKey
	NetworkID uint32
	Name      string
	Labels    map[string]string
	// Subject is the SPIFFE ID of the agent.
	Subject string
	// Routes are the prefixes that the attachment advertises.
	Routes []netip.Prefix
	// Addresses are the prefixes from Addresses.Assign.
	Addresses []netip.Prefix
}

// Addresses assigns overlay addresses to attachments. The relay host
// implements it.
type Addresses interface {
	// Assign returns the prefixes of a new attachment.
	Assign(ctx context.Context, a *Attachment) ([]netip.Prefix, error)
	// Release frees the prefixes of an attachment that ended.
	Release(a *Attachment)
}

// Attach adds an attachment to the session of the caller: addresses from
// Addresses, routes in the VPC, and a grant that the relay signs.
func (srv *Server) Attach(ctx context.Context, in *dp.AttachRequest) (*dp.AttachResponse, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	key, err := s.vpc(in.GetVpc())
	if err != nil {
		return nil, err
	}
	a, err := newAttachment(key, s.id.ID, in)
	if err != nil {
		return nil, err
	}
	n, err := srv.network(key)
	if err != nil {
		return nil, err
	}
	a.NetworkID = n.ID
	addrs, err := srv.Addresses.Assign(ctx, a)
	if err != nil {
		if rpc.CodeOf(err) == rpc.Unknown {
			err = rpc.Errorf(rpc.Unavailable, "no addresses: %v", err)
		}
		return nil, err
	}
	a.Addresses = addrs
	notAfter := s.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(identity.CertLifetime)
	}
	cert, err := srv.cert()
	if err != nil {
		srv.Addresses.Release(a)
		return nil, err
	}
	// The grant cannot outlive the agent cert.
	grant, err := SignGrant(cert, &dp.GrantClaims{
		Vpc:          &dp.VPCRef{ProjectId: key.Project, VpcUid: key.UID, NetworkId: n.ID},
		AttachmentId: a.ID,
		Subject:      a.Subject,
		Addresses:    prefixStrings(addrs),
		RelayId:      srv.RelayID,
		NotAfter:     timestamppb.New(notAfter),
	})
	if err == nil {
		err = srv.R.attach(s, a)
	}
	if err != nil {
		srv.Addresses.Release(a)
		if rpc.CodeOf(err) == rpc.Unknown {
			err = rpc.Errorf(rpc.Internal, "grant: %v", err)
		}
		return nil, err
	}
	return &dp.AttachResponse{AttachmentId: a.ID, Grant: grant}, nil
}

// Detach removes an attachment of the session of the caller: its routes, and
// its addresses.
func (srv *Server) Detach(ctx context.Context, in *dp.DetachRequest) (*emptypb.Empty, error) {
	s, err := srv.R.caller(ctx)
	if err != nil {
		return nil, err
	}
	a, err := srv.R.detach(s, in.GetAttachmentId())
	if err != nil {
		return nil, err
	}
	srv.Addresses.Release(a)
	return &emptypb.Empty{}, nil
}

func newAttachment(vpc VPCKey, subject string, in *dp.AttachRequest) (*Attachment, error) {
	if errs := validation.IsDNS1123Subdomain(in.GetName()); len(errs) > 0 {
		return nil, rpc.Errorf(rpc.InvalidArgument, "name %q: %s", in.GetName(), strings.Join(errs, "; "))
	}
	for k, v := range in.GetLabels() {
		errs := append(validation.IsQualifiedName(k), validation.IsValidLabelValue(v)...)
		if len(errs) > 0 {
			return nil, rpc.Errorf(rpc.InvalidArgument, "label %q: %s", k, strings.Join(errs, "; "))
		}
	}
	a := &Attachment{VPC: vpc, Name: in.GetName(), Labels: in.GetLabels(), Subject: subject}
	for _, r := range in.GetRoutes() {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, rpc.Errorf(rpc.InvalidArgument, "route: %v", err)
		}
		a.Routes = append(a.Routes, p.Masked())
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	a.ID = hex.EncodeToString(id[:])
	return a, nil
}

// attach adds the routes of a to s. It adds all of them or none.
func (r *Router) attach(s *Session, a *Attachment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var added []netip.Prefix
	for _, p := range append(append([]netip.Prefix{}, a.Addresses...), a.Routes...) {
		p = p.Masked()
		if slices.Contains(s.routes, p) {
			continue
		}
		if err := r.addRoute(s, p, a.ID); err != nil {
			for _, q := range added {
				r.deleteRoute(s, q)
			}
			s.routes = s.routes[:len(s.routes)-len(added)]
			return err
		}
		added = append(added, p)
	}
	s.attachments = append(s.attachments, a)
	return nil
}

// detach removes the attachment id and the routes that it added from s.
func (r *Router) detach(s *Session, id string) (*Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := slices.IndexFunc(s.attachments, func(a *Attachment) bool { return a.ID == id })
	if i < 0 {
		return nil, rpc.Errorf(rpc.NotFound, "no attachment %q on this session", id)
	}
	a := s.attachments[i]
	s.attachments = slices.Delete(s.attachments, i, i+1)
	var gone []netip.Prefix
	if d := r.domains[s.id.VPC]; d != nil {
		for _, p := range s.routes {
			if o, ok := d.routes[p]; ok && o.s == s && o.origin == id {
				gone = append(gone, p)
			}
		}
	}
	for _, p := range gone {
		r.deleteRoute(s, p)
	}
	s.routes = slices.DeleteFunc(s.routes, func(p netip.Prefix) bool { return slices.Contains(gone, p) })
	for w := range s.inbound {
		if r.lookup(w.vpc, w.dst) != s {
			r.removeRow(w)
		}
	}
	return a, nil
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

// grantAlgorithm is the signature algorithm of SignGrant for a key type.
var grantAlgorithm = map[x509.PublicKeyAlgorithm]x509.SignatureAlgorithm{
	x509.Ed25519: x509.PureEd25519,
	x509.ECDSA:   x509.ECDSAWithSHA256,
	x509.RSA:     x509.SHA256WithRSAPSS,
}

// VerifyGrant checks the relay chain, relay ID, signature and end of g, and
// returns its claims. The caller checks the VPC and the subject.
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
	if !now.Before(c.GetNotAfter().AsTime()) {
		return nil, errors.New("grant has ended")
	}
	return c, nil
}
