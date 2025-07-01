package net

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	goipam "github.com/metal-stack/go-ipam"
)

type IPAM interface {
	// AllocateV6 allocates an IPv6 address for a peer.
	AllocateV6(r *http.Request) (netip.Prefix, error)

	// AllocateV4 allocates an IPv4 address for a peer.
	AllocateV4(r *http.Request) (netip.Prefix, error)

	// Release releases an IP address for a peer. No-op if the address is not allocated
	// (returns nil).
	Release(peerPrefix netip.Prefix) error
}

const (
	ipv4CidrPrefix = "100.64.0.0/10"
)

type inMemoryIPAM struct {
	ipam                   goipam.Ipamer
	ipv4Prefix, ipv6Prefix *goipam.Prefix
}

// NewInMemoryIPAM creates a new in-memory IPAM instance.
func NewInMemoryIPAM(networkID [4]byte) (IPAM, error) {
	ipam := goipam.New(context.Background())
	ipv4Prefix, err := ipam.NewPrefix(context.Background(), ipv4CidrPrefix)
	if err != nil {
		return nil, err
	}
	ipv6Prefix, err := ipam.NewPrefix(context.Background(), ApoxyNetworkULA(networkID).String())
	if err != nil {
		return nil, err
	}
	return &inMemoryIPAM{
		ipam:       ipam,
		ipv4Prefix: ipv4Prefix,
		ipv6Prefix: ipv6Prefix,
	}, nil
}

func (r *inMemoryIPAM) AllocateV6(_ *http.Request) (netip.Prefix, error) {
	p, err := r.ipam.AcquireChildPrefix(context.Background(), r.ipv6Prefix.Cidr, 96)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.MustParsePrefix(p.Cidr), nil
}

func (r *inMemoryIPAM) AllocateV4(_ *http.Request) (netip.Prefix, error) {
	p, err := r.ipam.AcquireChildPrefix(context.Background(), r.ipv4Prefix.Cidr, 32)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.MustParsePrefix(p.Cidr), nil
}

func (r *inMemoryIPAM) Release(p netip.Prefix) error {
	child := &goipam.Prefix{
		Cidr: p.String(),
	}
	if p.Addr().Is4() {
		child.ParentCidr = r.ipv4Prefix.Cidr
	} else if p.Addr().Is6() {
		child.ParentCidr = r.ipv6Prefix.Cidr
	} else {
		return fmt.Errorf("invalid address type")
	}
	return r.ipam.ReleaseChildPrefix(context.Background(), child)
}
