package net

import (
	"context"
	"net/netip"

	goipam "github.com/metal-stack/go-ipam"
)

// IPAM interface defines the methods for managing IP addresses.
type IPAM interface {
	// Allocate allocates a prefix.
	Allocate() (netip.Prefix, error)

	// Release releases an IP address. No-op if the address is not allocated
	// (returns nil).
	Release(peerPrefix netip.Prefix) error

	// TODO(dilyevsky): Method to tell the length of the prefix.
}

const (
	ipv4CidrPrefix = "100.64.0.0/10"
)

type ipamv4 struct {
	ipam   goipam.Ipamer
	prefix *goipam.Prefix
}

func mustParsePrefix(ctx context.Context, ipamer goipam.Ipamer, s string) *goipam.Prefix {
	prefix, err := ipamer.NewPrefix(ctx, s)
	if err != nil {
		panic(err)
	}
	return prefix
}

func NewIPAMv4(ctx context.Context) IPAM {
	ipam := goipam.New(ctx)
	return &ipamv4{
		ipam:   ipam,
		prefix: mustParsePrefix(ctx, ipam, ipv4CidrPrefix),
	}
}

func (r *ipamv4) Allocate() (netip.Prefix, error) {
	p, err := r.ipam.AcquireChildPrefix(context.Background(), r.prefix.Cidr, 32)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.MustParsePrefix(p.Cidr), nil
}

func (r *ipamv4) Release(p netip.Prefix) error {
	child := &goipam.Prefix{
		Cidr:       p.String(),
		ParentCidr: r.prefix.Cidr,
	}
	return r.ipam.ReleaseChildPrefix(context.Background(), child)
}
