package net

import (
	"context"
	"errors"
	"log/slog"
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
	IPv4CidrPrefix = "100.64.0.0/10"
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
		prefix: mustParsePrefix(ctx, ipam, IPv4CidrPrefix),
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
	return releaseChildPrefix(r.ipam, r.prefix.Cidr, p)
}

// releaseChildPrefix releases prefix from its parent. The IPAM keeps its
// allocations in memory only, so it knows nothing after a process restart. An
// address it does not hold is already free and must not fail the release.
func releaseChildPrefix(ipam goipam.Ipamer, parentCidr string, prefix netip.Prefix) error {
	ctx := context.Background()
	_, err := ipam.PrefixFrom(ctx, prefix.String())
	if err == nil {
		err = ipam.ReleaseChildPrefix(ctx, &goipam.Prefix{
			Cidr:       prefix.String(),
			ParentCidr: parentCidr,
		})
	}
	if errors.Is(err, goipam.ErrNotFound) {
		slog.Debug("Address is already released", "prefix", prefix.String(), "parent", parentCidr)
		return nil
	}
	return err
}
