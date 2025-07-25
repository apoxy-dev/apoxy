package net

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"

	goipam "github.com/metal-stack/go-ipam"
)

const (
	// Addresses on ApoxyNet overlay follow this format:
	//   fd61:706f:7879:nnnn:nnuu:eeee:a.a.a.a/128
	// where:
	//  n: unique network identifier
	//  u: unused, reserved for future use
	//  e: endpoint name fnv hash
	//  a: IPv4 address downstream of the tunnel node endpoint
	apoxyULAPrefixS = "fd61:706f:7879::/48"
)

var (
	apoxyULAPrefix = netip.MustParsePrefix(apoxyULAPrefixS)
)

func init() {
	// Ensure that apoxyULAPrefix is exactly 48 bits.
	if apoxyULAPrefix.Bits() != 48 {
		panic("apoxyULAPrefix must be exactly 48 bits")
	}
}

// NetworkID represents a unique identifier for a network.
type NetworkID [3]byte

var (
	// SystemNetworkID is the network ID for the system network (as opposed to a user network).
	SystemNetworkID = NetworkID{0x00, 0x00, 0x00}
)

// NetworkIDHexToBytes converts a hexadecimal network id representation to a byte array.
// Example: NetworkIDHexToBytes("123456") returns [18, 52, 86]
func NetworkIDHexToBytes(h string) (NetworkID, error) {
	if len(h) != 6 {
		return NetworkID{}, fmt.Errorf("hex string must be 6 characters long")
	}

	bs, err := hex.DecodeString(h)
	if err != nil {
		return NetworkID{}, err
	}

	bytes := NetworkID{}
	copy(bytes[:], bs)

	return bytes, nil
}

// NetULA represents a ULA prefix for a network.
type NetULA struct {
	NetID      NetworkID
	EndpointID EndpointID

	ipam   goipam.Ipamer
	prefix netip.Prefix
}

// ULAFromPrefix creates a new NetULA from an IPv6 address.
func ULAFromPrefix(ctx context.Context, prefix netip.Prefix) (*NetULA, error) {
	if !prefix.Addr().Is6() {
		return nil, fmt.Errorf("address must be IPv6")
	}
	addrv6 := prefix.Addr().As16()

	netID := NetworkID([3]byte{addrv6[6], addrv6[7], addrv6[8]})
	endpointID := EndpointID([2]byte{addrv6[10], addrv6[11]})

	return &NetULA{
		NetID:      netID,
		EndpointID: endpointID,

		ipam:   goipam.New(ctx),
		prefix: prefix,
	}, nil
}

// NewULA returns the IPv6 ULA prefix for a project.
func NewULA(ctx context.Context, id NetworkID) *NetULA {
	addr := apoxyULAPrefix.Addr().As16()
	copy(addr[6:], id[:])
	return &NetULA{
		NetID:      id,
		EndpointID: EndpointID{0x00, 0x00},
		ipam:       goipam.New(ctx),
		prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), 80),
	}
}

// NetPrefix returns a prefix with just the network portion.
func (u *NetULA) NetPrefix() netip.Prefix {
	return netip.PrefixFrom(u.prefix.Addr(), 72).Masked()
}

// FullPrefix returns the IPv6 ULA prefix for the network.
func (u *NetULA) FullPrefix() netip.Prefix {
	return u.prefix
}

// EndpointID is and endpoint (e.g a Tunnel Agent, Backplane) which
// is unique within the network.
type EndpointID [2]byte

var (
	// ProxyEndpointID is the endpoint ID for the proxy.
	ProxyEndpointID = EndpointID{0x00, 0x00}
)

// WithEndpoint returns the IPv6 ULA prefix for an endpoint.
func (u *NetULA) WithEndpoint(ctx context.Context, epID EndpointID) (*NetULA, error) {
	parent, err := u.ipam.PrefixFrom(ctx, u.prefix.String())
	if errors.Is(err, goipam.ErrNotFound) {
		parent, err = u.ipam.NewPrefix(ctx, u.prefix.String())
	}
	if err != nil {
		return nil, err
	}

	addr := u.prefix.Addr().As16()
	copy(addr[10:], epID[:])
	prefix := netip.PrefixFrom(netip.AddrFrom16(addr), 96)

	_, err = u.ipam.AcquireSpecificChildPrefix(ctx, parent.String(), prefix.String())
	if err != nil {
		return nil, fmt.Errorf("failed to acquire specific child prefix: %w", err)
	}

	return &NetULA{
		NetID:      u.NetID,
		EndpointID: epID,

		ipam:   u.ipam,
		prefix: prefix,
	}, nil
}

type ulaIPAM struct {
	ipam   goipam.Ipamer
	parent *goipam.Prefix
	bits   uint8
}

// IPAM returns an IPAM that allocates bits-sized ULA prefixes.
func (u *NetULA) IPAM(ctx context.Context, bits uint8) (IPAM, error) {
	if bits <= uint8(u.prefix.Bits()) {
		return nil, fmt.Errorf("bits must be greater than parent prefix bits %d", u.prefix.Bits())
	}
	parent, err := u.ipam.PrefixFrom(ctx, u.prefix.String())
	if errors.Is(err, goipam.ErrNotFound) {
		parent, err = u.ipam.NewPrefix(ctx, u.prefix.String())
	}
	if err != nil {
		return nil, err
	}
	return &ulaIPAM{
		ipam:   u.ipam,
		parent: parent,
		bits:   bits,
	}, nil
}

func (u *ulaIPAM) Allocate() (netip.Prefix, error) {
	p, err := u.ipam.AcquireChildPrefix(context.Background(), u.parent.Cidr, u.bits)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.MustParsePrefix(p.Cidr), nil
}

func (u *ulaIPAM) Release(prefix netip.Prefix) error {
	child := &goipam.Prefix{
		Cidr:       prefix.String(),
		ParentCidr: u.parent.Cidr,
	}
	return u.ipam.ReleaseChildPrefix(context.Background(), child)
}
