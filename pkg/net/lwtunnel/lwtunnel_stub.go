//go:build !linux

package lwtunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

var errUnsupported = errors.New("lwtunnel: not supported on this platform")

type geneveOptions struct {
	dev   string
	vni   uint32
	port  uint16
	mtu   int
	netns string
}

// Geneve manages Geneve tunnel interfaces and routes.
type Geneve struct {
	opts *geneveOptions
}

type option func(*geneveOptions)

func WithDevName(dev string) option { return func(o *geneveOptions) { o.dev = dev } }
func WithVNI(vni uint32) option    { return func(o *geneveOptions) { o.vni = vni } }
func WithPort(port uint16) option  { return func(o *geneveOptions) { o.port = port } }
func WithMTU(mtu int) option       { return func(o *geneveOptions) { o.mtu = mtu } }
func WithNetNS(ns string) option   { return func(o *geneveOptions) { o.netns = ns } }

func NewGeneve(opts ...option) *Geneve {
	o := &geneveOptions{dev: "gnv0", vni: 0x61, port: 6081, mtu: DefaultGeneveMTU}
	for _, opt := range opts {
		opt(o)
	}
	return &Geneve{opts: o}
}

func (r *Geneve) SetUp(_ context.Context, _ netip.Addr) error         { return errUnsupported }
func (r *Geneve) SetAddr(_ context.Context, _ netip.Addr) error       { return errUnsupported }
func (r *Geneve) TearDown() error                                     { return errUnsupported }
func (r *Geneve) SyncEndpoints(_ context.Context, _ []Endpoint) error { return errUnsupported }

// Endpoint represents a tunnel route.
type Endpoint struct {
	Dst    tunnet.NetULA
	Remote netip.Addr
}

// IPEncap represents IP tunnel encapsulation (stub for non-Linux).
type IPEncap struct {
	ID     uint32
	Remote net.IP
	TTL    uint8
}

func (e *IPEncap) Type() int               { return 0 }
func (e *IPEncap) Decode(_ []byte) error   { return errUnsupported }
func (e *IPEncap) Encode() ([]byte, error) { return nil, errUnsupported }
func (e *IPEncap) String() string          { return "lwtunnel: unsupported" }
