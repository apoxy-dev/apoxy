//go:build !linux

package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/apoxy-dev/icx"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

func NewICXNetlinkRouter(_ ...Option) (*ICXNetlinkRouter, error) {
	h, err := icx.NewHandler(icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()))
	if err != nil {
		return nil, fmt.Errorf("failed to create ICX handler: %w", err)
	}

	return &ICXNetlinkRouter{Handler: h}, nil
}

type ICXNetlinkRouter struct {
	Handler *icx.Handler
}

func (r *ICXNetlinkRouter) Start(ctx context.Context) error {
	return errors.New("not implemented")
}

func (r *ICXNetlinkRouter) AddAddr(_ netip.Prefix, _ connection.Connection) error {
	return errors.New("not implemented")
}

func (r *ICXNetlinkRouter) DelAddr(_ netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *ICXNetlinkRouter) AddRoute(dst netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *ICXNetlinkRouter) DelRoute(dst netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *ICXNetlinkRouter) Close() error {
	return nil
}

func (r *ICXNetlinkRouter) ResolveMAC(ctx context.Context, addr netip.AddrPort) (tcpip.LinkAddress, error) {
	return "", errors.New("not implemented")
}
