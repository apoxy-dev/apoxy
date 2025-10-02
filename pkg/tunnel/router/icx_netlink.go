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

func NewICXNetlinkRouter(_ ...Option) (*ICXNotImplementedRouter, error) {
	h, err := icx.NewHandler(icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()))
	if err != nil {
		return nil, fmt.Errorf("failed to create ICX handler: %w", err)
	}

	return &ICXNotImplementedRouter{Handler: h}, nil
}

type ICXNotImplementedRouter struct {
	Handler *icx.Handler
}

func (r *ICXNotImplementedRouter) Start(ctx context.Context) error {
	return errors.New("not implemented")
}

func (r *ICXNotImplementedRouter) AddAddr(_ netip.Prefix, _ connection.Connection) error {
	return errors.New("not implemented")
}

func (r *ICXNotImplementedRouter) DelAddr(_ netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *ICXNotImplementedRouter) AddRoute(dst netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *ICXNotImplementedRouter) DelRoute(dst netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *ICXNotImplementedRouter) Close() error {
	return nil
}
