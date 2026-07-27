//go:build !linux

package router

import (
	"context"
	"errors"
	"net/netip"

	"github.com/apoxy-dev/icx"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// ICXTunRouter requires /dev/net/tun and netlink; it is linux-only. This stub
// keeps callers compiling on other platforms.
type ICXTunRouter struct {
	Handler *icx.Handler
}

var errTunLinuxOnly = errors.New("the TUN datapath is only supported on linux")

func NewICXTunRouter(_ ...Option) (*ICXTunRouter, error) {
	return nil, errTunLinuxOnly
}

func (r *ICXTunRouter) Start(ctx context.Context) error { return errTunLinuxOnly }

func (r *ICXTunRouter) AddAddr(_ netip.Prefix, _ connection.Connection) error {
	return errTunLinuxOnly
}

func (r *ICXTunRouter) DelAddr(_ netip.Prefix) error { return errTunLinuxOnly }

func (r *ICXTunRouter) AddRoute(_ netip.Prefix) error { return errTunLinuxOnly }

func (r *ICXTunRouter) DelRoute(_ netip.Prefix) error { return errTunLinuxOnly }

func (r *ICXTunRouter) Close() error { return nil }
