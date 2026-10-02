// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"errors"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

func startTun(context.Context, context.CancelCauseFunc, *psp.Binding, netip.Addr, netip.Prefix, string) (overlay, error) {
	return nil, errors.New("the tun driver of vpcbench runs only on Linux")
}
