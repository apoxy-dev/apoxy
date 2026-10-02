//go:build !linux

package vpc

import (
	"context"
	"errors"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// tunAvailable is false. The tun driver needs Linux.
func tunAvailable() bool { return false }

func startTun(context.Context, context.CancelCauseFunc, *psp.Binding, string, netip.Addr) (overlay, error) {
	return nil, errors.New("the tun driver needs Linux")
}
