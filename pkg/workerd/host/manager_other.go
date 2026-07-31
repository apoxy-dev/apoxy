// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package host

import (
	"errors"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// errUnsupportedPlatform is returned when constructing the gVisor sandbox core
// off Linux.
var errUnsupportedPlatform = errors.New("workerd-host: the gVisor sandbox runtime is only supported on linux")

func newCore(coreConfig) (sandbox.Runtime, error) {
	return nil, errUnsupportedPlatform
}
