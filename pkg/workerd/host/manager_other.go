// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package host

import (
	"errors"

	"github.com/apoxy-dev/clrk/pkg/sandbox"
)

// errUnsupportedPlatform is returned when constructing the gVisor sandbox core
// off linux. The neutral wrapper logic still compiles and unit-tests here
// against a fake sandbox.Runtime.
var errUnsupportedPlatform = errors.New("workerd-host: the gVisor sandbox runtime is only supported on linux")

func newCore(cfg Config) (sandbox.Runtime, error) {
	return nil, errUnsupportedPlatform
}
