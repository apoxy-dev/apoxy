// SPDX-License-Identifier: AGPL-3.0-only

package host

import "github.com/apoxy-dev/clrk/pkg/sandbox"

// ApplyEgress installs egress routing for a tenant's resident. M1 backend mode
// uses direct dial with no egress data path, so this is a documented no-op that
// names the exact APO-723 extension point: when the sandbox core gains
// EgressController support, the type assertion below drives the
// SetEgressBackends/SetEgressPolicy/SetInvocationID setters. The forwarder
// data path itself is installed by a separate sentrystack ForwarderInstaller
// blank import (also APO-723), mirroring clrk's internal/sentrystack.
func (r *Runtime) ApplyEgress(id sandbox.SandboxID, backends []sandbox.BackendListener, pol *sandbox.Policy) error {
	if ec, ok := r.core.(sandbox.EgressController); ok {
		_ = ec // APO-723 wiring lands here.
	}
	return nil
}
