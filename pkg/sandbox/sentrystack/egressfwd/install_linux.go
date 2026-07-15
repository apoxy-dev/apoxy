// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package egressfwd

import (
	sentrystack "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

// init arms the core sentrystack's egress data path. The core wires lo+eth0 and
// then calls ForwarderInstaller (if set) from inside Init; blank-importing this
// package sets it, so every sandbox that boots in this binary gets the egress
// forwarder. A binary that does not import this package leaves the hook nil and
// gets a lo+eth0 sandbox with no outbound forwarder (fail-closed egress) — the
// database/sql-driver registration pattern.
//
// Import sites (each an explicit opt-in): the Stage-0 spike acceptance test and,
// once the gate passes, cmd/workerd-manager's sentrystack_linux.go.
func init() {
	sentrystack.ForwarderInstaller = InstallEgress
}
