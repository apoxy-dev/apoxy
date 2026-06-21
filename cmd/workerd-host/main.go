// SPDX-License-Identifier: AGPL-3.0-only

// Command workerd-host runs stock workerd inside a gVisor/runsc sandbox via
// clrk's extracted pkg/sandbox runtime. It is the artifact a lifecycle
// controller (APO-796 ServiceManager) runs, and serves a worker's fetch handler
// over an HTTP socket (M1 backend mode).
package main

import (
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

func main() {
	// DispatchRunsc MUST be the very first call: the same /proc/self/exe is
	// re-exec'd for every runsc subcommand and for the Sentry/gofer children,
	// and those invocations must reach gVisor's maincli rather than our serve
	// loop. It returns only when this is the primary host invocation (and is a
	// no-op on non-linux).
	sandbox.DispatchRunsc()
	host.Main()
}
