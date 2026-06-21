// SPDX-License-Identifier: AGPL-3.0-only

// Command workerd-manager is the data-plane half of the APO-796 ServiceManager.
// It runs the single resident workerd (a stock-workerd dispatcher in a
// gVisor/runsc sandbox), serves the dispatcher control channel that feeds
// customer isolates over WorkerLoader, and reconciles compute ServiceRevisions
// into resident readiness. It runs as a privileged sidecar in the backplane pod;
// the control-plane minting reconciler runs separately in the apiserver.
package main

import (
	"log/slog"
	"os"

	"github.com/apoxy-dev/apoxy/pkg/workerd/manager"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

func main() {
	// DispatchRunsc MUST be the very first call: the same /proc/self/exe is
	// re-exec'd for every runsc subcommand and for the Sentry/gofer children, and
	// those invocations must reach gVisor's maincli rather than our manager loop.
	// It returns only when this is the primary host invocation (no-op off linux).
	sandbox.DispatchRunsc()

	if err := manager.Run(); err != nil {
		slog.Error("workerd-manager exited", "error", err)
		os.Exit(1)
	}
}
