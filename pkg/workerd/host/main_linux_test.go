// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package host_test

import (
	"os"
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"

	// Register the gVisor PluginStack (lo + eth0) that DispatchRunsc requires
	// before it hands off to the Sentry — the same blank import cmd/workerd-manager
	// uses. The host package also pulls this in transitively (host -> egressfwd ->
	// sentrystack), but import it explicitly so the acceptance harness doesn't
	// depend on that chain staying intact.
	_ "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

// TestMain makes the host test binary runsc-capable, exactly as the production
// workerd-manager main does. The sandbox core boots the Sentry by re-exec'ing
// /proc/self/exe with a runsc subcommand, so those invocations must reach
// gVisor's maincli (DispatchRunsc) before the testing framework parses flags —
// otherwise `runsc create` hits the Go test flag parser and exits 2 with no
// debug log. It also installs the child reaper the manager runs so resident
// teardown's `runsc wait` doesn't hang on re-parented Sentry/gofer zombies.
// Needed by the resident acceptance tests (build tag `acceptance`); a no-op for
// the ordinary linux unit tests in this package.
func TestMain(m *testing.M) {
	sandbox.DispatchRunsc()
	host.StartChildReaper()
	os.Exit(m.Run())
}
