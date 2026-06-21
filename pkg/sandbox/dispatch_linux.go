//go:build linux

package sandbox

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/runsc/cli/maincli"

	"github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
)

// runscSubcommands is the set of argv[1] tokens that mean "this process
// invocation is a runsc subcommand re-exec, not the host controller
// loop." Mirror of runsc/cli/maincli/maincli.go's commands() map plus
// the built-in `help` / `flags` registered by cli.Run. Keep in sync when
// bumping the pinned gvisor commit.
var runscSubcommands = map[string]struct{}{
	"checkpoint":      {},
	"create":          {},
	"delete":          {},
	"events":          {},
	"exec":            {},
	"kill":            {},
	"list":            {},
	"ps":              {},
	"pause":           {},
	"restore":         {},
	"resume":          {},
	"run":             {},
	"spec":            {},
	"start":           {},
	"state":           {},
	"update":          {},
	"wait":            {},
	"do":              {},
	"fscheckpoint":    {},
	"port-forward":    {},
	"tar":             {},
	"install":         {},
	"mitigate":        {},
	"uninstall":       {},
	"nvproxy":         {},
	"trace":           {},
	"cpu-features":    {},
	"debug":           {},
	"statefile":       {},
	"symbolize":       {},
	"usage":           {},
	"read-control":    {},
	"write-control":   {},
	"metric-metadata": {},
	"metric-export":   {},
	"metric-server":   {},
	"boot":            {},
	"gofer":           {},
	"umount":          {},
	"help":            {},
	"flags":           {},
}

// DispatchRunsc hands off to gVisor's runsc entrypoint when the process
// was re-exec'd as a runsc subcommand. A host binary that drives this
// package's Manager must call DispatchRunsc() as the very first thing in
// main(), before any other initialization: the same /proc/self/exe is
// re-exec'd for every runsc create/start/kill/wait/delete and for the
// Sentry boot/gofer children, and those invocations must reach gVisor's
// maincli rather than the host's normal control loop.
//
// The runsc-exec helpers in this package put runsc-level flags (e.g.
// --root, --network) BEFORE the subcommand, mirroring the runsc CLI; so
// scan past leading flag-shaped argv tokens before checking for a known
// subcommand. maincli.Main never returns (cli.Run terminates via
// os.Exit), so this function only returns when argv contained no
// recognized subcommand at all — i.e. this is the host's primary
// invocation, not a re-exec.
func DispatchRunsc() {
	for _, a := range os.Args[1:] {
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		if _, ok := runscSubcommands[a]; !ok {
			return
		}
		if sentrystack.Singleton() == nil {
			fmt.Fprintf(os.Stderr,
				"sandbox: runsc subcommand %q invoked but sentrystack PluginStack not registered\n", a)
			os.Exit(1)
		}
		maincli.Main()
		return
	}
}
