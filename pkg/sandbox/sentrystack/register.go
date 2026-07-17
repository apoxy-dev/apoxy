//go:build linux

package sentrystack

import (
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
)

// Build-time coordination guard. The resident's DNS forwarder dials a host
// unixgram resolver from inside the Sentry (see egressfwd/udp_linux.go and
// dns_tcp_linux.go), which only works if the pinned gvisor fork's plugin
// seccomp filter permits AF_UNIX SOCK_DGRAM socket creation. Static-asserting
// on the fork sentinel makes a gvisor pin bump that drops that patch fail to
// COMPILE here rather than silently breaking guest DNS at runtime: the array
// length is 0 while the allowance holds, -1 (a compile error) if the fork sets
// the sentinel to 0, and a dropped symbol is itself a compile error.
var _ [plugin.SeccompUnixgramDGram - 1]struct{}

// stk is the per-process singleton PluginStack. Same struct instance
// lives in both the worker process (where PreInit is called per-sandbox
// to compose the initStr) and each Sentry boot child (where Init is
// called exactly once).
var stk *Stack

func init() {
	stk = newStack()
	plugin.RegisterPluginStack(stk)
	registerProviders()
}

// Singleton returns the registered PluginStack. Useful in tests and for
// the worker side to look up per-sandbox state stashed during PreInit.
func Singleton() *Stack {
	return stk
}
