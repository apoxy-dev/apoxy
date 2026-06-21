//go:build linux

package sentrystack

import (
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
)

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
