//go:build linux

package sentrystack

import (
	"fmt"
	"sort"

	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// This file exposes the lo/eth0 NIC-wiring surface that cross-module
// unit tests reach via the regular import path. go_test targets don't
// pick up `_test.go` files from the imported library, which is why
// these aren't in an `export_test.go`. Production code shouldn't call
// NewForTest — the singleton is the supported entry point; the lint
// convention is "tests only" by naming.
//
// Returns flat Go types (strings, bools) rather than gvisor.dev/...
// types so a downstream test target doesn't need to expose the gvisor
// fork repo.

// NewForTest constructs a fresh Stack without registering it as the
// global PluginStack. Use for tests that need to spin up isolated
// stacks (Init wiring, NIC inspection) without touching the singleton.
func NewForTest() *Stack {
	return newStack()
}

// InitForTest invokes s.Init with the given encoded InitStr. Wraps the
// gvisor-typed plugin.InitStackArgs so tests don't have to import the
// gvisor package directly.
func InitForTest(s *Stack, encodedInitStr string) error {
	return s.Init(&plugin.InitStackArgs{InitStr: encodedInitStr})
}

// PreInitForTest invokes s.PreInit with the given pid and returns the
// encoded InitStr the host would ship to the Sentry. Fds are dropped
// (PreInit never returns any in the current design).
func PreInitForTest(s *Stack, pid int) (string, error) {
	out, _, err := s.PreInit(&plugin.PreInitStackArgs{Pid: pid})
	return out, err
}

// SingletonRegisteredForTest reports whether the package init() ran
// and registered a PluginStack via plugin.RegisterPluginStack. A bare
// import of sentrystack must always cause this to return true; if it
// doesn't, every sandbox boot panics in setupNetwork.
func SingletonRegisteredForTest() bool {
	return plugin.GetPluginStack() != nil
}

// NICNamesForTest returns the names of all NICs on s, sorted.
// Lo-only Init returns ["lo"]; eth0-wired Init returns ["eth0", "lo"].
func NICNamesForTest(s *Stack) []string {
	info := s.tcpipStack().NICInfo()
	out := make([]string, 0, len(info))
	for _, ni := range info {
		out = append(out, ni.Name)
	}
	// NIC names come back unordered; sort for stable test assertions.
	sort.Strings(out)
	return out
}

// NICAddressesForTest returns the protocol addresses of the named NIC
// in CIDR form (e.g. "127.0.0.1/8", "fd00:ec2::ffff/128"), sorted.
// Returns nil if the NIC doesn't exist.
func NICAddressesForTest(s *Stack, name string) []string {
	info := s.tcpipStack().NICInfo()
	for _, ni := range info {
		if ni.Name != name {
			continue
		}
		out := make([]string, 0, len(ni.ProtocolAddresses))
		for _, pa := range ni.ProtocolAddresses {
			out = append(out, fmt.Sprintf("%s/%d", pa.AddressWithPrefix.Address.String(), pa.AddressWithPrefix.PrefixLen))
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// HasDefaultRouteForTest reports whether the stack's route table has a
// default route for the given family ("v4" or "v6") via the named NIC.
func HasDefaultRouteForTest(s *Stack, family, nicName string) bool {
	ts := s.tcpipStack()
	nicID := nicIDByName(ts.NICInfo(), nicName)
	if nicID == 0 {
		return false
	}
	for _, r := range ts.GetRouteTable() {
		if r.NIC != nicID {
			continue
		}
		switch family {
		case "v4":
			if r.Destination == header.IPv4EmptySubnet {
				return true
			}
		case "v6":
			if r.Destination == header.IPv6EmptySubnet {
				return true
			}
		}
	}
	return false
}

// nicIDByName looks up a NIC's ID from a NICInfo map. NIC IDs are
// package-private (loNICID / eth0NICID); tests reach them by name so
// that numeric constants don't bleed across the test boundary.
// Returns 0 (an invalid NICID) when not found.
func nicIDByName(info map[tcpip.NICID]stack.NICInfo, name string) tcpip.NICID {
	for id, ni := range info {
		if ni.Name == name {
			return id
		}
	}
	return 0
}
