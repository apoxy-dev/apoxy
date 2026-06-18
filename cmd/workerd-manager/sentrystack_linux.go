// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

// Blank-import the core sentrystack to register the gVisor PluginStack
// (lo + eth0) that DispatchRunsc requires before it will hand off to maincli.
// M1 backend mode needs no egress forwarder. The resident control channel
// (dispatcher -> host manager) needs the clrk control forwarder, which will be
// registered here once it lands (mirroring the inbound forwarder import).
import _ "github.com/apoxy-dev/clrk/pkg/sandbox/sentrystack"
