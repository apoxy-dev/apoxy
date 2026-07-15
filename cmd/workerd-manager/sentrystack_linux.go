// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

import (
	// Register the gVisor PluginStack (lo + eth0) that DispatchRunsc requires
	// before it will hand off to maincli.
	_ "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"

	// Arm customer egress: this registers the ForwarderInstaller that installs
	// the in-Sentry catch-all TCP forwarder, tunnelling every isolate fetch()
	// connect() to the host egress bridge (which owns allow/deny/SSRF/gateway/
	// direct policy). Without this import the installer stays nil and outbound
	// SYNs are RST in the netstack — egress is dead. It is also pulled in
	// transitively via pkg/workerd/host, but arming egress is load-bearing, so
	// wire it explicitly rather than relying on that dependency edge surviving.
	_ "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack/egressfwd"
)
