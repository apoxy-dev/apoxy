// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package main

// Blank-import the core sentrystack to register the gVisor PluginStack
// (lo + eth0, no egress forwarder) that DispatchRunsc requires before it will
// hand off to maincli. M1 backend mode needs no egress forwarder, so the core
// registration suffices; APO-723 adds a host egress-forwarder installer import
// here (mirroring clrk's internal/sentrystack).
import _ "github.com/apoxy-dev/apoxy/pkg/sandbox/sentrystack"
