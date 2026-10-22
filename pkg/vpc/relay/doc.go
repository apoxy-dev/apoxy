// SPDX-License-Identifier: AGPL-3.0-only

// Package relay is the control plane of the VPC relay. It serves the Relay service and writes the
// entries of the data plane (package dp) through its Target.
//
// Each long-running process is one goroutine, and messages go only up and down the tree: the root
// (Router), one V for each VPC (vpc.go), and one A for each agent connection (conn.go) with its
// children extra (extra.go) and check (check.go). Events go in a mailbox; values go in watchable
// maps that the parent owns.
package relay
